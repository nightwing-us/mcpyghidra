#!/bin/bash
# Start Ghidra GUI MCP server under Xvfb (and optionally bwrap) for e2e testing.
# Called by test_gui_features.py fixture.
#
# Two modes:
#   - Default (developer machine): bwrap-isolated; hides any local
#     third-party Ghidra plugin dist-info from the test sandbox.
#   - MCPYGHIDRA_GUI_NO_BWRAP=1 (CI): no bwrap; redirect $HOME to a
#     fixture-local sandbox dir. Suits docker containers where
#     unprivileged user namespaces aren't available.
#
# Env knobs:
#   GHIDRA_INSTALL_DIR  Ghidra root (default: /opt/ghidra in CI)
#   PYGHIDRA_BIN        pyghidra CLI path (default: `command -v pyghidra`)
#   GHIDRA_VER          Ghidra-version subdir name (default: ghidra_12.0.4_PUBLIC)
#   JAVA_HOME           Auto-detected from `javac` if unset
#   EXTRA_PLUGIN_DIST_DIR  Override a local plugin dist-info path to hide (dev mode)
#
# Ignore SIGTERM/SIGHUP so pytest's cleanup doesn't kill us prematurely.
trap '' TERM HUP
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURE_DIR="$PROJECT_ROOT/tests/fixtures/ghidra_gui_test"
GHIDRA_VER="${GHIDRA_VER:-ghidra_12.0.4_PUBLIC}"

# Resolve binaries from environment or PATH.
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
PYGHIDRA_BIN="${PYGHIDRA_BIN:-$(command -v pyghidra || true)}"
if [ -z "$PYGHIDRA_BIN" ] || [ ! -x "$PYGHIDRA_BIN" ]; then
  echo "ERROR: pyghidra not found (set PYGHIDRA_BIN or add to PATH)" >&2
  exit 3
fi
if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
  echo "ERROR: Ghidra not found at GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >&2
  exit 3
fi

# Detect JAVA_HOME from `javac` if not set (Debian slim default-jdk-headless
# resolves to /usr/lib/jvm/java-NN-openjdk-... ; the committed fixture's
# java_home.save points at a developer-machine path which won't work in CI).
if [ -z "${JAVA_HOME:-}" ]; then
  if command -v javac >/dev/null 2>&1; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
    export JAVA_HOME
  fi
fi

# Restore fixture files to committed state so per-run mutations don't leak.
# Skip in CI mode: container is throwaway, AND the test fixture has
# already truncated server_stdout.log to capture this run's output —
# git-checkout would clobber that with committed content.
if [ "${MCPYGHIDRA_GUI_NO_BWRAP:-0}" != "1" ]; then
  git -C "$PROJECT_ROOT" checkout -- "$FIXTURE_DIR" 2>/dev/null || true
fi

# Rewrite committed paths to the current PROJECT_ROOT/JDK/Ghidra so the
# same fixture works in CI and on developer machines.
PREF="$FIXTURE_DIR/ghidra_config/$GHIDRA_VER/preferences"
LASTRUN="$FIXTURE_DIR/lastrun"
JAVAHOME_FILE="$FIXTURE_DIR/ghidra_config/$GHIDRA_VER/java_home.save"
# MCPYGHIDRA_COMMITTED_ROOT: the absolute path that was baked into the
# committed fixture files (preferences, project state, etc.) when they were
# last generated.  Set this to the path where the repo lived on the machine
# that generated the fixtures so the sed rewrite can substitute it with the
# current PROJECT_ROOT.  Defaults to empty (no rewrite attempted) so the
# script is safe to run from any checkout without manual intervention.
ORIG_ROOT="${MCPYGHIDRA_COMMITTED_ROOT:-}"

if [ -f "$PREF" ] && [ -n "$ORIG_ROOT" ] && [ "$PROJECT_ROOT" != "$ORIG_ROOT" ]; then
  sed -i "s|$ORIG_ROOT|$PROJECT_ROOT|g" "$PREF"
fi
echo "$GHIDRA_INSTALL_DIR" > "$LASTRUN"
if [ -n "${JAVA_HOME:-}" ] && [ -f "$JAVAHOME_FILE" ]; then
  echo "$JAVA_HOME" > "$JAVAHOME_FILE"
fi

# Rewrite the project's OWNER to the current Unix user. Ghidra refuses
# to open a project whose committed OWNER doesn't match the user
# trying to open it (NotOwnerException), and the fixture was committed
# under "user" but CI / docker typically runs as a different account.
PROJECT_PRP="$FIXTURE_DIR/gui_test/gui_test.rep/project.prp"
CURRENT_USER="$(id -un)"
if [ -f "$PROJECT_PRP" ]; then
  sed -i "s|VALUE=\"[^\"]*\" />\(.*OWNER\)|VALUE=\"$CURRENT_USER\" />\1|" "$PROJECT_PRP" 2>/dev/null || true
  # Simpler regex: replace any OWNER value with current user.
  sed -i "s|\(STATE NAME=\"OWNER\" TYPE=\"string\" VALUE=\"\)[^\"]*\(\"\)|\1$CURRENT_USER\2|" "$PROJECT_PRP"
fi

# ---------------------------------------------------------------------------
# CI mode: no bwrap (docker can't always run unprivileged user namespaces).
# Use $HOME redirection so Ghidra reads the fixture's config without touching
# the real ~/.config.
# ---------------------------------------------------------------------------
if [ "${MCPYGHIDRA_GUI_NO_BWRAP:-0}" = "1" ]; then
  SANDBOX_HOME="$FIXTURE_DIR/sandbox_home"
  rm -rf "$SANDBOX_HOME"
  mkdir -p "$SANDBOX_HOME/.config/ghidra"
  ln -sfn "$FIXTURE_DIR/ghidra_config/$GHIDRA_VER" "$SANDBOX_HOME/.config/ghidra/$GHIDRA_VER"
  ln -sfn "$FIXTURE_DIR/decaf_cache" "$SANDBOX_HOME/.config/decaf"
  ln -sfn "$FIXTURE_DIR/lastrun" "$SANDBOX_HOME/.config/ghidra/lastrun"

  # Pin Python user-site to the REAL home BEFORE redirecting HOME,
  # otherwise pip-installed packages (pyghidra, pyghidra_decaf,
  # mcpyghidra) become invisible — Python derives sys.path from
  # ~/.local/lib/pythonX.Y/site-packages at startup.
  REAL_HOME="$HOME"
  export PYTHONUSERBASE="$REAL_HOME/.local"
  export HOME="$SANDBOX_HOME"

  # Java reads `user.home` from /etc/passwd, NOT from $HOME, so we must
  # explicitly override the JVM property. Without this, Ghidra writes
  # config to the real login user's ~/.config/ghidra/
  # instead of the sandboxed fixture, and reads jars from a different
  # Extensions/ directory than the one we wired up via symlinks.
  export _JAVA_OPTIONS="-Duser.home=$SANDBOX_HOME"

  # pyghidra_decaf plugin extensions (MCPyGhidra in particular) need
  # 2-3 prior `pyghidra.start()` invocations before they're fully
  # registered in Ghidra's extensions dir. The image build runs
  # pyghidra_decaf_bootstrap so the extension is already present at
  # runtime — we only fall back to bootstrap-at-launch if the
  # build-time bootstrap was skipped or the cache got invalidated.
  if [ ! -d "$SANDBOX_HOME/.config/ghidra/$GHIDRA_VER/Extensions/MCPyGhidra" ]; then
    echo ">>> Extension missing — running runtime bootstrap (slow)..."
    pyghidra_decaf_bootstrap || echo ">>> bootstrap exited non-zero (continuing)"
  else
    echo ">>> MCPyGhidra extension found pre-built; skipping bootstrap."
  fi
  # Open the project AND pass crackme.elf as the binary so pyghidra
  # opens it in CodeBrowser. The committed project already has an
  # imported `/crackme.elf` and a saved CodeBrowser tool referencing
  # it, but Ghidra's GUI doesn't auto-resume the tool from project
  # state alone — it sits on the project window until something
  # triggers a tool open. Passing the binary as a positional arg
  # makes pyghidra launch CodeBrowser with that program, which fires
  # _post_program_activated → MCPyGhidraPlugin auto-starts the MCP
  # server.
  exec xvfb-run -a "$PYGHIDRA_BIN" --gui --install-dir "$GHIDRA_INSTALL_DIR" \
    --project-name gui_test \
    --project-path "$FIXTURE_DIR/gui_test" \
    --skip-analysis \
    "$PROJECT_ROOT/tests/fixtures/crackme.elf"
fi

# ---------------------------------------------------------------------------
# Developer mode: bwrap sandbox.
# ---------------------------------------------------------------------------
HOME_DIR="$HOME"
# EXTRA_PLUGIN_DIST_DIR: dev-only knob. Set it to a local Ghidra plugin
# dist-info directory that you want hidden from the test sandbox (bwrap
# mode only).  A fake dist-info stub from the GUI test fixtures is
# bind-mounted over it so Ghidra sees a stub instead of the real package.
# External contributors and CI do not need this variable; the hide-step
# is skipped when it is unset.
PLUGIN_DIST="${EXTRA_PLUGIN_DIST_DIR:-}"
FAKE_PLUGIN_DIST="$FIXTURE_DIR/fake_plugin_dist"

# Conditionally hide the plugin dist-info if both the real and stub paths exist.
LM_BIND_ARGS=()
if [ -d "$PLUGIN_DIST" ] && [ -d "$FAKE_PLUGIN_DIST" ]; then
  LM_BIND_ARGS=(--bind "$FAKE_PLUGIN_DIST" "$PLUGIN_DIST")
fi

exec xvfb-run -a bwrap \
  --ro-bind / / \
  --dev /dev \
  --proc /proc \
  --bind /tmp /tmp \
  --bind "$FIXTURE_DIR/ghidra_config/$GHIDRA_VER" "$HOME_DIR/.config/ghidra/$GHIDRA_VER" \
  --bind "$FIXTURE_DIR/decaf_cache" "$HOME_DIR/.config/decaf" \
  --bind "$FIXTURE_DIR/ghidra_cache" "/var/tmp/user-ghidra" \
  --bind "$FIXTURE_DIR/gui_test" "$FIXTURE_DIR/gui_test" \
  --bind "$PROJECT_ROOT" "$PROJECT_ROOT" \
  --bind "$FIXTURE_DIR/lastrun" "$HOME_DIR/.config/ghidra/lastrun" \
  --bind /var/tmp /var/tmp \
  "${LM_BIND_ARGS[@]}" \
  -- "$PYGHIDRA_BIN" --gui --install-dir "$GHIDRA_INSTALL_DIR"
