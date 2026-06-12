"""
invoke tasks — local developer workflow for building and publishing MCPyGhidra.

Normal releases are published automatically by .github/workflows/release.yml
when a v* tag is pushed; the `publish` task here is for one-off local uploads.
Reads credentials from ~/.pypirc (default [pypi] section) or from
TWINE_USERNAME / TWINE_PASSWORD environment variables.

Quick reference:
  inv install-tools   install build and twine into the current environment
  inv build           clean then build wheel + sdist into dist/
  inv publish         upload dist/* to PyPI via twine
  inv clean           remove dist/, build artifacts, and egg-info
"""

from invoke import task


@task
def install_tools(ctx):
    """Install build and twine into the current Python environment."""
    ctx.run("pip install --upgrade build twine")


@task
def clean(ctx):
    """Remove dist/, build artifacts, egg-info directories, and compiled bytecode."""
    ctx.run("rm -rf dist/")
    ctx.run("rm -rf build/")
    ctx.run("rm -rf src/build/")
    ctx.run("rm -rf src/*.egg-info")
    ctx.run("find . -type d -name __pycache__ -not -path './.git/*' -exec rm -rf {} +")
    ctx.run("find . -name '*.pyc' -not -path './.git/*' -delete")


@task(pre=[clean])
def build(ctx):
    """Clean then build the wheel and sdist into dist/ using python -m build."""
    ctx.run("python -m build")


@task
def publish(ctx):
    """Manually upload dist/* to PyPI via twine.

    Normal releases are published automatically by .github/workflows/release.yml
    when a v* tag is pushed; use this task only for one-off local uploads.
    Reads credentials from ~/.pypirc (or TWINE_USERNAME / TWINE_PASSWORD).
    Run `inv build` first if dist/ is empty.
    """
    ctx.run("python -m twine upload dist/*")
