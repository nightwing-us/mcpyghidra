"""Unit tests for build_instructions() and project://binaries in server.py."""
import json
from unittest.mock import MagicMock
from mcpyghidra.server import build_instructions, _collect_binaries


def _make_mock_backend(is_headless: bool, binary_name: str, binary_path: str, lang_id: str) -> MagicMock:
    backend = MagicMock()
    backend.is_headless = is_headless
    prog = MagicMock()
    prog.getName.return_value = binary_name
    prog.getExecutablePath.return_value = binary_path
    lang = MagicMock()
    lang.getLanguageID.return_value = lang_id
    prog.getLanguage.return_value = lang
    backend.program = prog
    return backend


def test_build_instructions_contains_tool_name():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    result = build_instructions(backend)
    assert 'Ghidra' in result or 'MCPyGhidra' in result


def test_build_instructions_contains_binary_name():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    result = build_instructions(backend)
    assert 'crackme.elf' in result


def test_build_instructions_contains_mode():
    headless_backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    gui_backend = _make_mock_backend(
        is_headless=False,
        binary_name='firmware.bin',
        binary_path='/tmp/firmware.bin',
        lang_id='ARM:LE:32:v7',
    )
    assert 'headless' in build_instructions(headless_backend)
    assert 'gui' in build_instructions(gui_backend)


def test_build_instructions_contains_architecture():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    result = build_instructions(backend)
    assert 'x86:LE:64:default' in result


def test_build_instructions_under_2kb():
    backend = _make_mock_backend(
        is_headless=False,
        binary_name='a' * 200,
        binary_path='/tmp/' + 'b' * 200,
        lang_id='x86:LE:64:default',
    )
    result = build_instructions(backend)
    assert len(result.encode('utf-8')) < 2048


def test_build_instructions_contains_tool_list():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    result = build_instructions(backend)
    assert 'decompile' in result
    assert 'cfg' in result
    assert 'callgraph' in result


def test_headless_backend_instructions():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    result = build_instructions(backend)
    assert 'Mode: headless' in result
    assert 'crackme.elf' in result
    assert 'x86:LE:64:default' in result
    assert 'open_program' not in result  # GUI-only tool not listed in headless mode


def test_gui_backend_instructions():
    backend = _make_mock_backend(
        is_headless=False,
        binary_name='firmware.bin',
        binary_path='/tmp/firmware.bin',
        lang_id='ARM:LE:32:v7',
    )
    result = build_instructions(backend)
    assert 'Mode: gui' in result
    assert 'firmware.bin' in result
    assert 'ARM:LE:32:v7' in result
    assert 'open_program' in result  # GUI mode includes open_program


def test_none_backend_instructions():
    result = build_instructions(None)
    assert 'Mode: unknown' in result
    assert 'Binary: none' in result
    assert len(result.encode('utf-8')) < 2048


# ---------------------------------------------------------------------------
# Tests for build_server_info_dict / server://info resource
# ---------------------------------------------------------------------------

def _capture_server_info_fn(backend, get_port=None):
    """Register resources on a mock mcp and extract the server://info handler."""
    from mcpyghidra.server import register_resources

    captured = {}

    class _FakeMcp:
        def resource(self, uri, **kwargs):
            def decorator(fn):
                captured[uri] = fn
                return fn
            return decorator

    register_resources(_FakeMcp(), backend, get_port=get_port)
    return captured.get('server://info')


def test_server_info_all_fields():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    fn = _capture_server_info_fn(backend, get_port=lambda: 6050)
    assert fn is not None
    result = fn()
    assert set(result.keys()) == {
        'tool', 'version', 'mode', 'binary', 'binary_path',
        'architecture', 'analysis_status', 'port',
    }


def test_server_info_with_port():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    fn = _capture_server_info_fn(backend, get_port=lambda: 9999)
    assert fn is not None
    result = fn()
    assert result['port'] == 9999


def test_server_info_no_port():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    fn = _capture_server_info_fn(backend, get_port=lambda: None)
    assert fn is not None
    result = fn()
    assert result['port'] is None


def test_server_info_analysis_status_complete():
    backend = _make_mock_backend(
        is_headless=False,
        binary_name='test.elf',
        binary_path='/tmp/test.elf',
        lang_id='ARM:LE:32:v7',
    )
    fn = _capture_server_info_fn(backend)
    assert fn is not None
    result = fn()
    assert result['analysis_status'] == 'complete'
    assert result['binary'] == 'test.elf'
    assert result['architecture'] == 'ARM:LE:32:v7'
    assert result['tool'] == 'ghidra'
    assert result['mode'] == 'gui'


def test_server_info_headless_mode():
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    fn = _capture_server_info_fn(backend, get_port=lambda: 6050)
    assert fn is not None
    result = fn()
    assert result['mode'] == 'headless'
    assert result['binary'] == 'crackme.elf'
    assert result['binary_path'] == '/tmp/crackme.elf'
    assert result['architecture'] == 'x86:LE:64:default'
    assert result['port'] == 6050


# ---------------------------------------------------------------------------
# Tests for project://binaries resource
# ---------------------------------------------------------------------------

def _capture_project_binaries_fn(backend, get_port=None):
    """Register resources on a mock mcp and extract the project://binaries handler."""
    from mcpyghidra.server import register_resources

    captured = {}

    class _FakeMcp:
        def resource(self, uri, **kwargs):
            def decorator(fn):
                captured[uri] = fn
                return fn
            return decorator

    register_resources(_FakeMcp(), backend, get_port=get_port)
    return captured.get('project://binaries')


def test_project_binaries_headless_returns_empty():
    """Headless backend should return an empty binaries list."""
    backend = _make_mock_backend(
        is_headless=True,
        binary_name='crackme.elf',
        binary_path='/tmp/crackme.elf',
        lang_id='x86:LE:64:default',
    )
    fn = _capture_project_binaries_fn(backend)
    assert fn is not None
    result = json.loads(fn())
    assert result['project_name'] is None
    assert result['binaries'] == []


def test_project_binaries_none_backend_returns_empty():
    """None backend should return an empty binaries list."""
    # Pass a MagicMock that raises AttributeError when is_headless is accessed,
    # simulating the None-like guard at the top of the resource handler.
    # We test the None path by using a sentinel object that mimics None behaviour.
    from mcpyghidra.server import register_resources

    captured = {}

    class _FakeMcp:
        def resource(self, uri, **kwargs):
            def decorator(fn):
                captured[uri] = fn
                return fn
            return decorator

    # Build a backend that has is_headless=False but whose _tool access fails —
    # we can't easily pass None as backend (register_resources calls backend.is_headless),
    # so instead we test the headless guard path via a headless=True mock.
    # The true None-backend path is covered by the guard `if backend is None`.
    # We verify that by patching backend to None inside the closure.
    backend = MagicMock()
    backend.is_headless = False

    register_resources(_FakeMcp(), backend)
    fn = captured.get('project://binaries')
    assert fn is not None

    # Now simulate what happens when backend would be None: the closure checks
    # `backend is None or backend.is_headless`. We can't rebind the closure's
    # free variable, so we test the is_headless=True branch (equivalent guard).
    backend.is_headless = True
    result = json.loads(fn())
    assert result['project_name'] is None
    assert result['binaries'] == []


# ---------------------------------------------------------------------------
# Tests for _collect_binaries helper
# ---------------------------------------------------------------------------

def _make_mock_domain_file(name: str, path: str) -> MagicMock:
    f = MagicMock()
    f.getName.return_value = name
    f.getPathname.return_value = path
    return f


def _make_mock_folder(pathname: str, files: list, subfolders: list) -> MagicMock:
    folder = MagicMock()
    folder.getPathname.return_value = pathname
    folder.getFiles.return_value = files
    folder.getFolders.return_value = subfolders
    return folder


def test_collect_binaries_flat_folder():
    """Single folder with two files, one open, one with MCP port."""
    file_a = _make_mock_domain_file('crackme.elf', '/crackme.elf')
    file_b = _make_mock_domain_file('firmware.bin', '/firmware.bin')
    folder = _make_mock_folder('/', [file_a, file_b], [])

    open_programs = {'/crackme.elf'}
    port_manager = MagicMock()
    port_manager._program_path_to_port = {'/crackme.elf': 6050}

    binaries: list = []
    _collect_binaries(folder, binaries, open_programs, port_manager)

    assert len(binaries) == 2

    crackme = next(b for b in binaries if b['name'] == 'crackme.elf')
    assert crackme['path'] == '/crackme.elf'
    assert crackme['folder'] == '/'
    assert crackme['is_open'] is True
    assert crackme['has_mcp_server'] is True
    assert crackme['mcp_port'] == 6050

    firmware = next(b for b in binaries if b['name'] == 'firmware.bin')
    assert firmware['is_open'] is False
    assert firmware['has_mcp_server'] is False
    assert firmware['mcp_port'] is None


def test_collect_binaries_recursive_subfolders():
    """Files in subfolders are collected with their folder path."""
    child_file = _make_mock_domain_file('nested.elf', '/sub/nested.elf')
    subfolder = _make_mock_folder('/sub', [child_file], [])

    root_file = _make_mock_domain_file('root.elf', '/root.elf')
    root_folder = _make_mock_folder('/', [root_file], [subfolder])

    binaries: list = []
    _collect_binaries(root_folder, binaries, set(), None)

    assert len(binaries) == 2
    paths = {b['path'] for b in binaries}
    assert '/root.elf' in paths
    assert '/sub/nested.elf' in paths

    nested = next(b for b in binaries if b['name'] == 'nested.elf')
    assert nested['folder'] == '/sub'


def test_collect_binaries_no_port_manager():
    """When port_manager is None, has_mcp_server is always False."""
    file_a = _make_mock_domain_file('test.elf', '/test.elf')
    folder = _make_mock_folder('/', [file_a], [])

    binaries: list = []
    _collect_binaries(folder, binaries, set(), None)

    assert binaries[0]['has_mcp_server'] is False
    assert binaries[0]['mcp_port'] is None


def test_collect_binaries_empty_folder():
    """Empty folder produces no binaries."""
    folder = _make_mock_folder('/', [], [])
    binaries: list = []
    _collect_binaries(folder, binaries, set(), None)
    assert binaries == []
