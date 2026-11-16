"""3.0 stdlib core (docs/adr/004): no third-party imports, plain deterministic text."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

from clirunner import CliRunner

from cqa_analyzer import text_render
from cqa_analyzer.__main__ import build_parser, main
from cqa_analyzer.text_render import Panel, PlainConsole, Table, escape, strip_markup

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_declares_no_runtime_dependencies():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["dependencies"] == []
    assert "deep" in project["optional-dependencies"]


# Classifier shared by the stdlib-only probe and its negative check. It runs in
# a `-I` child, so it must stay self-contained. A module counts as standard
# library when its top-level name is in sys.stdlib_module_names OR its file is
# under sysconfig's stdlib/platstdlib directory and not under purelib/platlib
# (a venv's site-packages lives inside its platstdlib, so the exclusion is
# load-bearing). The path rule exists because CPython 3.15 generates
# `_missing_stdlib_info` at build time (Tools/build/check_extension_modules.py,
# installed next to the stdlib) and `traceback.py` imports it, yet the name is
# absent from sys.stdlib_module_names.
_STDLIB_CLASSIFIER = """\
import sys, sysconfig
from pathlib import Path
std = set(sys.stdlib_module_names)
def _resolved(key):
    path = sysconfig.get_path(key)
    return Path(path).resolve() if path else None
stdlib_dirs = [p for p in (_resolved('stdlib'), _resolved('platstdlib')) if p]
site_dirs = [p for p in (_resolved('purelib'), _resolved('platlib')) if p]
def _under(file, dirs):
    return any(file.is_relative_to(d) for d in dirs)
def _is_stdlib(top):
    if top in std:
        return True
    file = getattr(sys.modules.get(top), '__file__', None)
    if not file:
        return False
    file = Path(file).resolve()
    return _under(file, stdlib_dirs) and not _under(file, site_dirs)
third = sorted({m.split('.')[0] for m in sys.modules
    if not m.startswith('cqa_analyzer') and not m.startswith('__editable__')
    and m.split('.')[0] not in
        ('_distutils_hack', 'sitecustomize', 'usercustomize', '__main__')
    and not _is_stdlib(m.split('.')[0])})
print(','.join(third))
"""


def _run_stdlib_probe(setup: str) -> str:
    """Run `setup` in a fresh isolated interpreter and return the non-stdlib modules it loaded."""
    result = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-I", "-c", setup + _STDLIB_CLASSIFIER],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_cli_imports_only_the_standard_library():
    """Import the CLI in a fresh interpreter and list every non-stdlib module loaded."""
    setup = "import cqa_analyzer.__main__, cqa_analyzer.mcp_server, cqa_analyzer.text_render\n"
    assert _run_stdlib_probe(setup) == ""


def test_stdlib_probe_still_reports_third_party_modules(tmp_path: Path):
    """The sysconfig path rule must not swallow a real third-party import."""
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "fakethirdparty.py").write_text("VALUE = 1\n")
    setup = f"import sys\nsys.path.insert(0, {str(site)!r})\nimport fakethirdparty\n"
    assert _run_stdlib_probe(setup) == "fakethirdparty"


def test_stdlib_probe_excludes_site_packages_inside_the_stdlib_directory(tmp_path: Path):
    """Every CPython layout nests site-packages under the stdlib directory.

    Without the purelib/platlib exclusion the path rule would call every
    installed package "standard library" and the probe would pass vacuously.
    Point sysconfig at a fake layout with that nesting and check the module
    under its site-packages is still reported.
    """
    lib = tmp_path / "lib" / "python3.x"
    site = lib / "site-packages"
    site.mkdir(parents=True)
    (site / "fakethirdparty.py").write_text("VALUE = 1\n")
    layout = {"stdlib": lib, "platstdlib": lib, "purelib": site, "platlib": site}
    setup = (
        "import sys, sysconfig\n"
        f"_layout = {({k: str(v) for k, v in layout.items()})!r}\n"
        "_real_get_path = sysconfig.get_path\n"
        "sysconfig.get_path = lambda name, *a, **k: (\n"
        "    _layout.get(name) or _real_get_path(name, *a, **k))\n"
        f"sys.path.insert(0, {str(site)!r})\nimport fakethirdparty\n"
    )
    # The real stdlib directory is hidden from the probe here, so on
    # interpreters with build-generated stdlib modules more names may appear.
    assert "fakethirdparty" in _run_stdlib_probe(setup).split(",")


def test_parser_exposes_the_2x_flag_surface_unchanged():
    flags = {
        action.option_strings[0] for action in build_parser()._actions if action.option_strings
    }
    assert flags >= {
        "--verbose",
        "--output-format",
        "--complexity",
        "--max-file-size",
        "--max-files",
        "--redact-paths",
        "--anonymize",
        "--offline",
        "--cache-dir",
        "--fail-under",
        "--fail-on",
        "--baseline",
        "--write-baseline",
        "--new-findings-only",
        "--changed-lines-manifest",
        "--strict",
        "--config",
        "--no-project-config",
        "--expect-config-fingerprint",
        "--version",
    }
    shorts = {s for a in build_parser()._actions for s in a.option_strings if len(s) == 2}
    assert shorts >= {"-v", "-f", "-c", "-h"}


def test_usage_errors_exit_2_and_fatal_errors_exit_1(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    usage = CliRunner().invoke(main, [str(tmp_path), "--new-findings-only"])
    assert usage.exit_code == 2 and "requires --baseline" in usage.stderr
    bad_dir = CliRunner().invoke(main, [str(tmp_path / "missing")])
    assert bad_dir.exit_code == 2 and "does not exist" in bad_dir.stderr
    bad_config = CliRunner().invoke(main, [str(tmp_path), "--config", str(tmp_path / "nope.toml")])
    assert bad_config.exit_code == 1 and bad_config.stderr.startswith("Error: ")


def test_version_string_shape_is_unchanged():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith("code-quality-analyzer, version ")


# --- renderer ----------------------------------------------------------------------


def test_strip_markup_removes_tags_but_keeps_escaped_and_non_tag_brackets():
    assert strip_markup("[bold blue]Analyzing:[/bold blue] x") == "Analyzing: x"
    assert strip_markup("[dim]a | b[/dim]") == "a | b"
    assert strip_markup("ctl[31m.py") == "ctl[31m.py"  # cannot be a tag
    assert strip_markup("arr\\[/i].py") == "arr[/i].py"  # escaped literal
    assert strip_markup("done[/]") == "done"


def test_escape_matches_rich_semantics():
    assert escape("ctl[31m.py") == "ctl[31m.py"
    assert escape("arr[/i].py") == "arr\\[/i].py"
    assert strip_markup(escape("[red]not a style[/red]")) == "[red]not a style[/red]"


def test_panel_and_table_render_deterministically():
    console = PlainConsole()
    with console.capture() as cap:
        console.print(Panel("1.0/10\nPoor", title="Score"))
        table = Table(title="Findings", show_header=True)
        table.add_column("rule")
        table.add_column("where")
        table.add_row("[red]PY-COR-007[/red]", "app.py:2")
        console.print(table)
        console.print()
    text = cap.get()
    assert "┌─ Score" in text and "│ 1.0/10" in text and "└" in text
    assert "Findings\nrule        where\n" in text
    assert "PY-COR-007  app.py:2" in text  # tag stripped inside a cell
    assert text.endswith("\n\n")
    # Same input, same bytes.
    with console.capture() as again:
        console.print(Panel("1.0/10\nPoor", title="Score"))
    assert again.get() == text.split("Findings")[0]


def test_capture_nests_and_restores(tmp_path: Path):
    import io

    stream = io.StringIO()
    console = PlainConsole(stream)
    with console.capture() as outer:
        console.print("outer")
        with console.capture() as inner:
            console.print("inner")
        console.print("outer again")
    console.print("direct")
    assert inner.get() == "inner\n"
    assert outer.get() == "outer\nouter again\n"
    assert stream.getvalue() == "direct\n"
    assert text_render.get_console().__class__ is PlainConsole
