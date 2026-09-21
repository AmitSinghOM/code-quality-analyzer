"""Deterministic parse-cache correctness and safety contracts."""

import json
from pathlib import Path

import pytest

import cqa_analyzer.cache as cache_module
from cqa_analyzer.cache import CACHE_NAMESPACE, CacheError, CacheStore
from cqa_analyzer.plugins import create_default_registry
from cqa_analyzer.protocols import SourceFile


def _source(content: str, identity: str = "pkg/module.py") -> SourceFile:
    return SourceFile(
        path=Path(identity),
        display_path=identity,
        identity_path=identity,
        content=content,
    )


def _python_parts():
    registry = create_default_registry()
    return registry.language("python"), registry.rule_packs_for("python")[0]


def test_cache_round_trip_preserves_rule_findings(tmp_path):
    adapter, rule_pack = _python_parts()
    source = _source("def f(items=[]):\n    return items\n")
    fresh = adapter.parse(source)
    cache = CacheStore(tmp_path / "cache")

    cache.store(adapter, source, fresh)
    loaded = cache.load(adapter, source)

    assert loaded is not None
    assert list(rule_pack.evaluate(loaded)) == list(rule_pack.evaluate(fresh))


def test_cache_misses_when_content_or_identity_changes(tmp_path):
    adapter, _ = _python_parts()
    original = _source("VALUE = 1\n")
    cache = CacheStore(tmp_path / "cache")
    cache.store(adapter, original, adapter.parse(original))

    assert cache.load(adapter, _source("VALUE = 2\n")) is None
    assert cache.load(adapter, _source("VALUE = 1\n", "other.py")) is None


def test_cache_rejects_symlinked_directory(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "cache"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(CacheError, match="symbolic link"):
        CacheStore(link)


def test_cache_treats_tampered_entry_as_miss(tmp_path):
    adapter, _ = _python_parts()
    source = _source("VALUE = 1\n")
    cache = CacheStore(tmp_path / "cache")
    cache.store(adapter, source, adapter.parse(source))
    entry = next(cache.directory.glob("*.json"))
    payload = json.loads(entry.read_text(encoding="utf-8"))
    payload["key"] = "0" * 64
    entry.write_text(json.dumps(payload), encoding="utf-8")

    assert cache.load(adapter, source) is None


def test_cache_rejects_duplicate_json_keys(tmp_path):
    adapter, _ = _python_parts()
    source = _source("VALUE = 1\n")
    cache = CacheStore(tmp_path / "cache")
    cache.store(adapter, source, adapter.parse(source))
    entry = next(cache.directory.glob("*.json"))
    entry.write_text('{"key":"a","key":"b"}', encoding="utf-8")

    assert cache.load(adapter, source) is None


def test_cache_prunes_old_entries_to_aggregate_limit(tmp_path, monkeypatch):
    adapter, _ = _python_parts()
    cache = CacheStore(tmp_path / "cache")
    monkeypatch.setattr(cache_module, "MAX_CACHE_ENTRIES", 1)
    for value in (1, 2):
        source = _source(f"VALUE = {value}\n")
        cache.store(adapter, source, adapter.parse(source))

    assert len(list((tmp_path / "cache" / CACHE_NAMESPACE).glob("*.json"))) == 1


# --- B3 (review 6): a cached artifact is the lexer's output, so it must not
# survive an analyzer upgrade or an edit to the adapter that produced it.


def test_cache_misses_after_analyzer_upgrade(tmp_path, monkeypatch):
    adapter, _ = _python_parts()
    source = _source("VALUE = 1\n")
    cache = CacheStore(tmp_path / "cache")
    cache.store(adapter, source, adapter.parse(source))
    assert cache.load(adapter, source) is not None

    monkeypatch.setattr(cache_module, "__version__", "999.0.0")

    assert cache.load(adapter, source) is None


def test_cache_misses_when_adapter_source_changes(tmp_path, monkeypatch):
    """Editing the lexer must invalidate that language's entries even when
    ``adapter_version`` was not bumped (3.3.0 shipped three lexer fixes and
    bumped none of the fourteen version constants)."""
    adapter, _ = _python_parts()
    source = _source("VALUE = 1\n")
    cache = CacheStore(tmp_path / "cache")
    cache.store(adapter, source, adapter.parse(source))
    assert cache.load(adapter, source) is not None

    module_name = type(adapter).__module__
    real_digest = cache_module._module_source_sha256(module_name)
    assert len(real_digest) == 64, "adapter module source must be readable"

    monkeypatch.setattr(
        cache_module,
        "_module_source_sha256",
        lambda name: "0" * 64 if name == module_name else real_digest,
    )

    assert cache.load(adapter, source) is None


def test_cache_hits_when_version_and_adapter_unchanged(tmp_path):
    adapter, _ = _python_parts()
    source = _source("VALUE = 1\n")
    cache = CacheStore(tmp_path / "cache")
    cache.store(adapter, source, adapter.parse(source))

    metadata = cache_module._codec_metadata(adapter, source)

    assert metadata["analyzer_version"] == cache_module.__version__
    assert metadata["adapter_source_sha256"] == cache_module._module_source_sha256(
        type(adapter).__module__
    )
    assert cache.load(adapter, source) is not None


def test_module_source_digest_is_content_based(tmp_path, monkeypatch):
    """The digest follows the module's bytes on disk, not its name or version."""
    import importlib.util
    import sys

    module_path = tmp_path / "fake_adapter_module.py"
    module_path.write_text("X = 1\n")
    spec = importlib.util.spec_from_file_location("fake_adapter_module", module_path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "fake_adapter_module", module)
    spec.loader.exec_module(module)

    cache_module._module_source_sha256.cache_clear()
    before = cache_module._module_source_sha256("fake_adapter_module")

    module_path.write_text("X = 2\n")
    cache_module._module_source_sha256.cache_clear()
    after = cache_module._module_source_sha256("fake_adapter_module")

    assert before != after
    assert cache_module._module_source_sha256("module.that.does.not.exist") == "no-source"
