"""T21 — optional [semantic] group, lazy model loading, and CLI wiring.

These are the deterministic, no-model tests for the local-embedder default:
base install stays PyYAML-only, the model runtime is imported only when
``--semantic`` is selected, and the model/corpus are pinned by hash/version.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

from mcpsec import cli
from mcpsec.embedder import (
    MODEL_REVISION,
    _MODEL_FILES,
    load_default_embedder,
)

PROJECT = Path(__file__).resolve().parents[1]


def test_pyproject_keeps_pyyaml_only_and_adds_semantic_group():
    data = tomllib.loads((PROJECT / "pyproject.toml").read_text(encoding="utf-8"))

    runtime = [d.lower() for d in data["project"]["dependencies"]]
    assert runtime == ["pyyaml>=6.0.3"], "PyYAML must remain the sole runtime dependency"

    semantic = data["project"]["optional-dependencies"]["semantic"]
    assert any(d.startswith("onnxruntime==") for d in semantic)
    assert any(d.startswith("tokenizers==") for d in semantic)
    # No floating spec: every optional dep is pinned with an exact version.
    for dep in semantic:
        assert "==" in dep, f"semantic dependency must be pinned, got {dep!r}"


def test_model_is_pinned_by_revision_and_file_hashes():
    # Revision is a full 40-hex git SHA (no floating branch/tag).
    assert len(MODEL_REVISION) == 40
    assert int(MODEL_REVISION, 16) >= 0

    # Every model file is pinned by a 64-hex SHA-256.
    assert _MODEL_FILES, "at least one model file must be declared"
    for _remote, (sha256, _local) in _MODEL_FILES.items():
        assert len(sha256) == 64
        assert int(sha256, 16) >= 0


def test_help_lists_semantic_flag(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "--help"])
    assert exc.value.code == 0
    assert "--semantic" in capsys.readouterr().out


def test_semantic_flag_invokes_embedder_loader(monkeypatch, tmp_path):
    calls: list[bool] = []

    class FakeEmbedder:
        name = "fake"
        version = "0"

        def embed(self, text):
            return [0.0]

    def fake_loader():
        calls.append(True)
        return FakeEmbedder()

    monkeypatch.setattr("mcpsec.embedder.load_default_embedder", fake_loader)
    code = cli.main(["scan", str(tmp_path), "--semantic"])
    assert calls == [True]
    assert code == 0


def test_default_scan_never_invokes_embedder_loader(monkeypatch, tmp_path):
    def boom():
        raise AssertionError("embedder loader must not run on a default scan")

    monkeypatch.setattr("mcpsec.embedder.load_default_embedder", boom)
    code = cli.main(["scan", str(tmp_path)])
    assert code == 0


def test_embedder_module_import_is_lazy():
    # Importing mcpsec.embedder must not pull in the model runtime.
    code = (
        "import sys; import mcpsec.embedder; "
        "print('clean' if 'onnxruntime' not in sys.modules "
        "and 'tokenizers' not in sys.modules else 'dirty')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.strip() == "clean"


def test_default_scan_does_not_import_model_runtime(tmp_path):
    code = (
        "import sys; from mcpsec import cli; "
        f"rc = cli.main(['scan', {str(tmp_path)!r}]); "
        "sys.stderr.write('clean' if 'onnxruntime' not in sys.modules "
        "and 'tokenizers' not in sys.modules else 'dirty')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stderr.strip() == "clean"


def test_load_default_embedder_raises_clear_error_when_extra_missing(monkeypatch):
    from mcpsec.embedder import SemanticBackendError

    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("onnxruntime", "tokenizers"):
            raise ImportError("No module named %r" % name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    import pytest

    with pytest.raises(SemanticBackendError) as exc:
        load_default_embedder()
    assert "[semantic]" in str(exc.value)
