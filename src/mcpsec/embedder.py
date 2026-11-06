"""Default local ONNX sentence-transformer embedder (ADR-0008).

The base install stays PyYAML-only: importing this module performs no heavy
imports. ``load_default_embedder`` is the single entry point that lazily
imports ``onnxruntime`` and ``tokenizers``, downloads the pinned model files
(verifying their SHA-256), and returns a ready ``Embedder``.

Model: ``Xenova/all-MiniLM-L6-v2`` (ONNX port of
``sentence-transformers/all-MiniLM-L6-v2``), Apache-2.0, ~86 MB fp32,
CPU-only, 384-dim. Pinned by Hugging Face revision (commit SHA) plus per-file
SHA-256 so results are reproducible.
"""

from __future__ import annotations

import hashlib
import math
import os
import urllib.request
from collections.abc import Sequence
from pathlib import Path

from .errors import McpsecError
from .model import Embedder

MODEL_NAME = "all-MiniLM-L6-v2"
MODEL_REPO = "Xenova/all-MiniLM-L6-v2"
MODEL_LICENSE = "Apache-2.0"
# Pinned Hugging Face revision (commit SHA) of the ONNX model — no floating ref.
MODEL_REVISION = "751bff37182d3f1213fa05d7196b954e230abad9"

_HF_BASE = f"https://huggingface.co/{MODEL_REPO}/resolve/{MODEL_REVISION}"

# Remote path -> (sha256, local relative path under the model cache dir).
_MODEL_FILES: dict[str, tuple[str, str]] = {
    "onnx/model.onnx": (
        "759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e",
        "model.onnx",
    ),
    "tokenizer.json": (
        "da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0",
        "tokenizer.json",
    ),
}

_MAX_SEQUENCE_LENGTH = 512


class SemanticBackendError(McpsecError):
    """The semantic backend (runtime or model files) is unavailable."""


def _cache_dir() -> Path:
    override = os.environ.get("MCPCACHE_DIR")
    base = Path(override) if override else Path.home() / ".cache" / "mcpsec"
    return base / "models" / MODEL_NAME / MODEL_REVISION


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, dest: Path, expected_sha256: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, tmp.open("wb") as out:  # nosec B310 - constant https URL, sha256-verified
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                out.write(chunk)
    except OSError as exc:
        raise SemanticBackendError(f"failed to download model file {url}: {exc}") from exc
    if _sha256(tmp) != expected_sha256:
        tmp.unlink(missing_ok=True)
        raise SemanticBackendError(f"sha256 mismatch for {url}")
    tmp.replace(dest)


def _ensure_model_files() -> dict[str, Path]:
    root = _cache_dir()
    paths: dict[str, Path] = {}
    for remote_path, (expected_sha256, local_name) in _MODEL_FILES.items():
        dest = root / local_name
        if dest.exists() and _sha256(dest) == expected_sha256:
            paths[remote_path] = dest
            continue
        _download(f"{_HF_BASE}/{remote_path}", dest, expected_sha256)
        paths[remote_path] = dest
    return paths


def _mean_pool_normalize(hidden: Sequence[Sequence[float]], mask: Sequence[int]) -> list[float]:
    """Mean-pool token embeddings over the attention mask, then L2-normalize."""
    hidden_size = len(hidden[0])
    summed = [0.0] * hidden_size
    count = 0
    for row, keep in zip(hidden, mask):
        if not keep:
            continue
        count += 1
        for i, value in enumerate(row):
            summed[i] += value
    if count == 0:
        return [0.0] * hidden_size
    pooled = [value / count for value in summed]
    norm = math.sqrt(sum(value * value for value in pooled))
    if norm == 0.0:
        return pooled
    return [value / norm for value in pooled]


class LocalOnnxEmbedder:
    """A sentence embedding produced by the pinned local ONNX model."""

    name = MODEL_NAME
    version = MODEL_REVISION

    def __init__(self, session, tokenizer) -> None:
        self._session = session
        self._tokenizer = tokenizer
        self._input_names = [item.name for item in session.get_inputs()]
        self._output_name = session.get_outputs()[0].name

    def embed(self, text: str) -> Sequence[float]:
        encoding = self._tokenizer.encode(text)
        ids = encoding.ids
        mask = encoding.attention_mask
        type_ids = encoding.type_ids

        feed = {
            "input_ids": [ids],
            "attention_mask": [mask],
            "token_type_ids": [type_ids],
        }
        # Only pass the inputs the graph actually declares (some exports omit
        # token_type_ids), keyed by the session's real input names.
        inputs = {
            name: feed[name]
            for name in self._input_names
            if name in feed
        }
        last_hidden_state = self._session.run([self._output_name], inputs)[0]
        # last_hidden_state: [batch=1, seq, hidden]
        hidden = last_hidden_state[0].tolist()
        return _mean_pool_normalize(hidden, mask)


def load_default_embedder() -> Embedder:
    """Lazily build the default local embedder (imports + downloads on demand).

    Raises ``SemanticBackendError`` when the ``[semantic]`` extra is not
    installed or the pinned model cannot be obtained/loaded.
    """
    try:
        import onnxruntime
        from tokenizers import Tokenizer
    except ImportError as exc:
        raise SemanticBackendError(
            "semantic detection requires the [semantic] extra: "
            "install with `pip install mcpsec-scan[semantic]`"
        ) from exc

    paths = _ensure_model_files()
    tokenizer = Tokenizer.from_file(str(paths["tokenizer.json"]))
    tokenizer.enable_truncation(max_length=_MAX_SEQUENCE_LENGTH)

    session = onnxruntime.InferenceSession(str(paths["onnx/model.onnx"]))
    return LocalOnnxEmbedder(session, tokenizer)
