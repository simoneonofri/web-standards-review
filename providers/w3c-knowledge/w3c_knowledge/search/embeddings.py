"""Pinned, offline-at-runtime multilingual E5 embeddings on the CPU."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from urllib.request import urlopen

MODEL_ID = "intfloat/multilingual-e5-small"
REVISION = "614241f622f53c4eeff9890bdc4f31cfecc418b3"
DIMENSIONS = 384
FINGERPRINT = f"{MODEL_ID}@{REVISION}:onnx-f32:mean-l2:window480-overlap48:v1"
FILES = {
    "model.onnx": ("onnx/model.onnx", 470268510, "ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665"),
    "tokenizer.json": ("tokenizer.json", 17082730, "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39"),
}


class EmbeddingUnavailable(RuntimeError):
    pass


def valid_file(path: Path, size: int, digest: str) -> bool:
    if not path.is_file() or path.is_symlink() or path.stat().st_size != size:
        return False
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() == digest


def download_model(directory: Path) -> dict:
    """Explicit public download, no Hub credentials or executable remote code."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, (remote, size, digest) in FILES.items():
        destination = directory / name
        if valid_file(destination, size, digest):
            continue
        fd, temporary = tempfile.mkstemp(prefix=name + ".", dir=directory)
        try:
            with os.fdopen(fd, "wb") as output, urlopen(
                f"https://huggingface.co/{MODEL_ID}/resolve/{REVISION}/{remote}", timeout=120
            ) as response:
                total = 0
                while data := response.read(1024 * 1024):
                    total += len(data)
                    if total > size:
                        raise EmbeddingUnavailable("Model download exceeds pinned size")
                    output.write(data)
            if not valid_file(Path(temporary), size, digest):
                raise EmbeddingUnavailable("Model download does not match pinned SHA-256")
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return {"model": MODEL_ID, "revision": REVISION, "verified": True}


class LocalEncoder:
    fingerprint = FINGERPRINT

    def __init__(self, directory: Path, threads: int = 2):
        for name, (_, size, digest) in FILES.items():
            if not valid_file(directory / name, size, digest):
                raise EmbeddingUnavailable("Pinned local model missing or invalid; run download-embedding-model")
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise EmbeddingUnavailable("Install the provider with its [vectors] extra") from exc
        self.np = np
        self.tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
        # Never truncate silently; long passages are chunked and long queries rejected.
        self.tokenizer.no_truncation()
        self.tokenizer.enable_padding(pad_id=1, pad_token="<pad>")
        options = ort.SessionOptions()
        options.intra_op_num_threads = max(1, min(threads, 8))
        options.inter_op_num_threads = 1
        self.runtime = ort.InferenceSession(str(directory / "model.onnx"), sess_options=options, providers=["CPUExecutionProvider"])

    def chunks(self, text: str) -> list[tuple[int, int]]:
        """Overlapping token windows with offsets into the unchanged source text."""
        encoded = self.tokenizer.encode(text, add_special_tokens=False)
        offsets = [pair for pair in encoded.offsets if pair[1] > pair[0]]
        if not offsets:
            return []
        spans = []
        for first in range(0, len(offsets), 432):
            last = min(first + 480, len(offsets))
            start = 0 if first == 0 else offsets[first][0]
            end = len(text) if last == len(offsets) else offsets[last][0]
            spans.append((start, end))
            if last == len(offsets):
                break
        return spans

    def encode(self, texts: list[str], *, query: bool = False) -> list[list[float]]:
        if not texts:
            return []
        prefix = "query: " if query else "passage: "
        encoded = self.tokenizer.encode_batch([prefix + value for value in texts])
        if any(len(item.ids) > 512 for item in encoded):
            raise ValueError("Embedding input exceeds 512 tokens; shorten the query or re-chunk the source")
        np = self.np
        inputs = {
            "input_ids": np.asarray([item.ids for item in encoded], dtype=np.int64),
            "attention_mask": np.asarray([item.attention_mask for item in encoded], dtype=np.int64),
            "token_type_ids": np.asarray([item.type_ids for item in encoded], dtype=np.int64),
        }
        hidden = self.runtime.run(None, {item.name: inputs[item.name] for item in self.runtime.get_inputs()})[0]
        mask = inputs["attention_mask"][..., None]
        pooled = (hidden * mask).sum(axis=1) / mask.sum(axis=1)
        vectors = pooled / np.linalg.norm(pooled, axis=1, keepdims=True)
        if vectors.shape != (len(texts), DIMENSIONS) or not np.isfinite(vectors).all():
            raise EmbeddingUnavailable("Local model returned invalid embeddings")
        return vectors.astype(np.float32).tolist()
