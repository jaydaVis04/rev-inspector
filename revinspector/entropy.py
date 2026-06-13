from __future__ import annotations

import math
from collections import Counter
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in Counter(data).values())


def file_entropy(path: Path) -> float:
    return shannon_entropy(path.read_bytes())
