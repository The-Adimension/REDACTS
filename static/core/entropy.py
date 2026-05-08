"""Canonical Shannon entropy computation for REDACTS.

Replaces 3 independent implementations (manifest.py, scanner.py,
file_analyzer.py) with a single utility.
"""

from __future__ import annotations

import math
from collections import Counter


def compute_shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of *data* (0-8 for byte-level).

    Parameters
    data:
        Raw byte sequence to measure.

    Returns
    float
        Entropy in bits per byte.  Returns ``0.0`` when *data* is empty.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
