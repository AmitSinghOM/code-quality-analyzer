"""Rating calculator for code quality."""

from __future__ import annotations

import math
from typing import Dict, List, Optional

from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS

# Above this share of unreadable/unparsed files the rating is not trustworthy.
COVERAGE_WARNING_THRESHOLD = 0.10

# Lines at which the "is this project substantial enough" factor saturates.
# Past this point extra lines do not raise the score — size is not quality.
SIZE_SATURATION_LINES = 2_000

# Distinct patterns at which the maturity component maxes out.
MATURITY_PATTERN_TARGET = 20


class QualityRater:
    """Calculates quality rating based on detected patterns.

    Two deliberate choices:

      - A pattern found in one file counts for less than the same pattern used
        across several. One incidental use is weaker evidence than a habit.
      - Project size no longer adds score. The old complexity bonus grew with
        file count and line count, so padding a codebase raised its rating.
        Size now only gates how much of the maturity component is reachable.
    """

    def __init__(
        self,
        dsa_found: Dict[str, List[str]],
        design_found: Dict[str, List[str]],
        files_scanned: int,
        total_lines: int,
        coverage_gap_ratio: float = 0.0,
    ):
        self.dsa_found = dsa_found
        self.design_found = design_found
        self.files_scanned = files_scanned
        self.total_lines = total_lines
        self.coverage_gap_ratio = max(0.0, min(1.0, coverage_gap_ratio))

    def calculate_rating(self):
        """Calculate overall rating from 1-10."""
        if self.files_scanned == 0:
            return 1.0, {
                "dsa_score": 0.0,
                "design_score": 0.0,
                "maturity_score": 0.0,
                "dsa_patterns_count": 0,
                "design_patterns_count": 0,
                "files_scanned": 0,
                "total_lines": 0,
                "coverage_gap_ratio": self.coverage_gap_ratio,
                "warnings": ["No Python files were analyzed — rating is not meaningful"],
            }

        dsa_score = self._score(self.dsa_found, DSA_PATTERNS, self._DSA_CURVE)
        design_score = self._score(self.design_found, SYSTEM_DESIGN_PATTERNS, self._DESIGN_CURVE)
        maturity_score = self._maturity_score()

        raw_score = (dsa_score * 0.4) + (design_score * 0.5) + (maturity_score * 0.1)

        warnings: List[str] = []
        if self.coverage_gap_ratio > COVERAGE_WARNING_THRESHOLD:
            # Do not present a confident number when a chunk of the project was
            # never read.
            raw_score *= 1.0 - min(0.3, self.coverage_gap_ratio)
            warnings.append(
                f"{self.coverage_gap_ratio:.0%} of discovered files could not be "
                f"analyzed — rating is a lower bound"
            )
        if self.total_lines < 200:
            warnings.append("Project is very small; pattern-based rating is noisy")

        final_rating = max(1.0, min(10.0, raw_score))

        breakdown = {
            "dsa_score": round(dsa_score, 2),
            "design_score": round(design_score, 2),
            "maturity_score": round(maturity_score, 2),
            "dsa_patterns_count": len(self.dsa_found),
            "design_patterns_count": len(self.design_found),
            "files_scanned": self.files_scanned,
            "total_lines": self.total_lines,
            "coverage_gap_ratio": round(self.coverage_gap_ratio, 3),
            "warnings": warnings,
        }

        return round(final_rating, 1), breakdown

    # -- scoring internals -------------------------------------------------

    # (weight_ceiling, score_at_ceiling) breakpoints
    _DSA_CURVE = ((2, 2.0, 1.0), (5, 4.0, 0.67), (10, 6.0, 0.4), (None, 8.0, 0.1))
    _DESIGN_CURVE = ((3, 2.0, 0.67), (8, 4.0, 0.4), (15, 6.0, 0.29), (None, 8.0, 0.1))

    def _score(self, found: Dict[str, List[str]], definitions: Dict, curve) -> float:
        if not found:
            return 1.0

        total_weight = 0.0
        for pattern, files in found.items():
            definition = definitions.get(pattern)
            if not definition:
                continue
            total_weight += definition["weight"] * self._breadth_factor(len(files))

        return self._apply_curve(total_weight, curve)

    @staticmethod
    def _breadth_factor(file_count: int) -> float:
        """Discount patterns that appear in only one or two files.

        1 file -> 0.6, 2 -> 0.8, 4+ -> 1.0.
        """
        if file_count <= 0:
            return 0.0
        return min(1.0, 0.6 + 0.2 * math.log2(file_count))

    @staticmethod
    def _apply_curve(total_weight: float, curve) -> float:
        lower_bound = 0.0
        for ceiling, base, slope in curve:
            if ceiling is None or total_weight < ceiling:
                return min(10.0, base + (total_weight - lower_bound) * slope)
            lower_bound = ceiling
        return 10.0  # pragma: no cover - curve always ends with None

    def _maturity_score(self) -> float:
        """Breadth of patterns, gated by whether the project is big enough.

        Deliberately does not grow with size: a large codebase gets access to
        the full range, it does not get points for being large.
        """
        distinct = len(self.dsa_found) + len(self.design_found)
        breadth = min(1.0, distinct / MATURITY_PATTERN_TARGET)
        size_adequacy = min(1.0, self.total_lines / SIZE_SATURATION_LINES)
        return 10.0 * breadth * size_adequacy

    def get_rating_label(self, rating: float) -> str:
        """Get human-readable label for rating."""
        if rating <= 2:
            return "Poor - Minimal value, basic code"
        elif rating <= 4:
            return "Below Average - Simple structures only"
        elif rating <= 6:
            return "Average - Some DSA/design patterns"
        elif rating <= 8:
            return "Good - Strategic DSA and design"
        else:
            return "Excellent - Comprehensive architecture"


def coverage_gap_ratio(files_scanned: int, skipped: int, unparsed: int) -> float:
    """Share of discovered files that produced no usable signal."""
    discovered = files_scanned + skipped
    if discovered <= 0:
        return 0.0
    return (skipped + unparsed) / discovered
