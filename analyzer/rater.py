"""Rating calculator for code quality."""

from typing import Dict, List, Tuple
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS


class QualityRater:
    """Calculates quality rating based on detected patterns."""
    
    def __init__(self, dsa_found: Dict[str, List[str]], design_found: Dict[str, List[str]], 
                 files_scanned: int, total_lines: int):
        self.dsa_found = dsa_found
        self.design_found = design_found
        self.files_scanned = files_scanned
        self.total_lines = total_lines
    
    def calculate_rating(self) -> Tuple[float, Dict]:
        """Calculate overall rating from 1-10."""
        dsa_score = self._calculate_dsa_score()
        design_score = self._calculate_design_score()
        complexity_bonus = self._calculate_complexity_bonus()
        
        # Weighted combination: DSA 40%, Design 50%, Complexity 10%
        raw_score = (dsa_score * 0.4) + (design_score * 0.5) + (complexity_bonus * 0.1)
        
        # Normalize to 1-10 scale
        final_rating = max(1.0, min(10.0, raw_score))
        
        breakdown = {
            "dsa_score": round(dsa_score, 2),
            "design_score": round(design_score, 2),
            "complexity_bonus": round(complexity_bonus, 2),
            "dsa_patterns_count": len(self.dsa_found),
            "design_patterns_count": len(self.design_found),
            "files_scanned": self.files_scanned,
            "total_lines": self.total_lines
        }
        
        return round(final_rating, 1), breakdown
    
    def _calculate_dsa_score(self) -> float:
        """Calculate DSA score based on patterns found and their weights."""
        if not self.dsa_found:
            return 1.0
        
        total_weight = 0
        for pattern_name in self.dsa_found:
            if pattern_name in DSA_PATTERNS:
                total_weight += DSA_PATTERNS[pattern_name]["weight"]
        
        # Scale: 0-2 weight = 2-4, 2-5 = 4-6, 5-10 = 6-8, 10+ = 8-10
        if total_weight < 2:
            return 2 + total_weight
        elif total_weight < 5:
            return 4 + (total_weight - 2) * 0.67
        elif total_weight < 10:
            return 6 + (total_weight - 5) * 0.4
        else:
            return min(10, 8 + (total_weight - 10) * 0.1)
    
    def _calculate_design_score(self) -> float:
        """Calculate System Design score based on patterns found."""
        if not self.design_found:
            return 1.0
        
        total_weight = 0
        for pattern_name in self.design_found:
            if pattern_name in SYSTEM_DESIGN_PATTERNS:
                total_weight += SYSTEM_DESIGN_PATTERNS[pattern_name]["weight"]
        
        # Similar scaling as DSA
        if total_weight < 3:
            return 2 + total_weight * 0.67
        elif total_weight < 8:
            return 4 + (total_weight - 3) * 0.4
        elif total_weight < 15:
            return 6 + (total_weight - 8) * 0.29
        else:
            return min(10, 8 + (total_weight - 15) * 0.1)
    
    def _calculate_complexity_bonus(self) -> float:
        """Bonus for project size and complexity."""
        if self.files_scanned == 0:
            return 0
        
        # More files and lines indicate more complex project
        file_score = min(5, self.files_scanned / 5)
        line_score = min(5, self.total_lines / 500)
        
        return file_score + line_score
    
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
