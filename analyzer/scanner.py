"""File scanner and pattern detector."""

import ast
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS


class CodeScanner:
    """Scans Python files for DSA and System Design patterns."""
    
    SKIP_DIRS = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', '.pytest_cache', 'dist', 'build'}
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.files_scanned = 0
        self.total_lines = 0
        self.imports: Set[str] = set()
        self.dsa_found: Dict[str, List[str]] = {}
        self.design_found: Dict[str, List[str]] = {}
    
    def scan(self) -> Tuple[Dict, Dict]:
        """Scan all Python files in the project."""
        for py_file in self._get_python_files():
            self._scan_file(py_file)
        return self.dsa_found, self.design_found
    
    def _get_python_files(self) -> List[Path]:
        """Get all Python files, excluding common non-source directories."""
        files = []
        for root, dirs, filenames in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for f in filenames:
                if f.endswith('.py'):
                    files.append(Path(root) / f)
        return files
    
    def _scan_file(self, filepath: Path):
        """Scan a single file for patterns."""
        try:
            content = filepath.read_text(encoding='utf-8')
            self.files_scanned += 1
            self.total_lines += len(content.splitlines())
            
            # Extract imports
            self._extract_imports(content)
            
            # Check for DSA patterns
            for pattern_name, pattern_def in DSA_PATTERNS.items():
                if self._matches_pattern(content, pattern_def):
                    if pattern_name not in self.dsa_found:
                        self.dsa_found[pattern_name] = []
                    self.dsa_found[pattern_name].append(str(filepath.relative_to(self.project_path)))
            
            # Check for System Design patterns
            for pattern_name, pattern_def in SYSTEM_DESIGN_PATTERNS.items():
                if self._matches_pattern(content, pattern_def):
                    if pattern_name not in self.design_found:
                        self.design_found[pattern_name] = []
                    self.design_found[pattern_name].append(str(filepath.relative_to(self.project_path)))
                    
        except Exception as e:
            pass  # Skip files that can't be read
    
    def _extract_imports(self, content: str):
        """Extract import statements from code."""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self.imports.add(node.module)
                        for alias in node.names:
                            self.imports.add(f"{node.module}.{alias.name}")
        except SyntaxError:
            pass
    
    def _matches_pattern(self, content: str, pattern_def: dict) -> bool:
        """Check if content matches a pattern definition."""
        content_lower = content.lower()
        
        # Check keywords
        for keyword in pattern_def["keywords"]:
            if keyword.lower() in content_lower:
                return True
        
        # Check imports
        for imp in pattern_def["imports"]:
            if any(imp.lower() in i.lower() for i in self.imports):
                return True
        
        return False
