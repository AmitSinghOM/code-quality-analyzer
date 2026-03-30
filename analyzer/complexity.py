"""
Advanced Time and Space Complexity Analyzer.

Features:
- AST-based deep analysis
- Type hints analysis for data size inference
- Data flow analysis for variable tracking
- Symbolic execution for path simulation
- Enhanced heuristics for edge cases
"""

import ast
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from copy import deepcopy


class ComplexityClass(Enum):
    """Big-O complexity classes."""
    O_1 = "O(1)"
    O_LOG_N = "O(log n)"
    O_N = "O(n)"
    O_N_LOG_N = "O(n log n)"
    O_N_SQUARED = "O(n²)"
    O_N_CUBED = "O(n³)"
    O_N_K = "O(n^k)"
    O_2_N = "O(2^n)"
    O_N_FACTORIAL = "O(n!)"
    UNKNOWN = "Unknown"
    
    @classmethod
    def from_loop_depth(cls, depth: int) -> 'ComplexityClass':
        if depth == 0:
            return cls.O_1
        elif depth == 1:
            return cls.O_N
        elif depth == 2:
            return cls.O_N_SQUARED
        elif depth == 3:
            return cls.O_N_CUBED
        else:
            return cls.O_N_K


@dataclass
class VariableInfo:
    """Tracks variable information for data flow analysis."""
    name: str
    source: str  # 'parameter', 'assignment', 'loop', 'comprehension'
    type_hint: Optional[str] = None
    is_collection: bool = False
    collection_type: Optional[str] = None  # 'list', 'dict', 'set', 'tuple'
    size_variable: Optional[str] = None  # Variable that determines size (e.g., 'n')
    is_input_dependent: bool = False  # True if size depends on function input
    constant_size: Optional[int] = None  # If size is known constant


@dataclass
class LoopInfo:
    """Information about a loop for complexity analysis."""
    loop_type: str  # 'for', 'while'
    iterator_var: str
    iterable_source: str  # What's being iterated
    estimated_iterations: str  # 'n', 'log n', 'constant', etc.
    is_input_dependent: bool
    has_early_exit: bool = False
    nested_depth: int = 0


@dataclass 
class FunctionComplexity:
    """Complete complexity analysis for a function."""
    name: str
    file: str
    line: int
    time_complexity: str
    space_complexity: str
    confidence: float  # 0.0 to 1.0
    reasoning: List[str] = field(default_factory=list)
    loop_analysis: List[LoopInfo] = field(default_factory=list)
    variables: Dict[str, VariableInfo] = field(default_factory=dict)
    has_recursion: bool = False
    recursion_type: Optional[str] = None  # 'linear', 'binary', 'multiple'
    uses_memoization: bool = False
    has_early_exit: bool = False
    dominant_operation: Optional[str] = None


# Known operation complexities
BUILTIN_TIME_COMPLEXITY = {
    # O(1) operations
    'len': 'O(1)', 'append': 'O(1)', 'pop': 'O(1)', 'add': 'O(1)',
    'get': 'O(1)', 'setdefault': 'O(1)', 'clear': 'O(1)',
    # O(n) operations  
    'sort': 'O(n log n)', 'sorted': 'O(n log n)', 'reverse': 'O(n)',
    'copy': 'O(n)', 'list': 'O(n)', 'set': 'O(n)', 'dict': 'O(n)',
    'sum': 'O(n)', 'max': 'O(n)', 'min': 'O(n)', 'any': 'O(n)', 'all': 'O(n)',
    'index': 'O(n)', 'count': 'O(n)', 'remove': 'O(n)', 'insert': 'O(n)',
    'extend': 'O(k)', 'update': 'O(k)',
    # O(log n) operations
    'bisect_left': 'O(log n)', 'bisect_right': 'O(log n)',
    'heappush': 'O(log n)', 'heappop': 'O(log n)',
    'insort': 'O(n)', 'insort_left': 'O(n)', 'insort_right': 'O(n)',
    # O(n log n)
    'heapify': 'O(n)', 'nlargest': 'O(n log k)', 'nsmallest': 'O(n log k)',
}

BUILTIN_SPACE_COMPLEXITY = {
    'sorted': 'O(n)', 'list': 'O(n)', 'set': 'O(n)', 'dict': 'O(n)',
    'copy': 'O(n)', 'deepcopy': 'O(n)', 'slice': 'O(k)',
}

# Type hints that indicate collections
COLLECTION_TYPE_HINTS = {
    'List': 'list', 'list': 'list',
    'Dict': 'dict', 'dict': 'dict', 
    'Set': 'set', 'set': 'set',
    'Tuple': 'tuple', 'tuple': 'tuple',
    'Sequence': 'list', 'Iterable': 'list',
    'Collection': 'list', 'Mapping': 'dict',
}


class TypeHintAnalyzer(ast.NodeVisitor):
    """Analyzes type hints to infer data sizes."""
    
    def __init__(self):
        self.param_types: Dict[str, VariableInfo] = {}
        self.return_type: Optional[str] = None
    
    def analyze_function(self, node: ast.FunctionDef) -> Dict[str, VariableInfo]:
        """Extract type information from function signature."""
        self.param_types = {}
        
        # Analyze parameters
        for arg in node.args.args:
            var_info = VariableInfo(
                name=arg.arg,
                source='parameter',
                is_input_dependent=True
            )
            
            if arg.annotation:
                type_str = self._annotation_to_string(arg.annotation)
                var_info.type_hint = type_str
                var_info.is_collection = self._is_collection_type(arg.annotation)
                var_info.collection_type = self._get_collection_type(arg.annotation)
            
            self.param_types[arg.arg] = var_info
        
        # Analyze return type
        if node.returns:
            self.return_type = self._annotation_to_string(node.returns)
        
        return self.param_types
    
    def _annotation_to_string(self, annotation) -> str:
        """Convert annotation AST to string."""
        if isinstance(annotation, ast.Name):
            return annotation.id
        elif isinstance(annotation, ast.Constant):
            return str(annotation.value)
        elif isinstance(annotation, ast.Subscript):
            base = self._annotation_to_string(annotation.value)
            if isinstance(annotation.slice, ast.Tuple):
                args = ', '.join(self._annotation_to_string(e) for e in annotation.slice.elts)
            else:
                args = self._annotation_to_string(annotation.slice)
            return f"{base}[{args}]"
        elif isinstance(annotation, ast.Attribute):
            return f"{self._annotation_to_string(annotation.value)}.{annotation.attr}"
        return "Unknown"
    
    def _is_collection_type(self, annotation) -> bool:
        """Check if type hint indicates a collection."""
        if isinstance(annotation, ast.Name):
            return annotation.id in COLLECTION_TYPE_HINTS
        elif isinstance(annotation, ast.Subscript):
            return self._is_collection_type(annotation.value)
        return False
    
    def _get_collection_type(self, annotation) -> Optional[str]:
        """Get the base collection type."""
        if isinstance(annotation, ast.Name):
            return COLLECTION_TYPE_HINTS.get(annotation.id)
        elif isinstance(annotation, ast.Subscript):
            return self._get_collection_type(annotation.value)
        return None


class DataFlowAnalyzer(ast.NodeVisitor):
    """Tracks data flow to understand variable relationships."""
    
    def __init__(self, initial_vars: Dict[str, VariableInfo]):
        self.variables = deepcopy(initial_vars)
        self.input_params = set(initial_vars.keys())
        self.derived_from: Dict[str, Set[str]] = {k: {k} for k in initial_vars}
    
    def analyze(self, node: ast.FunctionDef):
        """Analyze data flow in function body."""
        for stmt in node.body:
            self.visit(stmt)
        return self.variables, self.derived_from
    
    def visit_Assign(self, node: ast.Assign):
        """Track assignments to understand data relationships."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                sources = self._get_value_sources(node.value)
                
                var_info = VariableInfo(
                    name=var_name,
                    source='assignment',
                    is_input_dependent=any(s in self.input_params or 
                        self.variables.get(s, VariableInfo(s, '')).is_input_dependent 
                        for s in sources)
                )
                
                # Check if it's a collection creation
                if isinstance(node.value, (ast.List, ast.ListComp)):
                    var_info.is_collection = True
                    var_info.collection_type = 'list'
                elif isinstance(node.value, (ast.Dict, ast.DictComp)):
                    var_info.is_collection = True
                    var_info.collection_type = 'dict'
                elif isinstance(node.value, (ast.Set, ast.SetComp)):
                    var_info.is_collection = True
                    var_info.collection_type = 'set'
                
                # Track constant size if possible
                if isinstance(node.value, ast.List):
                    var_info.constant_size = len(node.value.elts)
                
                self.variables[var_name] = var_info
                self.derived_from[var_name] = sources
        
        self.generic_visit(node)
    
    def visit_For(self, node: ast.For):
        """Track loop variables."""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            iter_sources = self._get_value_sources(node.iter)
            
            var_info = VariableInfo(
                name=var_name,
                source='loop',
                is_input_dependent=any(s in self.input_params or
                    self.variables.get(s, VariableInfo(s, '')).is_input_dependent
                    for s in iter_sources)
            )
            self.variables[var_name] = var_info
            self.derived_from[var_name] = iter_sources
        
        self.generic_visit(node)
    
    def _get_value_sources(self, node) -> Set[str]:
        """Get all variable names that a value depends on."""
        sources = set()
        
        if isinstance(node, ast.Name):
            sources.add(node.id)
            if node.id in self.derived_from:
                sources.update(self.derived_from[node.id])
        elif isinstance(node, ast.BinOp):
            sources.update(self._get_value_sources(node.left))
            sources.update(self._get_value_sources(node.right))
        elif isinstance(node, ast.Call):
            for arg in node.args:
                sources.update(self._get_value_sources(arg))
            if isinstance(node.func, ast.Name):
                sources.add(f"call:{node.func.id}")
        elif isinstance(node, ast.Subscript):
            sources.update(self._get_value_sources(node.value))
        elif isinstance(node, ast.Attribute):
            sources.update(self._get_value_sources(node.value))
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                sources.update(self._get_value_sources(elt))
        elif isinstance(node, ast.ListComp):
            for gen in node.generators:
                sources.update(self._get_value_sources(gen.iter))
        
        return sources


class SymbolicExecutor(ast.NodeVisitor):
    """Simulates code paths to estimate complexity."""
    
    def __init__(self, variables: Dict[str, VariableInfo], derived_from: Dict[str, Set[str]]):
        self.variables = variables
        self.derived_from = derived_from
        self.current_depth = 0
        self.max_depth = 0
        self.loop_stack: List[LoopInfo] = []
        self.all_loops: List[LoopInfo] = []
        self.has_early_exit = False
        self.space_allocations: List[Tuple[str, str]] = []  # (type, size_estimate)
        self.expensive_ops: List[Tuple[str, str]] = []  # (operation, complexity)
        self.recursive_calls = 0
        self.recursive_pattern: Optional[str] = None
        self.current_function: Optional[str] = None
    
    def execute(self, node: ast.FunctionDef) -> Dict:
        """Symbolically execute function to gather complexity info."""
        self.current_function = node.name
        
        for stmt in node.body:
            self.visit(stmt)
        
        return {
            'max_loop_depth': self.max_depth,
            'loops': self.all_loops,
            'has_early_exit': self.has_early_exit,
            'space_allocations': self.space_allocations,
            'expensive_ops': self.expensive_ops,
            'recursive_calls': self.recursive_calls,
            'recursive_pattern': self.recursive_pattern,
        }
    
    def visit_For(self, node: ast.For):
        """Analyze for loop complexity."""
        self.current_depth += 1
        self.max_depth = max(self.max_depth, self.current_depth)
        
        loop_info = self._analyze_for_loop(node)
        loop_info.nested_depth = self.current_depth
        self.loop_stack.append(loop_info)
        self.all_loops.append(loop_info)
        
        # Check for early exit
        for stmt in ast.walk(node):
            if isinstance(stmt, (ast.Break, ast.Return)):
                loop_info.has_early_exit = True
                self.has_early_exit = True
        
        self.generic_visit(node)
        self.loop_stack.pop()
        self.current_depth -= 1
    
    def visit_While(self, node: ast.While):
        """Analyze while loop complexity."""
        self.current_depth += 1
        self.max_depth = max(self.max_depth, self.current_depth)
        
        loop_info = self._analyze_while_loop(node)
        loop_info.nested_depth = self.current_depth
        self.loop_stack.append(loop_info)
        self.all_loops.append(loop_info)
        
        # Check for early exit
        for stmt in ast.walk(node):
            if isinstance(stmt, (ast.Break, ast.Return)):
                loop_info.has_early_exit = True
                self.has_early_exit = True
        
        self.generic_visit(node)
        self.loop_stack.pop()
        self.current_depth -= 1
    
    def _analyze_for_loop(self, node: ast.For) -> LoopInfo:
        """Determine iteration count for a for loop."""
        iter_var = node.target.id if isinstance(node.target, ast.Name) else "unknown"
        iterable = node.iter
        
        # Analyze what's being iterated
        if isinstance(iterable, ast.Call):
            func_name = self._get_call_name(iterable)
            
            if func_name == 'range':
                return self._analyze_range_loop(node, iter_var, iterable)
            elif func_name in ('enumerate', 'zip'):
                # Get the underlying iterable
                if iterable.args:
                    inner = self._get_iterable_source(iterable.args[0])
                    is_input = self._is_input_dependent(iterable.args[0])
                    return LoopInfo('for', iter_var, inner, 'n', is_input)
        
        source = self._get_iterable_source(iterable)
        is_input = self._is_input_dependent(iterable)
        
        return LoopInfo('for', iter_var, source, 'n', is_input)
    
    def _analyze_range_loop(self, node, iter_var, call) -> LoopInfo:
        """Analyze range() call to determine iterations."""
        args = call.args
        
        if len(args) == 1:
            # range(n)
            if isinstance(args[0], ast.Constant):
                return LoopInfo('for', iter_var, f'range({args[0].value})', 
                              'constant', False)
            elif isinstance(args[0], ast.Name):
                is_input = args[0].id in self.variables and \
                          self.variables[args[0].id].is_input_dependent
                return LoopInfo('for', iter_var, f'range({args[0].id})', 'n', is_input)
            elif isinstance(args[0], ast.Call):
                # range(len(x))
                inner_call = self._get_call_name(args[0])
                if inner_call == 'len' and args[0].args:
                    source = self._get_iterable_source(args[0].args[0])
                    is_input = self._is_input_dependent(args[0].args[0])
                    return LoopInfo('for', iter_var, f'range(len({source}))', 'n', is_input)
        
        return LoopInfo('for', iter_var, 'range(...)', 'n', True)
    
    def _analyze_while_loop(self, node: ast.While) -> LoopInfo:
        """Analyze while loop to estimate iterations."""
        # Check for common patterns
        test = node.test
        
        # Pattern: while left < right (binary search)
        if isinstance(test, ast.Compare):
            if self._is_binary_search_pattern(node):
                return LoopInfo('while', '', 'binary_search', 'log n', True)
        
        # Default: assume linear
        return LoopInfo('while', '', 'condition', 'n', True)
    
    def _is_binary_search_pattern(self, node: ast.While) -> bool:
        """Detect binary search pattern in while loop."""
        # Look for mid = (left + right) // 2 pattern
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                if isinstance(stmt.value, ast.BinOp):
                    if isinstance(stmt.value.op, ast.FloorDiv):
                        return True
        return False

    
    def visit_Call(self, node: ast.Call):
        """Track function calls for complexity."""
        func_name = self._get_call_name(node)
        
        if func_name:
            # Check for recursion
            if func_name == self.current_function:
                self.recursive_calls += 1
                self._detect_recursion_pattern(node)
            
            # Check for expensive operations
            if func_name in BUILTIN_TIME_COMPLEXITY:
                self.expensive_ops.append((func_name, BUILTIN_TIME_COMPLEXITY[func_name]))
            
            # Check for space allocations
            if func_name in BUILTIN_SPACE_COMPLEXITY:
                self.space_allocations.append((func_name, BUILTIN_SPACE_COMPLEXITY[func_name]))
        
        self.generic_visit(node)
    
    def visit_ListComp(self, node: ast.ListComp):
        """Track list comprehension space."""
        gens = len(node.generators)
        if gens == 1:
            self.space_allocations.append(('list_comp', 'O(n)'))
        else:
            self.space_allocations.append(('list_comp', f'O(n^{gens})'))
        
        # Also counts as nested loops for time
        self.current_depth += gens
        self.max_depth = max(self.max_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= gens
    
    def visit_DictComp(self, node: ast.DictComp):
        """Track dict comprehension space."""
        gens = len(node.generators)
        self.space_allocations.append(('dict_comp', f'O(n^{gens})' if gens > 1 else 'O(n)'))
        self.current_depth += gens
        self.max_depth = max(self.max_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= gens
    
    def _detect_recursion_pattern(self, call_node: ast.Call):
        """Detect type of recursion (linear, binary, multiple)."""
        # Count recursive calls in the function
        if self.recursive_calls == 1:
            self.recursive_pattern = 'linear'  # O(n)
        elif self.recursive_calls == 2:
            self.recursive_pattern = 'binary'  # O(2^n) or O(n) with memoization
        else:
            self.recursive_pattern = 'multiple'  # O(k^n)
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
    
    def _get_iterable_source(self, node) -> str:
        """Get string representation of iterable source."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_iterable_source(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return f"{self._get_call_name(node)}(...)"
        elif isinstance(node, ast.Subscript):
            return f"{self._get_iterable_source(node.value)}[...]"
        return "unknown"
    
    def _is_input_dependent(self, node) -> bool:
        """Check if node depends on function input."""
        if isinstance(node, ast.Name):
            if node.id in self.variables:
                return self.variables[node.id].is_input_dependent
        elif isinstance(node, ast.Attribute):
            return self._is_input_dependent(node.value)
        elif isinstance(node, ast.Call):
            return any(self._is_input_dependent(arg) for arg in node.args)
        elif isinstance(node, ast.Subscript):
            return self._is_input_dependent(node.value)
        return False


class AdvancedComplexityAnalyzer:
    """Main analyzer combining all analysis techniques."""
    
    def __init__(self):
        self.all_functions: Set[str] = set()
    
    def analyze_function(self, node: ast.FunctionDef, filepath: Path) -> FunctionComplexity:
        """Perform complete complexity analysis on a function."""
        reasoning = []
        confidence = 0.8  # Start with high confidence
        
        # 1. Type hints analysis
        type_analyzer = TypeHintAnalyzer()
        param_vars = type_analyzer.analyze_function(node)
        reasoning.append(f"Parameters: {len(param_vars)} ({sum(1 for v in param_vars.values() if v.type_hint)} typed)")
        
        # 2. Check for memoization
        uses_memo = self._check_memoization(node)
        if uses_memo:
            reasoning.append("Uses memoization decorator")
        
        # 3. Data flow analysis
        flow_analyzer = DataFlowAnalyzer(param_vars)
        variables, derived_from = flow_analyzer.analyze(node)
        
        # 4. Symbolic execution
        executor = SymbolicExecutor(variables, derived_from)
        exec_result = executor.execute(node)
        
        # 5. Calculate time complexity
        time_complexity, time_reasoning = self._calculate_time_complexity(
            exec_result, uses_memo, variables
        )
        reasoning.extend(time_reasoning)
        
        # 6. Calculate space complexity
        space_complexity, space_reasoning = self._calculate_space_complexity(
            exec_result, uses_memo
        )
        reasoning.extend(space_reasoning)
        
        # 7. Adjust confidence based on analysis quality
        if exec_result['recursive_calls'] > 0 and not uses_memo:
            confidence -= 0.2  # Recursion without memo is harder to analyze
        if exec_result['max_loop_depth'] > 2:
            confidence -= 0.1  # Deep nesting is complex
        if not any(v.type_hint for v in param_vars.values()):
            confidence -= 0.1  # No type hints reduces confidence
        
        return FunctionComplexity(
            name=node.name,
            file=str(filepath),
            line=node.lineno,
            time_complexity=time_complexity,
            space_complexity=space_complexity,
            confidence=max(0.3, confidence),
            reasoning=reasoning,
            loop_analysis=exec_result['loops'],
            variables=variables,
            has_recursion=exec_result['recursive_calls'] > 0,
            recursion_type=exec_result['recursive_pattern'],
            uses_memoization=uses_memo,
            has_early_exit=exec_result['has_early_exit'],
            dominant_operation=self._get_dominant_operation(exec_result)
        )
    
    def _check_memoization(self, node: ast.FunctionDef) -> bool:
        """Check if function uses memoization."""
        memo_decorators = {'lru_cache', 'cache', 'memoize', 'cached', 'functools.lru_cache'}
        
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id in memo_decorators:
                return True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name) and decorator.func.id in memo_decorators:
                    return True
                elif isinstance(decorator.func, ast.Attribute) and decorator.func.attr in memo_decorators:
                    return True
        return False
    
    def _calculate_time_complexity(self, exec_result: Dict, uses_memo: bool, 
                                   variables: Dict[str, VariableInfo]) -> Tuple[str, List[str]]:
        """Calculate time complexity from execution results."""
        reasoning = []
        
        # Handle recursion
        if exec_result['recursive_calls'] > 0:
            pattern = exec_result['recursive_pattern']
            if uses_memo:
                reasoning.append(f"Recursive ({pattern}) with memoization → O(n)")
                return "O(n)", reasoning
            elif pattern == 'linear':
                reasoning.append("Linear recursion without memoization → O(n)")
                return "O(n)", reasoning
            elif pattern == 'binary':
                reasoning.append("Binary recursion without memoization → O(2^n)")
                return "O(2^n)", reasoning
            else:
                reasoning.append(f"Multiple recursion ({exec_result['recursive_calls']} calls) → O(k^n)")
                return "O(k^n)", reasoning
        
        # Handle loops
        max_depth = exec_result['max_loop_depth']
        loops = exec_result['loops']
        
        # Check for special patterns
        has_log_n = any(l.estimated_iterations == 'log n' for l in loops)
        has_sorting = any(op[0] in ('sort', 'sorted') for op in exec_result['expensive_ops'])
        
        if max_depth == 0:
            if has_sorting:
                reasoning.append("No loops but uses sorting → O(n log n)")
                return "O(n log n)", reasoning
            
            # Check for expensive operations
            for op, comp in exec_result['expensive_ops']:
                if 'n' in comp:
                    reasoning.append(f"Uses {op}() → {comp}")
                    return comp, reasoning
            
            reasoning.append("No loops or expensive operations → O(1)")
            return "O(1)", reasoning
        
        elif max_depth == 1:
            if has_log_n:
                reasoning.append("Single loop with log n iterations → O(log n)")
                return "O(log n)", reasoning
            if has_sorting:
                reasoning.append("Single loop + sorting → O(n log n)")
                return "O(n log n)", reasoning
            
            # Check if loop has early exit that makes it effectively O(1) or O(log n)
            if loops and loops[0].has_early_exit:
                reasoning.append("Single loop with early exit → O(n) worst case")
            else:
                reasoning.append("Single loop over input → O(n)")
            return "O(n)", reasoning
        
        elif max_depth == 2:
            if has_log_n:
                reasoning.append("Nested loops with log n inner → O(n log n)")
                return "O(n log n)", reasoning
            reasoning.append(f"Nested loops (depth {max_depth}) → O(n²)")
            return "O(n²)", reasoning
        
        elif max_depth == 3:
            reasoning.append(f"Triple nested loops → O(n³)")
            return "O(n³)", reasoning
        
        else:
            reasoning.append(f"Deep nesting (depth {max_depth}) → O(n^{max_depth})")
            return f"O(n^{max_depth})", reasoning
    
    def _calculate_space_complexity(self, exec_result: Dict, uses_memo: bool) -> Tuple[str, List[str]]:
        """Calculate space complexity from execution results."""
        reasoning = []
        allocations = exec_result['space_allocations']
        
        # Recursion adds stack space
        if exec_result['recursive_calls'] > 0:
            if uses_memo:
                reasoning.append("Recursion with memoization → O(n) for cache")
                return "O(n)", reasoning
            else:
                reasoning.append("Recursion → O(n) call stack")
                return "O(n)", reasoning
        
        if not allocations:
            reasoning.append("No significant allocations → O(1)")
            return "O(1)", reasoning
        
        # Find worst case allocation
        max_space = "O(1)"
        for alloc_type, space in allocations:
            if 'n^' in space:
                if max_space == "O(1)" or 'n^' not in max_space:
                    max_space = space
                    reasoning.append(f"{alloc_type} creates {space} space")
            elif space == "O(n)" and max_space == "O(1)":
                max_space = space
                reasoning.append(f"{alloc_type} creates O(n) space")
        
        if max_space == "O(1)":
            reasoning.append("Only constant space allocations → O(1)")
        
        return max_space, reasoning
    
    def _get_dominant_operation(self, exec_result: Dict) -> Optional[str]:
        """Identify the dominant operation affecting complexity."""
        if exec_result['recursive_calls'] > 0:
            return f"recursion ({exec_result['recursive_pattern']})"
        if exec_result['max_loop_depth'] > 0:
            return f"nested loops (depth {exec_result['max_loop_depth']})"
        if exec_result['expensive_ops']:
            return exec_result['expensive_ops'][0][0]
        return None


class ProjectComplexityAnalyzer:
    """Analyzes complexity across an entire project."""
    
    SKIP_DIRS = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', 
                 '.pytest_cache', 'dist', 'build', '.tox', '.eggs'}
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.results: List[FunctionComplexity] = []
        self.analyzer = AdvancedComplexityAnalyzer()
    
    def analyze(self) -> List[FunctionComplexity]:
        """Analyze all Python files in project."""
        import os
        
        for py_file in self._get_python_files():
            try:
                content = py_file.read_text(encoding='utf-8')
                tree = ast.parse(content)
                
                # Collect all function names first
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.analyzer.all_functions.add(node.name)
                
                # Analyze each function
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        result = self.analyzer.analyze_function(node, py_file)
                        result.file = str(py_file.relative_to(self.project_path))
                        self.results.append(result)
                        
            except (SyntaxError, UnicodeDecodeError):
                continue
        
        return self.results
    
    def _get_python_files(self) -> List[Path]:
        """Get all Python files."""
        import os
        files = []
        for root, dirs, filenames in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for f in filenames:
                if f.endswith('.py'):
                    files.append(Path(root) / f)
        return files
    
    def get_summary(self) -> Dict:
        """Get complexity summary statistics."""
        if not self.results:
            return {"total_functions": 0}
        
        time_counts: Dict[str, int] = {}
        space_counts: Dict[str, int] = {}
        high_complexity = []
        avg_confidence = 0.0
        
        for r in self.results:
            time_counts[r.time_complexity] = time_counts.get(r.time_complexity, 0) + 1
            space_counts[r.space_complexity] = space_counts.get(r.space_complexity, 0) + 1
            avg_confidence += r.confidence
            
            # Flag high complexity functions
            if any(x in r.time_complexity for x in ['n²', 'n³', 'n^', '2^n', 'k^n']):
                high_complexity.append(r)
        
        avg_confidence /= len(self.results)
        
        return {
            "total_functions": len(self.results),
            "average_confidence": round(avg_confidence, 2),
            "time_complexity_distribution": dict(sorted(time_counts.items())),
            "space_complexity_distribution": dict(sorted(space_counts.items())),
            "high_complexity_count": len(high_complexity),
            "high_complexity_functions": [
                {
                    "name": r.name,
                    "file": r.file,
                    "line": r.line,
                    "time": r.time_complexity,
                    "space": r.space_complexity,
                    "confidence": r.confidence,
                    "dominant_op": r.dominant_operation,
                    "reasoning": r.reasoning[:3]  # Top 3 reasons
                }
                for r in high_complexity
            ]
        }
