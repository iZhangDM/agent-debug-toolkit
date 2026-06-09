"""Memory leak detector — finds agents that accumulate state without cleanup."""

import ast
from typing import Dict, List, Any


class MemoryLeakDetector:
    """Detects patterns that cause memory leaks in agent code."""

    name = "memory_detector"

    # Collections that grow without bound
    GROWING_COLLECTIONS = {
        "append": "list",
        "extend": "list",
        "add": "set",
        "update": "set/dict",
    }

    # Variable names that suggest accumulated state
    ACCUMULATOR_NAMES = {
        "history", "conversation_history", "messages", "memory", "context",
        "chat_history", "message_history", "buffer", "cache", "log",
        "results", "outputs", "responses", "turns", "call_log",
        "tool_history", "intermediate_steps", "scratchpad",
    }

    def analyze(self, source: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            findings.append({
                "analyzer": self.name,
                "severity": "critical",
                "title": "Syntax error prevents analysis",
                "description": str(e),
                "line": e.lineno or 0,
                "code_snippet": "",
                "recommendation": "Fix syntax errors before running analysis.",
            })
            return findings

        self._check_unbounded_collections(tree, findings, source)
        self._check_missing_cleanup(tree, findings, source)
        self._check_large_global_state(tree, findings, source)
        self._check_circular_references(tree, findings, source)

        findings.sort(key=lambda f: f["line"])
        return findings

    def _check_unbounded_collections(self, tree: ast.AST, findings: list, source: str) -> None:
        """Detect collections that grow without bound inside loops."""

        class UnboundedCollector(ast.NodeVisitor):
            def __init__(self):
                self.loop_depth = 0
                self.accumulators_inside_loops: dict[str, set[str]] = {}
                self.truncations_inside_loops: dict[str, bool] = {}
                self.accumulator_lines: dict[str, int] = {}

            def visit_While(self, node: ast.While):
                self.loop_depth += 1
                self.generic_visit(node)
                self.loop_depth -= 1

            def visit_For(self, node: ast.For):
                self.loop_depth += 1
                self.generic_visit(node)
                self.loop_depth -= 1

            def visit_Call(self, node: ast.Call):
                if self.loop_depth > 0:
                    # Check for .append(), .extend(), .add()
                    if isinstance(node.func, ast.Attribute):
                        method = node.func.attr
                        if method in MemoryLeakDetector.GROWING_COLLECTIONS:
                            # Get the variable name
                            var_name = self._get_var_name(node.func.value)
                            if var_name and var_name in MemoryLeakDetector.ACCUMULATOR_NAMES:
                                loop_id = f"loop_{node.lineno}"
                                self.accumulators_inside_loops.setdefault(loop_id, set()).add(var_name)
                                self.accumulator_lines[var_name] = node.lineno
                self.generic_visit(node)

            def visit_Assign(self, node: ast.Assign):
                if self.loop_depth > 0:
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id in MemoryLeakDetector.ACCUMULATOR_NAMES:
                            # Check if it's being reassigned (reset) or extended
                            if isinstance(node.value, ast.Call):
                                if isinstance(node.value.func, ast.Name) and node.value.func.id == "len":
                                    pass  # Just checking length, ignore
                self.generic_visit(node)

            def _get_var_name(self, node: ast.AST) -> str | None:
                if isinstance(node, ast.Name):
                    return node.id
                if isinstance(node, ast.Attribute):
                    return node.attr
                if isinstance(node, ast.Subscript):
                    return self._get_var_name(node.value)
                return None

        visitor = UnboundedCollector()
        visitor.visit(tree)

        # Check for truncation in the same loops
        class TruncationChecker(ast.NodeVisitor):
            def __init__(self, accumulators: dict, acc_lines: dict):
                self.accumulators = accumulators
                self.acc_lines = acc_lines
                self.loop_depth = 0

            def visit_While(self, node: ast.While):
                self.loop_depth += 1
                self.generic_visit(node)
                self.loop_depth -= 1

            def visit_For(self, node: ast.For):
                self.loop_depth += 1
                self.generic_visit(node)
                self.loop_depth -= 1

            def visit_Assign(self, node: ast.Assign):
                if self.loop_depth > 0:
                    for target in node.targets:
                        var_name = None
                        if isinstance(target, ast.Name):
                            var_name = target.id
                        elif isinstance(target, ast.Subscript):
                            if isinstance(target.slice, ast.Slice):
                                var_name = self._get_base_name(target.value)

                        if var_name and var_name in MemoryLeakDetector.ACCUMULATOR_NAMES:
                            # Check if assignment is a truncation
                            if isinstance(node.value, ast.Subscript):
                                pass  # Slicing
                            elif isinstance(node.value, ast.Call):
                                if isinstance(node.value.func, ast.Attribute):
                                    if node.value.func.attr in ("clear", "reset", "truncate"):
                                        loop_id = f"loop_{node.lineno}"
                                        if loop_id in visitor.accumulators:
                                            pass  # Has cleanup
                self.generic_visit(node)

            def _get_base_name(self, node: ast.AST) -> str | None:
                if isinstance(node, ast.Name):
                    return node.id
                if isinstance(node, ast.Attribute):
                    return node.attr
                return None

        # Report findings for accumulators that never get cleaned
        for loop_id, acc_names in visitor.accumulators_inside_loops.items():
            for acc_name in acc_names:
                findings.append({
                    "analyzer": "memory_detector",
                    "severity": "high",
                    "title": f"Unbounded growth: '{acc_name}' accumulates inside a loop",
                    "description": (
                        f"The collection '{acc_name}' grows via .append()/add() inside a loop "
                        "with no visible size limit or cleanup. In long-running agents, this will "
                        "eventually exhaust memory and crash the process."
                    ),
                    "line": visitor.accumulator_lines.get(acc_name, 0),
                    "code_snippet": self._get_line(source, visitor.accumulator_lines.get(acc_name, 0)),
                    "recommendation": (
                        f"Add a maximum size limit: 'if len({acc_name}) > MAX: {acc_name}.pop(0)'. "
                        "Or truncate to last N items after each iteration. Consider using "
                        "collections.deque with maxlen for automatic truncation."
                    ),
                })

    def _check_missing_cleanup(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for classes with __init__ that accumulate state but no cleanup."""

        class CleanupVisitor(ast.NodeVisitor):
            def visit_ClassDef(self, node: ast.ClassDef):
                has_init = False
                has_cleanup = False
                has_accumulators = False

                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        if item.name == "__init__":
                            has_init = True
                            # Check if init creates accumulator attributes
                            for stmt in ast.walk(item):
                                if isinstance(stmt, ast.Assign):
                                    for target in stmt.targets:
                                        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                                            if target.value.id == "self" and target.attr in MemoryLeakDetector.ACCUMULATOR_NAMES:
                                                has_accumulators = True
                        if item.name in ("cleanup", "clear", "reset", "close", "__del__", "shutdown", "teardown"):
                            has_cleanup = True

                if has_init and has_accumulators and not has_cleanup:
                    findings.append({
                        "analyzer": "memory_detector",
                        "severity": "medium",
                        "title": f"Class '{node.name}' accumulates state without cleanup method",
                        "description": (
                            f"'{node.name}' creates accumulator attributes in __init__ but has no "
                            "cleanup/clear/reset method. Long-lived agent instances will retain "
                            "stale data and grow memory usage over time."
                        ),
                        "line": node.lineno,
                        "code_snippet": self._get_line(source, node.lineno),
                        "recommendation": (
                            "Add a 'clear_history()' or 'reset()' method that empties accumulated "
                            "collections. Call it periodically or between sessions."
                        ),
                    })
                self.generic_visit(node)

        CleanupVisitor().visit(tree)

    def _check_large_global_state(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for module-level accumulator variables."""

        class GlobalStateVisitor(ast.NodeVisitor):
            def visit_Assign(self, node: ast.Assign):
                # Module-level assignments
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in MemoryLeakDetector.ACCUMULATOR_NAMES:
                        # Only flag if assigned a mutable collection
                        is_mutable = False
                        if isinstance(node.value, ast.List) or isinstance(node.value, ast.Dict):
                            is_mutable = True
                        elif isinstance(node.value, ast.Call):
                            if isinstance(node.value.func, ast.Name):
                                if node.value.func.id in ("list", "dict", "set", "deque", "defaultdict"):
                                    is_mutable = True

                        if is_mutable:
                            findings.append({
                                "analyzer": "memory_detector",
                                "severity": "medium",
                                "title": f"Module-level mutable state: '{target.id}'",
                                "description": (
                                    f"'{target.id}' is a mutable collection at module level. "
                                    "Module-level state persists for the lifetime of the process "
                                    "and grows unboundedly unless explicitly cleared."
                                ),
                                "line": node.lineno,
                                "code_snippet": self._get_line(source, node.lineno),
                                "recommendation": (
                                    "Move mutable state into class instances or function scopes. "
                                    "If module-level state is needed, expose a clear function "
                                    "and consider max size limits."
                                ),
                            })
                self.generic_visit(node)

        GlobalStateVisitor().visit(tree)

    def _check_circular_references(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for self-referential data structures that prevent GC."""

        class CircularRefVisitor(ast.NodeVisitor):
            def visit_Assign(self, node: ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                        if target.value.id == "self":
                            # Check if assigning self or another object that references self
                            if isinstance(node.value, ast.Name) and node.value.id == "self":
                                findings.append({
                                    "analyzer": "memory_detector",
                                    "severity": "low",
                                    "title": "Self-referential assignment may create circular reference",
                                    "description": (
                                        f"Assigning 'self' to 'self.{target.attr}' creates a circular "
                                        "reference. While Python's GC handles most circular refs, "
                                        "this pattern in long-running agents can delay cleanup."
                                    ),
                                    "line": node.lineno,
                                    "code_snippet": self._get_line(source, node.lineno),
                                    "recommendation": (
                                        "Use weakref.ref() if you need a self-reference. "
                                        "Ensure __del__ or cleanup breaks the cycle."
                                    ),
                                })
                self.generic_visit(node)

        CircularRefVisitor().visit(tree)

    @staticmethod
    def _get_line(source: str, lineno: int) -> str:
        try:
            lines = source.splitlines()
            if 0 <= lineno - 1 < len(lines):
                return lines[lineno - 1].strip()
        except:
            pass
        return ""
