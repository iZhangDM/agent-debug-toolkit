"""Agent loop analyzer — detects infinite loops, missing termination, missing error handling."""

import ast
from typing import Dict, List, Any


class LoopAnalyzer:
    """Analyzes agent execution loops for common bugs."""

    name = "loop_analyzer"

    # Patterns that indicate agent loops
    LOOP_VAR_NAMES = {"running", "active", "alive", "continue_loop", "should_run", "is_running"}
    MAX_ITERATIONS_KEYWORDS = {"max_iterations", "max_steps", "max_turns", "iteration_limit", "step_limit"}

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

        self._check_while_loops(tree, findings, source)
        self._check_recursive_calls(tree, findings, source)
        self._check_try_except(tree, findings, source)
        self._check_iteration_limits(tree, findings, source)

        findings.sort(key=lambda f: f["line"])
        return findings

    def _get_line(self, node: ast.AST, source: str) -> str:
        """Get the source line for a node."""
        try:
            lines = source.splitlines()
            lineno = getattr(node, "lineno", 1) - 1
            if 0 <= lineno < len(lines):
                return lines[lineno].strip()
        except Exception:
            pass
        return ""

    def _check_while_loops(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for while loops without proper termination."""

        class WhileVisitor(ast.NodeVisitor):
            def visit_While(self, node: ast.While):
                line = node.lineno
                code = source.splitlines()[line - 1].strip() if line - 1 < len(source.splitlines()) else ""

                # Check: while True without break
                is_while_true = isinstance(node.test, ast.Constant) and node.test.value is True
                has_break = self._has_break(node)
                has_return = self._has_return(node)
                has_exception = self._has_raise(node)

                if is_while_true and not has_break and not has_return and not has_exception:
                    findings.append({
                        "analyzer": "loop_analyzer",
                        "severity": "critical",
                        "title": "Infinite loop: 'while True' with no break, return, or raise",
                        "description": (
                            "This 'while True' loop has no visible exit path. It will run forever "
                            "unless an unhandled exception occurs. Add a break condition or max iteration guard."
                        ),
                        "line": line,
                        "code_snippet": code,
                        "recommendation": (
                            "Add an explicit break condition, a return statement, or a max_iterations counter "
                            "with a StopIteration or custom exception."
                        ),
                    })

                # Check: while variable without mutation evidence
                if isinstance(node.test, ast.Name):
                    var_name = node.test.id
                    if var_name in self.LOOP_VAR_NAMES and not self._var_mutated_in_body(node, var_name):
                        findings.append({
                            "analyzer": "loop_analyzer",
                            "severity": "high",
                            "title": f"Loop condition variable '{var_name}' may never change",
                            "description": (
                                f"The loop condition checks '{var_name}' but no assignment to it "
                                "was found in the loop body. The loop may run forever."
                            ),
                            "line": line,
                            "code_snippet": code,
                            "recommendation": (
                                f"Ensure '{var_name}' is updated inside the loop body, or add a break condition."
                            ),
                        })

                # Check: no max iterations guard
                if not self._has_max_iterations_guard(node) and len(list(ast.walk(node))) > 5:
                    findings.append({
                        "analyzer": "loop_analyzer",
                        "severity": "medium",
                        "title": "Missing max iterations guard",
                        "description": (
                            "This loop has significant complexity but no max_iterations safety limit. "
                            "Agent loops should always have a maximum step count as a safety net."
                        ),
                        "line": line,
                        "code_snippet": code,
                        "recommendation": (
                            "Add a counter like 'for i in range(max_iterations):' or check 'if steps > max_steps: break'."
                        ),
                    })

                self.generic_visit(node)

            def _has_break(self, node: ast.AST) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Break):
                        return True
                return False

            def _has_return(self, node: ast.AST) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        return True
                return False

            def _has_raise(self, node: ast.AST) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Raise):
                        return True
                return False

            def _var_mutated_in_body(self, node: ast.While, var_name: str) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name) and target.id == var_name:
                                return True
                    if isinstance(child, ast.AugAssign):
                        if isinstance(child.target, ast.Name) and child.target.id == var_name:
                            return True
                return False

            def _has_max_iterations_guard(self, node: ast.While) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id in LoopAnalyzer.MAX_ITERATIONS_KEYWORDS:
                        return True
                    if isinstance(child, ast.Attribute) and child.attr in LoopAnalyzer.MAX_ITERATIONS_KEYWORDS:
                        return True
                return False

        WhileVisitor().visit(tree)

    def _check_recursive_calls(self, tree: ast.AST, findings: list, source: str) -> None:
        """Detect recursive functions without base cases."""

        class RecursionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.current_func: str | None = None
                self.func_calls: dict[str, set[str]] = {}

            def visit_FunctionDef(self, node: ast.FunctionDef):
                prev = self.current_func
                self.current_func = node.name
                self.func_calls.setdefault(node.name, set())
                self.generic_visit(node)
                self.current_func = prev

            def visit_Call(self, node: ast.Call):
                if self.current_func and isinstance(node.func, ast.Name):
                    if node.func.id == self.current_func:
                        self.func_calls[self.current_func].add("self")
                self.generic_visit(node)

        visitor = RecursionVisitor()
        visitor.visit(tree)

        for func_name, calls in visitor.func_calls.items():
            if "self" in calls:
                # Find the function node to check for base case
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name == func_name:
                        if not self._has_early_return(node):
                            findings.append({
                                "analyzer": "loop_analyzer",
                                "severity": "high",
                                "title": f"Recursive function '{func_name}' may lack a base case",
                                "description": (
                                    f"Function '{func_name}' calls itself but no early return (base case) "
                                    "was detected. This could cause infinite recursion."
                                ),
                                "line": node.lineno,
                                "code_snippet": self._get_line(node, source),
                                "recommendation": (
                                    "Add a base case with an early return at the beginning of the function, "
                                    "e.g., 'if n <= 0: return'."
                                ),
                            })

    def _has_early_return(self, node: ast.FunctionDef) -> bool:
        """Check if a function has an early return (base case)."""
        body = node.body
        if len(body) < 2:
            return False
        first_stmt = body[0]
        if isinstance(first_stmt, ast.If):
            for child in ast.walk(first_stmt):
                if isinstance(child, ast.Return):
                    return True
        return False

    def _check_try_except(self, tree: ast.AST, findings: list, source: str) -> None:
        """Detect agent run functions without try/except error handling."""

        class TryExceptVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                # Look for agent-style run/execute/start functions
                is_agent_func = any(
                    keyword in node.name.lower()
                    for keyword in ("run", "execute", "start", "main", "loop", "agent")
                )
                if is_agent_func:
                    has_try = any(isinstance(child, ast.Try) for child in ast.walk(node))
                    if not has_try:
                        findings.append({
                            "analyzer": "loop_analyzer",
                            "severity": "medium",
                            "title": f"Agent function '{node.name}' lacks error handling",
                            "description": (
                                f"Function '{node.name}' appears to be an agent entry point but has no "
                                "try/except block. Unhandled exceptions will crash the agent."
                            ),
                            "line": node.lineno,
                            "code_snippet": source.splitlines()[node.lineno - 1].strip()
                                if node.lineno - 1 < len(source.splitlines()) else "",
                            "recommendation": (
                                "Wrap the main execution logic in try/except to catch and log errors gracefully."
                            ),
                        })
                self.generic_visit(node)

        TryExceptVisitor().visit(tree)

    def _check_iteration_limits(self, tree: ast.AST, findings: list, source: str) -> None:
        """Warn about hardcoded low iteration limits."""

        class LimitVisitor(ast.NodeVisitor):
            def visit_Assign(self, node: ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in LoopAnalyzer.MAX_ITERATIONS_KEYWORDS:
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
                            val = node.value.value
                            if val > 10000:
                                findings.append({
                                    "analyzer": "loop_analyzer",
                                    "severity": "low",
                                    "title": f"Max iterations limit ({target.id}={val}) is very high",
                                    "description": (
                                        f"The max iterations guard is set to {val}. This is high enough "
                                        "that a runaway loop could still consume significant resources "
                                        "before hitting the limit."
                                    ),
                                    "line": node.lineno,
                                    "code_snippet": self._get_line(node, source, source.splitlines()),
                                    "recommendation": (
                                        "Consider a lower limit (100-1000) for faster failure on infinite loops."
                                    ),
                                })
                self.generic_visit(node)

            def _get_line(self, node, source, lines):
                try:
                    return lines[node.lineno - 1].strip()
                except Exception:
                    return ""

        LimitVisitor().visit(tree)
