"""Tool call validator — checks tool definitions for safety and completeness."""

import ast
from typing import Dict, List, Any


class ToolValidator:
    """Validates agent tool/function definitions for common issues."""

    name = "tool_validator"

    # Patterns that suggest tool/function definitions for agents
    TOOL_DECORATORS = {"tool", "function_tool", "register_tool", "agent_tool"}
    TOOL_PARAM_PATTERNS = {"name", "description", "parameters", "func", "function"}
    DANGEROUS_FUNCTIONS = {"eval", "exec", "compile", "__import__", "open", "os.system", "subprocess"}
    DANGEROUS_PARAM_NAMES = {"command", "cmd", "code", "script", "shell", "sql", "query"}

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

        self._check_tool_definitions(tree, findings, source)
        self._check_dangerous_calls(tree, findings, source)
        self._check_missing_return_types(tree, findings, source)

        findings.sort(key=lambda f: f["line"])
        return findings

    def _get_line(self, source: str, lineno: int) -> str:
        try:
            lines = source.splitlines()
            if 0 <= lineno - 1 < len(lines):
                return lines[lineno - 1].strip()
        except Exception:
            pass
        return ""

    def _check_tool_definitions(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check functions decorated as tools for missing descriptions/error handling."""

        class ToolDefVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                # Check if this function is decorated as a tool
                is_tool = False
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id in ToolValidator.TOOL_DECORATORS:
                        is_tool = True
                    elif isinstance(decorator, ast.Call):
                        if isinstance(decorator.func, ast.Name) and decorator.func.id in ToolValidator.TOOL_DECORATORS:
                            is_tool = True

                if not is_tool:
                    # Also check if function name suggests it's a tool
                    if node.name.startswith("tool_") or node.name.endswith("_tool"):
                        is_tool = True

                if is_tool:
                    # Check for docstring (description)
                    docstring = ast.get_docstring(node)
                    if not docstring:
                        findings.append({
                            "analyzer": "tool_validator",
                            "severity": "medium",
                            "title": f"Tool '{node.name}' is missing a description (docstring)",
                            "description": (
                                f"Tool function '{node.name}' has no docstring. AI agents rely on tool "
                                "descriptions to decide when and how to use them. Without a description, "
                                "the agent may misuse this tool or ignore it entirely."
                            ),
                            "line": node.lineno,
                            "code_snippet": ToolValidator._get_line_static(source, node.lineno),
                            "recommendation": (
                                f"Add a docstring describing what '{node.name}' does, its parameters, "
                                "and when to use it."
                            ),
                        })
                    elif len(docstring) < 20:
                        findings.append({
                            "analyzer": "tool_validator",
                            "severity": "low",
                            "title": f"Tool '{node.name}' has a very short description",
                            "description": (
                                f"The docstring for '{node.name}' is only {len(docstring)} characters. "
                                "LLMs need detailed descriptions to use tools correctly."
                            ),
                            "line": node.lineno,
                            "code_snippet": ToolValidator._get_line_static(source, node.lineno),
                            "recommendation": "Expand the docstring with parameter descriptions and usage examples.",
                        })

                    # Check for unsafe parameter names
                    for arg in node.args.args:
                        if arg.arg in ToolValidator.DANGEROUS_PARAM_NAMES:
                            findings.append({
                                "analyzer": "tool_validator",
                                "severity": "high",
                                "title": f"Tool '{node.name}' has potentially unsafe parameter '{arg.arg}'",
                                "description": (
                                    f"Parameter '{arg.arg}' in tool '{node.name}' may accept dangerous input "
                                    "(commands, code, SQL). Parameter names don't guarantee danger, but this "
                                    "deserves review."
                                ),
                                "line": node.lineno,
                                "code_snippet": ToolValidator._get_line_static(source, node.lineno),
                                "recommendation": (
                                    "Validate/sanitize this parameter. Consider allowlisting permitted values "
                                    "or using parameterized interfaces."
                                ),
                            })

                    # Check for missing error handling
                    has_try = any(isinstance(child, ast.Try) for child in ast.walk(node))
                    has_return_none = False
                    for child in ast.walk(node):
                        if isinstance(child, ast.Return) and (
                            child.value is None
                            or (isinstance(child.value, ast.Constant) and child.value.value is None)
                        ):
                            has_return_none = True

                    if not has_try:
                        findings.append({
                            "analyzer": "tool_validator",
                            "severity": "medium",
                            "title": f"Tool '{node.name}' has no error handling",
                            "description": (
                                f"Tool '{node.name}' has no try/except block. Tool execution failures "
                                "without error returns will propagate to the agent as unhandled exceptions."
                            ),
                            "line": node.lineno,
                            "code_snippet": ToolValidator._get_line_static(source, node.lineno),
                            "recommendation": (
                                "Wrap tool logic in try/except and return error information instead of raising."
                            ),
                        })

                    if not has_return_none and not has_try:
                        findings.append({
                            "analyzer": "tool_validator",
                            "severity": "low",
                            "title": f"Tool '{node.name}' may not return error states",
                            "description": (
                                "No explicit 'return None' or error-return pattern found. Tools should "
                                "return structured error information on failure so the agent can recover."
                            ),
                            "line": node.lineno,
                            "code_snippet": ToolValidator._get_line_static(source, node.lineno),
                            "recommendation": "Return a dict with 'error' or 'success' keys for structured error handling.",
                        })

                self.generic_visit(node)

        @staticmethod
        def _get_line_static(source: str, lineno: int) -> str:
            try:
                lines = source.splitlines()
                if 0 <= lineno - 1 < len(lines):
                    return lines[lineno - 1].strip()
            except Exception:
                pass
            return ""

        ToolDefVisitor().visit(tree)

    def _check_dangerous_calls(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for dangerous function calls in tool definitions."""

        class DangerousCallVisitor(ast.NodeVisitor):
            def __init__(self):
                self.inside_tool = False

            def visit_FunctionDef(self, node: ast.FunctionDef):
                # Determine if this is a tool function
                was_tool = self.inside_tool
                is_tool = False
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id in ToolValidator.TOOL_DECORATORS:
                        is_tool = True
                    elif isinstance(decorator, ast.Call):
                        if isinstance(decorator.func, ast.Name) and decorator.func.id in ToolValidator.TOOL_DECORATORS:
                            is_tool = True
                if node.name.startswith("tool_") or node.name.endswith("_tool"):
                    is_tool = True

                self.inside_tool = is_tool
                self.generic_visit(node)
                self.inside_tool = was_tool

            def visit_Call(self, node: ast.Call):
                if self.inside_tool:
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr

                    if func_name in ToolValidator.DANGEROUS_FUNCTIONS:
                        findings.append({
                            "analyzer": "tool_validator",
                            "severity": "critical",
                            "title": f"Dangerous function '{func_name}' called inside a tool",
                            "description": (
                                f"Function '{func_name}' is called inside a tool definition. "
                                "This is a critical security risk — it could allow arbitrary code execution "
                                "if the tool's inputs are influenced by LLM output or user data."
                            ),
                            "line": node.lineno,
                            "code_snippet": ToolValidator._get_line_static(source, node.lineno),
                            "recommendation": (
                                f"Remove or heavily sandbox the call to '{func_name}'. "
                                "Use safer alternatives or strict input validation."
                            ),
                        })
                self.generic_visit(node)

        DangerousCallVisitor().visit(tree)

    def _check_missing_return_types(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for tool functions without return type annotations."""

        class ReturnTypeVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                is_tool = False
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id in ToolValidator.TOOL_DECORATORS:
                        is_tool = True
                    elif isinstance(decorator, ast.Call):
                        if isinstance(decorator.func, ast.Name) and decorator.func.id in ToolValidator.TOOL_DECORATORS:
                            is_tool = True

                if is_tool and node.returns is None:
                    findings.append({
                        "analyzer": "tool_validator",
                        "severity": "low",
                        "title": f"Tool '{node.name}' is missing a return type annotation",
                        "description": (
                            "Tool functions should have explicit return type annotations so the agent "
                            "framework knows what to expect."
                        ),
                        "line": node.lineno,
                        "code_snippet": ToolValidator._get_line_static(source, node.lineno),
                        "recommendation": "Add a return type annotation (e.g., '-> dict' or '-> str').",
                    })
                self.generic_visit(node)

    @staticmethod
    def _get_line_static(source: str, lineno: int) -> str:
        try:
            lines = source.splitlines()
            if 0 <= lineno - 1 < len(lines):
                return lines[lineno - 1].strip()
        except:
            pass
        return ""

        ReturnTypeVisitor().visit(tree)
