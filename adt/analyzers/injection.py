"""Prompt injection scanner — finds common prompt injection vulnerabilities in agent code."""

import ast
import re
from typing import Dict, List, Any


class InjectionScanner:
    """Scans agent code for prompt injection vulnerabilities."""

    name = "injection_scanner"

    # Patterns that indicate user input flows into prompts
    PROMPT_VARS = {"prompt", "system_prompt", "user_prompt", "instruction", "messages", "context"}
    USER_INPUT_VARS = {"user_input", "user_message", "query", "input_text", "user_query", "message"}
    FORMAT_METHODS = {"format", "replace", "f-string", "join"}

    # Dangerous patterns in prompt construction
    DANGEROUS_PATTERNS = [
        (r"f[\"'].*\{.*user.*\}.*[\"']", "f-string with user input directly in prompt"),
        (r"\.format\(.*user", ".format() with user input in prompt"),
        (r"prompt\s*\+.*user", "String concatenation with user input in prompt"),
        (r"system_prompt\s*\+.*input", "String concatenation with input in system prompt"),
        (r"prompt\.replace\(.*user", ".replace() with user input in prompt"),
        (r"messages\.append\(.*user", "User message appended without sanitization"),
    ]

    # Delimiter patterns that could be exploited
    DELIMITER_PATTERNS = [
        "---",
        "```",
        "'''",
        "===",
        "<|",
        "|>",
        "[INST]",
        "[/INST]",
        "<system>",
        "</system>",
        "<user>",
        "</user>",
    ]

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

        self._check_unsanitized_user_input(tree, findings, source)
        self._check_missing_delimiters(tree, findings, source)
        self._check_json_yaml_injection(tree, findings, source)
        self._check_regex_patterns(source, findings)

        findings.sort(key=lambda f: f["line"])
        return findings

    def _check_unsanitized_user_input(self, tree: ast.AST, findings: list, source: str) -> None:
        """Detect user input flowing into prompts without sanitization."""

        class PromptInjectionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.prompt_assignments: dict[str, int] = {}
                self.user_input_assignments: dict[str, int] = {}

            def visit_Assign(self, node: ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id in InjectionScanner.PROMPT_VARS:
                            self.prompt_assignments[target.id] = node.lineno
                        if target.id in InjectionScanner.USER_INPUT_VARS:
                            self.user_input_assignments[target.id] = node.lineno
                self.generic_visit(node)

            def visit_BinOp(self, node: ast.BinOp):
                if isinstance(node.op, ast.Add):
                    left_is_prompt = self._is_prompt_var(node.left)
                    right_is_user = self._is_user_input_var(node.right)
                    if (left_is_prompt and right_is_user) or (right_is_user and left_is_prompt):
                        findings.append({
                            "analyzer": "injection_scanner",
                            "severity": "critical",
                            "title": "Prompt injection risk: user input concatenated into prompt",
                            "description": (
                                "User input is being concatenated directly into a prompt string. "
                                "This allows prompt injection attacks where users can override "
                                "system instructions or exfiltrate data."
                            ),
                            "line": node.lineno,
                            "code_snippet": self._get_line(source, node.lineno),
                            "recommendation": (
                                "Use structured message formats (role/content dicts). "
                                "Wrap user input in XML tags, use separate user/system roles, "
                                "or add input sanitization (strip delimiters, escape special chars)."
                            ),
                        })
                self.generic_visit(node)

            def visit_JoinedStr(self, node: ast.JoinedStr):
                has_prompt = False
                has_user_input = False
                for value in node.values:
                    if isinstance(value, ast.FormattedValue):
                        if self._is_user_input_var(value):
                            has_user_input = True
                    elif isinstance(value, ast.Constant):
                        if any(kw in str(value.value).lower() for kw in ["prompt", "system", "instruction"]):
                            has_prompt = True

                if has_user_input and has_prompt:
                    findings.append({
                        "analyzer": "injection_scanner",
                        "severity": "critical",
                        "title": "Prompt injection risk: user input in f-string prompt",
                        "description": (
                            "User input is embedded in an f-string that appears to be a prompt. "
                            "This is a direct prompt injection vector."
                        ),
                        "line": node.lineno,
                        "code_snippet": self._get_line(source, node.lineno),
                        "recommendation": (
                            "Use structured messages with role separation. If you must use f-strings, "
                            "wrap user content in clear boundary markers like <user_query>...</user_query>."
                        ),
                    })
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call):
                # Check .format() calls
                if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id in InjectionScanner.PROMPT_VARS:
                            findings.append({
                                "analyzer": "injection_scanner",
                                "severity": "high",
                                "title": "Prompt injection risk: .format() on prompt string",
                                "description": (
                                    f"'.format()' is called on '{node.func.value.id}' which appears to be "
                                    "a prompt. User-controlled format arguments can inject prompt content."
                                ),
                                "line": node.lineno,
                                "code_snippet": self._get_line(source, node.lineno),
                                "recommendation": (
                                    "Avoid .format() on prompts. Use structured message construction instead."
                                ),
                            })
                self.generic_visit(node)

            def _is_prompt_var(self, node: ast.AST) -> bool:
                if isinstance(node, ast.Name):
                    return node.id in InjectionScanner.PROMPT_VARS
                if isinstance(node, ast.Attribute):
                    return node.attr in InjectionScanner.PROMPT_VARS
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    return any(kw in node.value.lower() for kw in ["system:", "instruction:", "you are"])
                return False

            def _is_user_input_var(self, node: ast.AST) -> bool:
                if isinstance(node, ast.Name):
                    return node.id in InjectionScanner.USER_INPUT_VARS
                if isinstance(node, ast.FormattedValue):
                    return self._is_user_input_var(node.value)
                if isinstance(node, ast.Attribute):
                    return node.attr in InjectionScanner.USER_INPUT_VARS
                return False

            @staticmethod
            def _get_line(source: str, lineno: int) -> str:
                try:
                    lines = source.splitlines()
                    if 0 <= lineno - 1 < len(lines):
                        return lines[lineno - 1].strip()
                except:
                    pass
                return ""

        PromptInjectionVisitor().visit(tree)

    def _check_missing_delimiters(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for prompt construction without delimiters around user content."""

        class DelimiterVisitor(ast.NodeVisitor):
            def __init__(self):
                self.lines_with_user_input: set[int] = set()
                self.lines_with_delimiters: set[int] = set()

            def visit_BinOp(self, node: ast.BinOp):
                if isinstance(node.op, ast.Add):
                    has_user = self._contains_user_input(node)
                    has_delim = self._contains_delimiter(node)
                    if has_user and not has_delim:
                        findings.append({
                            "analyzer": "injection_scanner",
                            "severity": "medium",
                            "title": "User input in prompt without delimiter protection",
                            "description": (
                                "User input is added to a prompt without wrapping it in delimiter markers. "
                                "Without clear boundaries (like <user_query>...</user_query>), the LLM cannot "
                                "distinguish user content from instructions."
                            ),
                            "line": node.lineno,
                            "code_snippet": self._get_line(source, node.lineno),
                            "recommendation": (
                                "Wrap user content in unambiguous delimiters: "
                                "e.g., f'<user_query>\\n{user_input}\\n</user_query>'."
                            ),
                        })
                self.generic_visit(node)

            def _contains_user_input(self, node: ast.AST) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id in InjectionScanner.USER_INPUT_VARS:
                        return True
                    if isinstance(child, ast.Attribute) and child.attr in InjectionScanner.USER_INPUT_VARS:
                        return True
                return False

            def _contains_delimiter(self, node: ast.AST) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        for delim in InjectionScanner.DELIMITER_PATTERNS:
                            if delim in child.value:
                                return True
                return False

            @staticmethod
            def _get_line(source: str, lineno: int) -> str:
                try:
                    lines = source.splitlines()
                    if 0 <= lineno - 1 < len(lines):
                        return lines[lineno - 1].strip()
                except:
                    pass
                return ""

        DelimiterVisitor().visit(tree)

    def _check_json_yaml_injection(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for JSON/YAML parsing of LLM output without validation."""

        class JSONVisitor(ast.NodeVisitor):
            def visit_Call(self, node: ast.Call):
                func_name = None
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in ("json.loads", "yaml.load", "yaml.safe_load", "eval", "literal_eval"):
                    # Check if the argument comes from an LLM response
                    for arg in node.args:
                        if self._is_llm_output(arg):
                            severity = "critical" if func_name in ("eval", "yaml.load") else "medium"
                            findings.append({
                                "analyzer": "injection_scanner",
                                "severity": severity,
                                "title": f"Potential injection: {func_name} on LLM output",
                                "description": (
                                    f"'{func_name}' is called on what appears to be LLM output. "
                                    "Malicious users can craft inputs that cause the LLM to output "
                                    "injected JSON/YAML that executes dangerous operations."
                                ),
                                "line": node.lineno,
                                "code_snippet": self._get_line(source, node.lineno),
                                "recommendation": (
                                    "Validate parsed output against a strict schema before using it. "
                                    "Use json.loads with a schema validator. Never use eval() on LLM output."
                                ),
                            })

            def _is_llm_output(self, node: ast.AST) -> bool:
                llm_vars = {"response", "output", "result", "completion", "llm_response", "agent_output"}
                if isinstance(node, ast.Name) and node.id in llm_vars:
                    return True
                if isinstance(node, ast.Attribute) and node.attr in llm_vars:
                    return True
                return False

            @staticmethod
            def _get_line(source: str, lineno: int) -> str:
                try:
                    lines = source.splitlines()
                    if 0 <= lineno - 1 < len(lines):
                        return lines[lineno - 1].strip()
                except:
                    pass
                return ""

        JSONVisitor().visit(tree)

    def _check_regex_patterns(self, source: str, findings: list) -> None:
        """Check source code for regex patterns indicating injection risks."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("#"):
                continue

            for pattern, description in InjectionScanner.DANGEROUS_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append({
                        "analyzer": "injection_scanner",
                        "severity": "high",
                        "title": f"Regex-detected injection risk: {description}",
                        "description": (
                            f"Pattern detected: '{description}'. This code pattern is commonly "
                            "associated with prompt injection vulnerabilities."
                        ),
                        "line": i,
                        "code_snippet": stripped[:120],
                        "recommendation": (
                            "Review this line. Consider structured message APIs with role separation "
                            "instead of string concatenation for prompt construction."
                        ),
                    })
