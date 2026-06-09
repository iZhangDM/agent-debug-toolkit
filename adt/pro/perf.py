"""Performance benchmark (Pro) — measures tool call latency and token usage patterns."""

import ast
import re
from typing import Dict, List, Any


class PerfAnalyzer:
    """Analyzes agent code for performance anti-patterns and token waste."""

    name = "perf_analyzer"

    TOKEN_WASTE_PATTERNS: list[tuple[str, str]] = [
        (r"max_tokens\s*[=:]\s*(\d+)", "max_tokens"),
        (r"temperature\s*[=:]\s*(0\.?\d*)", "temperature"),
        (r"model\s*=\s*[\"\'](gpt-4|claude-3-opus|gemini-ultra)", "expensive_model"),
    ]

    API_CALL_METHODS = {
        "chat.completions.create",
        "completions.create",
        "messages.create",
        "generate",
        "invoke",
        "predict",
        "run",
        "call",
    }

    PARALLEL_PATTERNS = {
        "asyncio.gather",
        "concurrent.futures",
        "ThreadPoolExecutor",
        "ProcessPoolExecutor",
        "Promise.all",
        "batch",
    }

    def analyze(self, source: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            findings.append({
                "analyzer": self.name,
                "severity": "low",
                "title": "Pro: Performance analysis skipped due to syntax errors",
                "description": "Fix syntax errors to enable performance analysis.",
                "line": 0,
                "code_snippet": "",
                "recommendation": "Fix syntax errors.",
            })
            return findings

        self._check_token_usage(source, findings)
        self._check_sequential_api_calls(tree, findings, source)
        self._check_parallel_opportunities(tree, findings, source)
        self._check_caching_patterns(tree, findings, source)

        findings.sort(key=lambda f: f["line"])
        return findings

    def _check_token_usage(self, source: str, findings: list) -> None:
        """Check token limit and temperature settings."""
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern, category in self.TOKEN_WASTE_PATTERNS:
                match = re.search(pattern, stripped)
                if match:
                    if category == "max_tokens":
                        val = int(match.group(1))
                        if val < 50:
                            findings.append({
                                "analyzer": "perf_analyzer",
                                "severity": "medium",
                                "title": f"max_tokens is very low ({val})",
                                "description": (
                                    f"max_tokens={val} may truncate responses, causing the agent "
                                    "to make redundant follow-up calls for complete information."
                                ),
                                "line": i,
                                "code_snippet": stripped[:120],
                                "recommendation": "Set max_tokens >= 256. Consider 1024-4096 for complex tasks.",
                            })
                        elif val > 16000:
                            findings.append({
                                "analyzer": "perf_analyzer",
                                "severity": "low",
                                "title": f"max_tokens is very high ({val})",
                                "description": (
                                    f"max_tokens={val} allows very long responses, increasing latency and cost."
                                ),
                                "line": i,
                                "code_snippet": stripped[:120],
                                "recommendation": "Set a reasonable cap (4096-8192).",
                            })

                    elif category == "temperature":
                        temp = float(match.group(1))
                        if temp == 0.0:
                            findings.append({
                                "analyzer": "perf_analyzer",
                                "severity": "low",
                                "title": "temperature=0 may cause repetitive agent loops",
                                "description": (
                                    "Deterministic output can cause agents to repeat actions in a loop "
                                    "when stuck, with no variation to break dead ends."
                                ),
                                "line": i,
                                "code_snippet": stripped[:120],
                                "recommendation": "Use temperature=0.1-0.3 for slight variation in agent loops.",
                            })

                    elif category == "expensive_model":
                        model = match.group(1)
                        findings.append({
                            "analyzer": "perf_analyzer",
                            "severity": "low",
                            "title": f"Using expensive model: {model}",
                            "description": (
                                f"'{model}' is a frontier model with high latency and cost. "
                                "For agent loops, consider a cheaper model for routine decisions."
                            ),
                            "line": i,
                            "code_snippet": stripped[:120],
                            "recommendation": (
                                "Use model routing: expensive for planning, cheap for execution steps."
                            ),
                        })

    def _check_sequential_api_calls(self, tree: ast.AST, findings: list, source: str) -> None:
        """Detect sequential API calls that could be parallelized."""

        class SequentialCallVisitor(ast.NodeVisitor):
            def __init__(self):
                self.api_calls: list[int] = []

            def visit_Call(self, node: ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in PerfAnalyzer.API_CALL_METHODS:
                        self.api_calls.append(node.lineno)
                self.generic_visit(node)

        visitor = SequentialCallVisitor()
        visitor.visit(tree)

        for i in range(len(visitor.api_calls) - 1):
            if visitor.api_calls[i + 1] - visitor.api_calls[i] <= 3:
                findings.append({
                    "analyzer": "perf_analyzer",
                    "severity": "medium",
                    "title": "Sequential API calls — consider parallelization",
                    "description": (
                        "Multiple API calls close together. If independent, parallelizing "
                        "could significantly reduce total latency."
                    ),
                    "line": visitor.api_calls[i],
                    "code_snippet": self._get_line(source, visitor.api_calls[i]),
                    "recommendation": "Use asyncio.gather() or ThreadPoolExecutor for concurrent calls.",
                })
                break

    def _check_parallel_opportunities(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check if the agent already uses parallelism."""

        has_parallel = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "gather":
                    has_parallel = True
                if isinstance(node.func, ast.Name) and node.func.id in PerfAnalyzer.PARALLEL_PATTERNS:
                    has_parallel = True

        if has_parallel:
            findings.append({
                "analyzer": "perf_analyzer",
                "severity": "low",
                "title": "Parallel execution detected — good for latency",
                "description": "The agent uses async/parallel patterns, which is good for performance.",
                "line": 0,
                "code_snippet": "",
                "recommendation": "Ensure proper error handling for parallel tasks.",
            })

    def _check_caching_patterns(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check for caching of LLM responses or embeddings."""

        has_cache = False
        has_lru = False

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if "cache" in alias.name.lower() or "lru" in alias.name.lower():
                        has_cache = True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("lru_cache", "cache", "cached", "memoize"):
                        has_lru = True
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("lru_cache", "cache", "memoize"):
                        has_lru = True

        if not has_cache and not has_lru:
            has_llm_call = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in self.API_CALL_METHODS:
                            has_llm_call = True
                            break

            if has_llm_call:
                findings.append({
                    "analyzer": "perf_analyzer",
                    "severity": "medium",
                    "title": "No caching detected — repeated LLM calls waste tokens",
                    "description": (
                        "LLM API calls are detected but no caching found. "
                        "Repeated identical queries incur unnecessary latency and cost."
                    ),
                    "line": 0,
                    "code_snippet": "",
                    "recommendation": (
                        "Add @functools.lru_cache or disk-based cache. Consider semantic caching."
                    ),
                })

    @staticmethod
    def _get_line(source: str, lineno: int) -> str:
        try:
            lines = source.splitlines()
            if 0 <= lineno - 1 < len(lines):
                return lines[lineno - 1].strip()
        except Exception:
            pass
        return ""
