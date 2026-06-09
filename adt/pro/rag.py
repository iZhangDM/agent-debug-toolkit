"""RAG pipeline analyzer (Pro) — checks chunk size, overlap, and retrieval strategy."""

import ast
import re
from typing import Dict, List, Any


class RAGAnalyzer:
    """Analyzes RAG (Retrieval-Augmented Generation) pipeline code for best practices."""

    name = "rag_analyzer"

    # Patterns for chunk size settings
    CHUNK_SIZE_PATTERNS = [
        r"chunk_size\s*[=:]\s*(\d+)",
        r"chunkSize\s*[=:]\s*(\d+)",
        r"max_chunk\w*\s*[=:]\s*(\d+)",
    ]

    CHUNK_OVERLAP_PATTERNS = [
        r"chunk_overlap\s*[=:]\s*(\d+)",
        r"chunkOverlap\s*[=:]\s*(\d+)",
        r"overlap\s*[=:]\s*(\d+)",
    ]

    # Thresholds
    MIN_CHUNK_SIZE = 100
    MAX_CHUNK_SIZE = 4096
    IDEAL_CHUNK_SIZE = (256, 2048)
    IDEAL_OVERLAP_RATIO = (0.05, 0.25)

    RETRIEVAL_METHODS = {
        "similarity_search": "Similarity",
        "similarity_search_with_score": "Similarity w/ score",
        "max_marginal_relevance_search": "MMR (Max Marginal Relevance)",
        "as_retriever": "LangChain retriever",
        "retrieve": "Generic retrieve",
        "query": "Generic query",
    }

    EMBEDDING_MODELS = {
        "text-embedding-ada-002": {"dim": 1536, "provider": "OpenAI"},
        "text-embedding-3-small": {"dim": 1536, "provider": "OpenAI"},
        "text-embedding-3-large": {"dim": 3072, "provider": "OpenAI"},
        "embed-english-v3.0": {"dim": 1024, "provider": "Cohere"},
        "e5": {"dim": 1024, "provider": "Microsoft"},
        "bge": {"dim": 1024, "provider": "BAAI"},
    }

    def analyze(self, source: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            findings.append({
                "analyzer": self.name,
                "severity": "low",
                "title": "Pro: RAG analysis skipped due to syntax errors",
                "description": "Fix syntax errors to enable RAG pipeline analysis.",
                "line": 0,
                "code_snippet": "",
                "recommendation": "Fix syntax errors.",
            })
            return findings

        self._check_chunk_config(source, findings)
        self._check_retrieval_strategy(tree, findings, source)
        self._check_embedding_usage(source, findings)
        self._check_vector_store_config(tree, findings, source)

        findings.sort(key=lambda f: f["line"])
        return findings

    def _check_chunk_config(self, source: str, findings: list) -> None:
        """Check chunk size and overlap settings."""
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            # Chunk size check
            for pattern in self.CHUNK_SIZE_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    size = int(match.group(1))
                    if size < self.MIN_CHUNK_SIZE:
                        findings.append({
                            "analyzer": "rag_analyzer",
                            "severity": "high",
                            "title": f"Chunk size ({size}) is too small",
                            "description": (
                                f"Chunk size of {size} characters is very small. Tiny chunks lose "
                                "semantic context and may not contain complete sentences or ideas. "
                                "This degrades retrieval quality significantly."
                            ),
                            "line": i,
                            "code_snippet": line.strip()[:120],
                            "recommendation": (
                                f"Increase chunk_size to at least {self.MIN_CHUNK_SIZE}. "
                                "Recommended range: 256-2048 characters depending on content type."
                            ),
                        })
                    elif size > self.MAX_CHUNK_SIZE:
                        findings.append({
                            "analyzer": "rag_analyzer",
                            "severity": "medium",
                            "title": f"Chunk size ({size}) is very large",
                            "description": (
                                f"Chunk size of {size} characters is very large. Large chunks "
                                "dilute embedding quality and may exceed model context windows "
                                "when multiple chunks are retrieved."
                            ),
                            "line": i,
                            "code_snippet": line.strip()[:120],
                            "recommendation": (
                                f"Reduce chunk_size to {self.MAX_CHUNK_SIZE} or below. "
                                "Consider 512-1024 for general text, 256-512 for code."
                            ),
                        })
                    elif self.IDEAL_CHUNK_SIZE[0] <= size <= self.IDEAL_CHUNK_SIZE[1]:
                        findings.append({
                            "analyzer": "rag_analyzer",
                            "severity": "low",
                            "title": f"Chunk size ({size}) is in the recommended range",
                            "description": f"Chunk size of {size} is within the ideal range of 256-2048.",
                            "line": i,
                            "code_snippet": line.strip()[:120],
                            "recommendation": "Good chunk size. Consider A/B testing with adjacent values.",
                        })
                    break

            # Overlap check
            for pattern in self.CHUNK_OVERLAP_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    overlap = int(match.group(1))
                    # Look for chunk_size on nearby lines
                    chunk_size = None
                    for j in range(max(0, i - 3), min(len(lines), i + 4)):
                        for cp in self.CHUNK_SIZE_PATTERNS:
                            cm = re.search(cp, lines[j], re.IGNORECASE)
                            if cm:
                                chunk_size = int(cm.group(1))
                                break

                    if chunk_size and chunk_size > 0:
                        ratio = overlap / chunk_size
                        if ratio < self.IDEAL_OVERLAP_RATIO[0]:
                            findings.append({
                                "analyzer": "rag_analyzer",
                                "severity": "medium",
                                "title": f"Chunk overlap ratio is too low ({ratio:.1%})",
                                "description": (
                                    f"Overlap of {overlap} with chunk_size of {chunk_size} gives "
                                    f"only {ratio:.1%} overlap. Low overlap risks missing information "
                                    "that spans chunk boundaries."
                                ),
                                "line": i,
                                "code_snippet": line.strip()[:120],
                                "recommendation": (
                                    f"Increase overlap to {int(chunk_size * 0.1)}-{int(chunk_size * 0.25)} "
                                    "for better boundary coverage."
                                ),
                            })
                        elif ratio > self.IDEAL_OVERLAP_RATIO[1]:
                            findings.append({
                                "analyzer": "rag_analyzer",
                                "severity": "low",
                                "title": f"Chunk overlap ratio is high ({ratio:.1%})",
                                "description": (
                                    f"Overlap of {overlap} with chunk_size of {chunk_size} is {ratio:.1%}. "
                                    "High overlap increases storage cost with diminishing returns."
                                ),
                                "line": i,
                                "code_snippet": line.strip()[:120],
                                "recommendation": (
                                    f"Consider reducing overlap to {int(chunk_size * 0.15)} for efficiency."
                                ),
                            })
                    break

    def _check_retrieval_strategy(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check retrieval method used."""

        class RetrievalVisitor(ast.NodeVisitor):
            def __init__(self):
                self.found_methods: list[tuple[str, int]] = []

            def visit_Call(self, node: ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in RAGAnalyzer.RETRIEVAL_METHODS:
                        self.found_methods.append((node.func.attr, node.lineno))
                self.generic_visit(node)

        visitor = RetrievalVisitor()
        visitor.visit(tree)

        for method, line in visitor.found_methods:
            if method == "similarity_search":
                findings.append({
                    "analyzer": "rag_analyzer",
                    "severity": "low",
                    "title": "Using basic similarity search — consider MMR or re-ranking",
                    "description": (
                        "Basic similarity search returns results ranked only by embedding distance. "
                        "This can return near-duplicate chunks missing diverse perspectives."
                    ),
                    "line": line,
                    "code_snippet": self._get_line(source, line),
                    "recommendation": (
                        "Consider max_marginal_relevance_search for diversity, or add a re-ranker "
                        "(cross-encoder) for better precision."
                    ),
                })
            elif method == "max_marginal_relevance_search":
                findings.append({
                    "analyzer": "rag_analyzer",
                    "severity": "low",
                    "title": "Using MMR retrieval — good choice for diversity",
                    "description": "MMR balances relevance with diversity, reducing duplicate information.",
                    "line": line,
                    "code_snippet": self._get_line(source, line),
                    "recommendation": "Good. Consider tuning lambda_mult for your use case (0.5-0.7 for balanced).",
                })

        if not visitor.found_methods:
            findings.append({
                "analyzer": "rag_analyzer",
                "severity": "medium",
                "title": "No explicit retrieval method detected",
                "description": (
                    "The code doesn't clearly call a known retrieval method. If this is a RAG pipeline, "
                    "make the retrieval strategy explicit for better debuggability."
                ),
                "line": 0,
                "code_snippet": "",
                "recommendation": "Make the retrieval method explicit (similarity_search, MMR, etc.).",
            })

    def _check_embedding_usage(self, source: str, findings: list) -> None:
        """Check embedding model usage."""
        lines = source.splitlines()
        found_model = None
        model_line = 0

        for i, line in enumerate(lines, 1):
            for model_name in self.EMBEDDING_MODELS:
                if model_name in line:
                    found_model = model_name
                    model_line = i
                    break

        if found_model and found_model in self.EMBEDDING_MODELS:
            info = self.EMBEDDING_MODELS[found_model]
            findings.append({
                "analyzer": "rag_analyzer",
                "severity": "low",
                "title": f"Embedding model: {found_model} ({info['provider']}, {info['dim']}d)",
                "description": (
                    f"Using {found_model} embeddings. "
                    f"Dimension: {info['dim']}. Ensure your vector store is configured for this dimensionality."
                ),
                "line": model_line,
                "code_snippet": lines[model_line - 1].strip() if model_line else "",
                "recommendation": "Ensure consistent dimensionality across embedding and vector store.",
            })
        else:
            # Check for any embedding reference
            has_embedding = any("embedding" in line.lower() or "embed" in line.lower() for line in lines)
            if has_embedding:
                findings.append({
                    "analyzer": "rag_analyzer",
                    "severity": "low",
                    "title": "Embedding model not recognized",
                    "description": (
                        "An embedding reference was found but the model couldn't be identified. "
                        "Consider using a well-known model for better tooling support."
                    ),
                    "line": 0,
                    "code_snippet": "",
                    "recommendation": "Use a standard embedding model for consistent behavior.",
                })

    def _check_vector_store_config(self, tree: ast.AST, findings: list, source: str) -> None:
        """Check vector store configuration."""

        class VSVisitor(ast.NodeVisitor):
            def visit_Call(self, node: ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("Chroma", "FAISS", "Pinecone", "Weaviate", "Qdrant", "Milvus"):
                    # Check if 'k' (number of results) is set
                    has_k = False
                    for kw in node.keywords:
                        if kw.arg in ("k", "top_k", "topk", "n_results"):
                            has_k = True
                            if isinstance(kw.value, ast.Constant):
                                k = kw.value.value
                                if isinstance(k, int):
                                    if k > 50:
                                        findings.append({
                                            "analyzer": "rag_analyzer",
                                            "severity": "medium",
                                            "title": f"High retrieval count (k={k}) may waste tokens",
                                            "description": (
                                                f"Retrieving {k} results per query may include low-relevance "
                                                "chunks, wasting context window space and increasing costs."
                                            ),
                                            "line": node.lineno,
                                            "code_snippet": RAGAnalyzer._get_line_static(source, node.lineno),
                                            "recommendation": (
                                                "Use k=3-10 for most use cases. Use re-ranking if you need "
                                                "to start with a larger pool."
                                            ),
                                        })
                                    elif k < 2:
                                        findings.append({
                                            "analyzer": "rag_analyzer",
                                            "severity": "medium",
                                            "title": f"Very low retrieval count (k={k})",
                                            "description": (
                                                f"Retrieving only {k} result(s) may miss relevant context."
                                            ),
                                            "line": node.lineno,
                                            "code_snippet": RAGAnalyzer._get_line_static(source, node.lineno),
                                            "recommendation": "Use at least k=3 for adequate context coverage.",
                                        })
                    if not has_k:
                        findings.append({
                            "analyzer": "rag_analyzer",
                            "severity": "medium",
                            "title": "Vector store created without explicit 'k' (retrieval count)",
                            "description": (
                                "No 'k' parameter found. Relying on defaults may retrieve too many "
                                "or too few documents."
                            ),
                            "line": node.lineno,
                            "code_snippet": RAGAnalyzer._get_line_static(source, node.lineno),
                            "recommendation": "Set an explicit k value (3-10 recommended).",
                        })
                self.generic_visit(node)

        VSVisitor().visit(tree)

    @staticmethod
    def _get_line_static(source: str, lineno: int) -> str:
        try:
            lines = source.splitlines()
            if 0 <= lineno - 1 < len(lines):
                return lines[lineno - 1].strip()
        except:
            pass
        return ""

    def _get_line(self, source: str, lineno: int) -> str:
        return RAGAnalyzer._get_line_static(source, lineno)
