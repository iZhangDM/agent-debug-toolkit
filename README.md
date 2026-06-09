# Agent Debug Toolkit (ADT)

**Find bugs in AI agent code before they find you.**

A production-quality static analysis tool that scans Python agent code for
common bugs, security vulnerabilities, and performance issues. Zero external
dependencies — pure Python standard library.

## Features

### Free Tier
| Analyzer | What it finds |
|----------|---------------|
| **Loop Analyzer** | Infinite loops, missing termination conditions, missing error handling, runaway recursion, unsafe max_iterations |
| **Tool Validator** | Missing tool descriptions, unsafe `eval()`/`exec()` calls, missing error handling, missing return types |
| **Injection Scanner** | Prompt injection via f-strings/concatenation, missing delimiter protection, unsafe JSON/YAML parsing of LLM output |
| **Memory Detector** | Unbounded collections in loops, missing cleanup methods, module-level mutable state, circular references |

### Pro Tier (requires license key)
| Analyzer | What it finds |
|----------|---------------|
| **RAG Analyzer** | Suboptimal chunk sizes, low overlap, basic retrieval strategies, missing k-parameter, embedding model validation |
| **Performance** | Token waste (very low/high max_tokens), expensive model selection, sequential API calls, missing caching |

## Installation

```bash
# Clone and install
git clone https://github.com/nousresearch/agent-debug-toolkit.git
cd agent-debug-toolkit
pip install -e .

# Or run directly without installing
python -m adt.cli analyze path/to/agent.py
```

**Requirements:** Python 3.10+. No external dependencies.

## Quick Start

```bash
# Analyze the sample agent (free features)
adt analyze examples/sample_agent.py

# Text format (easier to read)
adt analyze examples/sample_agent.py --format text

# Only show critical and high severity
adt analyze examples/sample_agent.py --severity high

# Run a specific analyzer
adt analyze examples/sample_agent.py --analyzer injection_scanner

# With Pro license
adt analyze examples/sample_agent.py --license YOUR_KEY

# Generate a license key
adt generate-license user@example.com --days 365

# Validate a license
adt validate-license "user@example.com:1234567890:abc123"

# Show version
adt version
```

## Output Format

### JSON (default)
```json
{
  "meta": {
    "version": "1.0.0",
    "analyzers_ran": ["loop_analyzer", "tool_validator", ...],
    "file": "my_agent.py",
    "pro_features": false
  },
  "findings": [
    {
      "analyzer": "loop_analyzer",
      "severity": "critical",
      "title": "Infinite loop: 'while True' with no break",
      "description": "This loop has no visible exit path...",
      "line": 42,
      "code_snippet": "while True:",
      "recommendation": "Add a break condition or max_iterations guard."
    }
  ],
  "summary": {
    "total": 8,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1
  }
}
```

### Text
```
╔══════════════════════════════════════════╗
║       Agent Debug Toolkit — Report       ║
╚══════════════════════════════════════════╝

  File:       examples/sample_agent.py
  Version:    1.0.0
  Pro:        Disabled

  Summary:
    Total findings: 8
    Critical:       2
    High:           3
    Medium:         2
    Low:            1

  [1] [CRITICAL] Infinite loop: 'while True' with no break
      Line 72 | loop_analyzer
      Code: while True:
      Fix: Add a break condition or max_iterations guard.
...
```

## Severity Levels

| Level | Meaning |
|-------|---------|
| **critical** | Will crash or cause security breach (infinite loops, eval(), prompt injection) |
| **high** | Likely to cause bugs (unbounded memory, missing error handling) |
| **medium** | Code smell / best practice violation |
| **low** | Suggestion for improvement |

## Architecture

```
agent-debug-toolkit/
├── adt/
│   ├── __init__.py       # Core API (analyze, analyze_file)
│   ├── cli.py            # CLI (argparse)
│   ├── license.py        # HMAC license key system
│   ├── analyzers/
│   │   ├── loop.py       # Agent loop analysis
│   │   ├── tools.py      # Tool definition validation
│   │   ├── injection.py  # Prompt injection scanning
│   │   └── memory.py     # Memory leak detection
│   └── pro/
│       ├── rag.py        # RAG pipeline analysis
│       └── perf.py       # Performance benchmarking
├── setup.py
├── README.md
└── examples/
    └── sample_agent.py   # Demo agent with intentional bugs
```

## Programmatic API

```python
from adt import analyze, analyze_file

# Analyze source code string
source = open("my_agent.py").read()
report = analyze(source)

# Analyze a file directly (free tier)
report = analyze_file("my_agent.py")

# Analyze with Pro features
report = analyze_file("my_agent.py", license_key="your-key")
```

## License

Agent Debug Toolkit is source-available. Free tier features are available to
everyone. Pro features require a license key.

Generate a free trial: `adt generate-license your@email.com --days 30`
