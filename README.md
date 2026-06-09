# Agent Debug Toolkit (ADT)

[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Stars](https://img.shields.io/github/stars/iZhangDM/agent-debug-toolkit)](https://github.com/iZhangDM/agent-debug-toolkit)

**Find bugs in AI agent code before they find you.**

Static analysis CLI that scans Python agent code for bugs, vulnerabilities, and performance issues. Zero dependencies — pure stdlib.

## Free & Open Source

| Analyzer | What it finds |
|----------|---------------|
| Loop | Infinite loops, missing termination, missing error handling |
| Tools | Unsafe `eval()`/`exec()`, missing descriptions, missing error handling |
| Injection | Prompt injection via f-strings, missing delimiters |
| Memory | Unbounded collections, missing cleanup, global mutable state |

## Pro ($9 one-time → [get license](mailto:2638884823@qq.com))

| Analyzer | What it finds |
|----------|---------------|
| RAG | Chunk size issues, low overlap, missing k-parameter |
| Performance | Token waste, expensive models, sequential API calls |

## Install

```bash
pip install git+https://github.com/iZhangDM/agent-debug-toolkit.git
```

## Usage

```bash
adt analyze your_agent.py
adt analyze your_agent.py --severity critical --format json
```

## Pro

Email 2638884823@qq.com. $9, lifetime license. You get:
- RAG pipeline analyzer
- Performance benchmark
- Priority support

## License

Free tier: MIT. Pro features: proprietary.
