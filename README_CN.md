# Agent Debug Toolkit (ADT) — AI Agent 代码调试工具

[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Stars](https://img.shields.io/github/stars/iZhangDM/agent-debug-toolkit)](https://github.com/iZhangDM/agent-debug-toolkit)

**在 AI Agent 代码上线之前，先找到隐藏的 Bug。**

ADT 是一款零依赖、纯 Python 标准库的静态分析 CLI 工具。它扫描 Python Agent 代码，自动检测漏洞、性能问题和安全隐患——在 Bug 找到你之前，你先找到它。

---

## 安装

```bash
pip install git+https://github.com/iZhangDM/agent-debug-toolkit.git
```

**要求：** Python 3.10+。零外部依赖，开箱即用。

安装后验证：

```bash
adt version
```

输出：

```
Agent Debug Toolkit v1.0.0
Pure Python • Zero dependencies • AST-based analysis

Free features:  loop analysis, tool validation, injection scanning, memory leak detection
Pro features:   RAG pipeline analysis, performance benchmarking
```

---

## 快速上手

### 基本用法

```bash
# 分析单个 Python Agent 文件
adt analyze your_agent.py

# 只显示严重和高级别问题
adt analyze your_agent.py --severity critical

# 以易读的文本格式输出（默认 JSON）
adt analyze your_agent.py --format text

# 只运行特定分析器
adt analyze your_agent.py --analyzer injection_scanner

# 生成许可证密钥（Pro 功能）
adt generate-license user@example.com

# 验证许可证
adt validate-license "user@example.com:1234567890:abc123"
```

### 运行示例

仓库自带一个故意包含 Bug 的示例 Agent，跑一遍看看效果：

```bash
adt analyze examples/sample_agent.py --format text
```

输出示例：

```
╔══════════════════════════════════════════╗
║       Agent Debug Toolkit — Report        ║
╚══════════════════════════════════════════╝

  File:       examples/sample_agent.py
  Version:    1.0.0
  Pro:        Disabled
  Analyzers:  loop_analyzer, tool_validator, injection_scanner, memory_detector

  Summary:
    Total findings: 12
    Critical:       4
    High:           5
    Medium:         2
    Low:            1

  [1] [CRITICAL] Infinite loop: 'while True' with no break, return, or raise
      Line 83 | loop_analyzer
      Code: while True:
      该 'while True' 循环没有可见的退出路径...

  [2] [CRITICAL] Dangerous function 'eval' called inside a tool
      Line 54 | tool_validator
      Code: result = eval(code)

  [3] [CRITICAL] Prompt injection risk: user input in f-string prompt
      Line 85 | injection_scanner
      Code: prompt = f"System: You are a helpful assistant.\nUser: {user_input}"

  [4] [CRITICAL] Potential injection: eval on LLM output
      Line 101 | injection_scanner
      Code: execute_code(code_to_run)
```

### JSON 输出（机器可读）

```bash
adt analyze examples/sample_agent.py --format json
```

```json
{
  "meta": {
    "file": "examples/sample_agent.py",
    "version": "1.0.0",
    "pro_features": false,
    "analyzers_ran": ["loop_analyzer", "tool_validator", "injection_scanner", "memory_detector"]
  },
  "summary": {
    "total": 12,
    "critical": 4,
    "high": 5,
    "medium": 2,
    "low": 1
  },
  "findings": [
    {
      "analyzer": "loop_analyzer",
      "severity": "critical",
      "title": "Infinite loop: 'while True' with no break, return, or raise",
      "line": 83,
      "code_snippet": "while True:",
      "description": "...",
      "recommendation": "..."
    }
  ]
}
```

---

## Free vs Pro 功能对比

| 分析器 | Free | Pro ($9) | 检测内容 |
|--------|:----:|:--------:|----------|
| **Loop 循环分析** | ✅ | ✅ | 无限循环、缺少终止条件、缺少错误处理 |
| **Tools 工具校验** | ✅ | ✅ | 危险函数调用 (`eval`/`exec`)、缺少文档字符串、缺少错误处理 |
| **Injection 注入扫描** | ✅ | ✅ | Prompt 注入漏洞（f-string、字符串拼接）、缺少分隔符 |
| **Memory 内存检测** | ✅ | ✅ | 无界集合增长、缺少清理逻辑、全局可变状态 |
| **RAG 管道分析** | ❌ | ✅ | 分块大小问题、低重叠度、缺失 k 参数 |
| **Performance 性能基准** | ❌ | ✅ | Token 浪费、高成本模型、串行 API 调用 |

---

## 定价与购买

| 版本 | 价格 | 包含功能 |
|------|------|----------|
| **Free** | 免费 | Loop / Tools / Injection / Memory 四大分析器 |
| **Pro** | **$9**（一次性，终身有效） | 全部 Free 功能 + RAG 分析 + 性能基准 + 优先支持 |

### 如何购买 Pro 许可证

发送邮件至 **2638884823@qq.com**，主题注明"ADT Pro License"，我们会在 24 小时内将许可证密钥发送给你。

收到密钥后，通过以下命令使用 Pro 功能：

```bash
adt analyze your_agent.py --license <你的许可证密钥>
```

---

## 常见问题 FAQ

### Q: ADT 和普通 Linter（如 pylint / ruff）有什么区别？
ADT 专为 **AI Agent 代码** 设计。普通 Linter 检查代码风格和通用错误，而 ADT 检测的是 Agent 特有的问题：无限 Agent 循环、Prompt 注入漏洞、工具调用缺少错误处理、对话历史无界增长等。

### Q: 零依赖是什么意思？
ADT 只使用 Python 标准库（`ast`、`json`、`argparse` 等），不需要安装任何第三方包。安装后立即可用。

### Q: 支持哪些 Python 版本？
Python 3.10 及以上版本。

### Q: Pro 许可证可以多台机器使用吗？
可以。许可证绑定邮箱，可在多台开发机器上使用。

### Q: 如何让 ADT 分析整个项目？
目前 ADT 一次分析一个文件。可以配合 shell 脚本批量分析：

```bash
find . -name "*.py" -exec adt analyze {} --format json \;
```

### Q: 支持 CI/CD 集成吗？
支持。ADT 如果发现 `critical` 级别问题会返回退出码 1，可直接集成到 CI 流程中：

```yaml
# GitHub Actions 示例
- name: Run ADT
  run: adt analyze agent.py --severity critical
```

---

## 许可证

Free 功能：MIT License。Pro 功能：专有许可。

详见 [LICENSE](LICENSE)。

---

**让 Agent 代码的上线更安心。Bug 不等人，ADT 先人一步。**
