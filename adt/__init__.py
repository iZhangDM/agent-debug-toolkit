"""Agent Debug Toolkit — analyze AI agent code for bugs and vulnerabilities."""

__version__ = "1.0.0"
__all__ = [
    "analyze",
    "analyze_file",
    "LicenseManager",
]

from adt.license import LicenseManager


def analyze(source: str) -> dict:
    """Analyze agent source code and return a structured report.

    Args:
        source: Python source code as a string.

    Returns:
        A dict containing the analysis report with findings.
    """
    from adt.analyzers.loop import LoopAnalyzer
    from adt.analyzers.tools import ToolValidator
    from adt.analyzers.injection import InjectionScanner
    from adt.analyzers.memory import MemoryLeakDetector

    report: dict = {
        "meta": {"version": __version__, "analyzers_ran": []},
        "findings": [],
        "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
    }

    analyzers = [
        LoopAnalyzer(),
        ToolValidator(),
        InjectionScanner(),
        MemoryLeakDetector(),
    ]

    for analyzer in analyzers:
        name = analyzer.name
        try:
            results = analyzer.analyze(source)
            report["meta"]["analyzers_ran"].append(name)
            for finding in results:
                report["findings"].append(finding)
                sev = finding.get("severity", "low")
                report["summary"]["total"] += 1
                if sev in report["summary"]:
                    report["summary"][sev] += 1
        except Exception as e:
            report["findings"].append({
                "analyzer": name,
                "severity": "low",
                "title": f"Analyzer '{name}' failed",
                "description": str(e),
                "line": 0,
                "code_snippet": "",
                "recommendation": "Check the source code for syntax errors.",
            })

    return report


def analyze_file(filepath: str, license_key: str | None = None) -> dict:
    """Analyze a Python file and return a structured report.

    Args:
        filepath: Path to the Python file to analyze.
        license_key: Optional license key for Pro features.

    Returns:
        A dict containing the analysis report with findings.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    report = analyze(source)
    report["meta"]["file"] = filepath

    if license_key:
        lm = LicenseManager()
        if lm.validate(license_key):
            report["meta"]["pro_features"] = True
            from adt.pro.rag import RAGAnalyzer
            from adt.pro.perf import PerfAnalyzer

            for pro_analyzer in [RAGAnalyzer(), PerfAnalyzer()]:
                name = pro_analyzer.name
                try:
                    results = pro_analyzer.analyze(source)
                    report["meta"]["analyzers_ran"].append(name)
                    for finding in results:
                        report["findings"].append(finding)
                        sev = finding.get("severity", "low")
                        report["summary"]["total"] += 1
                        if sev in report["summary"]:
                            report["summary"][sev] += 1
                except Exception as e:
                    report["findings"].append({
                        "analyzer": name,
                        "severity": "low",
                        "title": f"Pro analyzer '{name}' failed",
                        "description": str(e),
                        "line": 0,
                        "code_snippet": "",
                        "recommendation": "Check the source code.",
                    })
        else:
            report["meta"]["pro_features"] = False
            report["meta"]["license_error"] = "Invalid or expired license key. Pro features disabled."
    else:
        report["meta"]["pro_features"] = False

    return report
