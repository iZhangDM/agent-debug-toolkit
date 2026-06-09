"""Setup for Agent Debug Toolkit."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="agent-debug-toolkit",
    version="1.0.0",
    author="Nous Research",
    description="Analyze AI agent code for bugs, vulnerabilities, and performance issues",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nousresearch/agent-debug-toolkit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Debuggers",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "adt=adt.cli:main",
        ],
    },
)
