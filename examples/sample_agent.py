"""
Sample AI Agent — Intentionally Buggy for Demo Purposes

This file contains common bugs found in AI agent code. Run the Agent Debug
Toolkit against it to see what it finds:

    adt analyze examples/sample_agent.py
    adt analyze examples/sample_agent.py --format text

Bugs included:
  1. Infinite while loop with no break condition
  2. Tool without docstring or error handling
  3. Prompt injection vulnerability (f-string with user input)
  4. Unbounded message history (memory leak)
  5. eval() call inside a tool (security risk)
  6. Missing max iterations guard
  7. Missing error handling in agent run function
"""

import json
import time
from typing import Any

# Module-level mutable state — memory leak risk
conversation_history: list[dict] = []
global_cache: dict[str, Any] = {}

# Very high iteration limit — could hide runaway loops
max_iterations = 50000


# ============================================================
# TOOLS — intentionally problematic
# ============================================================

def search_web(query):
    """
    Search the web for information.

    Args:
        query: The search query string.

    Returns:
        Search results as a list of dicts.
    """
    import requests
    response = requests.get(f"https://api.example.com/search?q={query}")
    return response.json()


@register_tool
def execute_code(code: str):
    # No docstring, no error handling, dangerous eval
    result = eval(code)
    return {"output": result}


@register_tool
def read_file(path: str):
    # Missing description and error handling
    with open(path, "r") as f:
        return f.read()


# ============================================================
# AGENT LOOP — intentionally buggy
# ============================================================

class SimpleAgent:
    """A simple AI agent with several bugs."""

    def __init__(self):
        self.messages: list[dict] = []  # Unbounded growth
        self.running = False
        self.results = []  # Another unbounded list

    def run(self):
        """Main agent loop."""
        user_input = input("You: ")
        running = True

        # BUG: while True with no break
        while True:
            # BUG: Prompt injection — user input in f-string
            prompt = f"System: You are a helpful assistant.\nUser: {user_input}"

            response = self.call_llm(prompt)
            print(f"Agent: {response}")

            # BUG: Appending to messages without limit (memory leak)
            self.messages.append({"role": "user", "content": user_input})
            self.messages.append({"role": "assistant", "content": response})

            # BUG: Tool call without error handling
            if "search" in response.lower():
                search_web(response)

            # BUG: executing LLM output without validation
            if "CODE:" in response:
                code_to_run = response.split("CODE:")[1].strip()
                execute_code(code_to_run)

            time.sleep(1)

    def call_llm(self, prompt: str) -> str:
        # BUG: No error handling around API call
        # BUG: No caching — repeated identical calls waste tokens
        # BUG: Expensive model with high max_tokens
        model = "gpt-4"
        max_tokens = 32000  # Very high
        temperature = 0.0  # Deterministic — can loop

        # Simulated API call
        result = f"I received: {prompt[:50]}..."
        return result

    def cleanup(self):
        # Has cleanup method so memory detector won't flag the class,
        # but the actual loop code still has unbounded growth
        pass


# ============================================================
# BONUS: Recursive function without base case
# ============================================================

def process_nested_data(data):
    """Process nested data structures — might be recursively called."""
    if isinstance(data, dict):
        for key, value in data.items():
            # BUG: No base case check — could recurse infinitely on circular refs
            process_nested_data(value)
    elif isinstance(data, list):
        for item in data:
            process_nested_data(item)
    return data


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    agent = SimpleAgent()
    # BUG: run() has no try/except — crashes will be unhandled
    agent.run()
