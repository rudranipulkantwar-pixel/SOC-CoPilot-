# llm_engine.py
import subprocess
import json
import re

MODEL = "mistral:7b-instruct"


def extract_json(text: str):
    """
    Extracts the first JSON object found in the LLM output.
    """
    match = re.search(r"\{[\s\S]*\}", text)
    return match.group(0) if match else None


def generate_summary_and_mitigation(log: str, severity: str) -> dict:
    """
    Generates a human-readable incident summary and mitigation steps
    using Ollama (v0.14.2, stdin-based).
    """

    prompt = f"""
You are an experienced SOC Analyst.

TASK:
Explain the security log in a way that a NORMAL PERSON (non-technical) can understand.

RULES:
- Respond ONLY in valid JSON
- No markdown
- No extra text outside JSON

CONTENT REQUIREMENTS:
- Summary: 4–6 full sentences
- Explain what happened, why it matters, and what could happen if ignored
- Mitigation: 4 clear, actionable steps

JSON FORMAT:
{{
  "alert": "Short alert title",
  "summary": "Detailed human-readable explanation",
  "mitigation": [
    "Step 1 explanation",
    "Step 2 explanation",
    "Step 3 explanation",
    "Step 4 explanation"
  ]
}}

Severity Level: {severity}

Log Entry:
{log}
"""

    try:
        # IMPORTANT:
        # Ollama v0.14.2 only supports stdin-based prompts.
        # json.dumps() safely escapes newlines and quotes.
        command = f'echo {json.dumps(prompt)} | ollama run {MODEL}'

        result = subprocess.run(
            command,
            shell=True,
            text=True,
            capture_output=True,
            timeout=120
        )

        raw_output = result.stdout.strip()

        if not raw_output:
            raise ValueError("Empty response from Ollama")

        json_text = extract_json(raw_output)
        if not json_text:
            raise ValueError("No JSON detected in LLM output")

        return json.loads(json_text)

    except FileNotFoundError:
        return {
            "alert": "Ollama Not Installed",
            "summary": (
                "The local LLM engine (Ollama) is not installed on this system, "
                "so an automated explanation could not be generated."
            ),
            "mitigation": [
                "Install Ollama on the system.",
                "Download a supported model such as mistral:7b-instruct.",
                "Ensure Ollama is accessible from the command line.",
                "Restart the application after installation."
            ]
        }

    except Exception as e:
        return {
            "alert": "LLM Generation Failed",
            "summary": (
                "The system was unable to generate an explanation using the local LLM. "
                f"Reason: {str(e)}"
            ),
            "mitigation": [
                "Ensure the Ollama server is running.",
                "Verify the model name is correct and available.",
                "Check system memory availability.",
                "Retry after resolving the issue."
            ]
        }
