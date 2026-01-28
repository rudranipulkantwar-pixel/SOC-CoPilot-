from langchain_core.prompts import PromptTemplate
from langchain_ollama import OllamaLLM


def analyze_log(log_text: str):
    """
    Analyze SOC log data using Ollama + LangChain
    """

    # Load Ollama model (model must already be pulled)
    llm = OllamaLLM(model="phi")

    # Prompt template
    prompt = PromptTemplate(
        input_variables=["log"],
        template="""
You are a SOC analyst.

Analyze the following log and extract:
- Platform name (e.g., Mozilla, Chrome, Edge)
- Browser
- Suspicious indicators (if any)
- Short security summary

Log:
{log}

Return output in clear bullet points.
"""
    )

    # Build final prompt
    final_prompt = prompt.format(log=log_text)

    # Run LLM
    response = llm.invoke(final_prompt)

    return response


# -------- TEST RUN --------
if __name__ == "__main__":
    sample_log = """
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/120.0.0.0 Safari/537.36
"""

    result = analyze_log(sample_log)
    print("\n=== AI ANALYSIS OUTPUT ===\n")
    print(result)
