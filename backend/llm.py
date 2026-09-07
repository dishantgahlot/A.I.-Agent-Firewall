import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


def get_env_value(name: str) -> str | None:
    """Read a .env value while tolerating a trailing shell semicolon."""
    value = os.getenv(name)
    return value.rstrip(";").strip() if value else None


def ask_ai(prompt: str):
    api_key =  get_env_value("OPENAI_API_KEY")
    base_url = get_env_value("OPENAI_BASE_URL")
    model = get_env_value("OPENAI_MODEL") or "openai/gpt-oss-120b"

    if not api_key:
        raise RuntimeError("Set GROQ_API_KEY in backend/.env before calling the LLM.")

    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
    )

    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": """
You are a code generation assistant for an AI Agent Firewall.

Given the user's request, return ONLY valid JSON.

The JSON must have exactly these fields:
{
  "language": "rust",
  "code": "the generated Rust code",
  "explanation": "short explanation of what the code does"
}

Generate Rust code that directly addresses the user's request.
Do not use markdown code fences.
Do not add any text outside the JSON.
The Rust code must be a complete program with a fn main() function.
"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content


if __name__ == "__main__":
    result = ask_ai("Write Rust code that adds two numbers.")
    print(result)
