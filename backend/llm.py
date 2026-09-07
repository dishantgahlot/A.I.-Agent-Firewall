import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url=os.getenv("OPENAI_BASE_URL")
)


def ask_ai(prompt: str):
    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[
            {
                "role": "system",
                "content": """
You are a code generation assistant for an AI Agent Firewall.

Given the user's request, return ONLY valid JSON.

The JSON must have exactly these fields:
{
  "language": "python",
  "code": "the generated code",
  "explanation": "short explanation of what the code does"
}

Generate code that directly addresses the user's request.
Do not use markdown code fences.
Do not add any text outside the JSON.
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
    result = ask_ai("Write Python code that adds two numbers.")
    print(result)