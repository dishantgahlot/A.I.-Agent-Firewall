from fastapi import FastAPI
from policy import create_policy
from pydantic import BaseModel

from llm import ask_ai
from security import analyze_code

import json


app = FastAPI()


class ExecuteRequest(BaseModel):
    prompt: str


@app.get("/")
def home():
    return {
        "message": "AI Agent Firewall Backend is running"
    }


@app.post("/api/execute")
def execute(request: ExecuteRequest):

    # 1. Ask the AI to generate code
    ai_response = ask_ai(request.prompt)

    # 2. Convert AI's JSON response into Python dictionary
    result = json.loads(ai_response)

    code = result["code"]
    language = result["language"]
    explanation = result["explanation"]

    # 3. Analyze generated code
    security = analyze_code(code)

 

  # 4 . policy 

    policy = create_policy(security)

    return {
    "language": language,
    "code": code,
    "explanation": explanation,
    "security": security,
    "policy": policy
}