from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from openai import APIConnectionError, APIStatusError, AuthenticationError
from policy import create_policy
from pydantic import BaseModel

from llm import ask_ai
from sandbox_client import call_sandbox
from security import analyze_request

import json


app = FastAPI()

# Allow the local frontend development server to call this API from another port.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    try:
        ai_response = ask_ai(request.prompt)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=502,
            detail="LLM authentication failed. Replace GROQ_API_KEY in backend/.env and restart the server.",
        ) from exc
    except APIConnectionError as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not connect to the configured LLM provider.",
        ) from exc
    except APIStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"LLM provider request failed: {exc.status_code}",
        ) from exc

    # 2. Convert the LLM JSON response into a Python dictionary.
    try:
        result = json.loads(ai_response)
        code = result["code"]
        language = result["language"]
        explanation = result["explanation"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="LLM returned an invalid code-generation response.",
        ) from exc

    # 3. Analyze the Rust request/code and generate its capability policy.
    security = analyze_request(
        prompt=request.prompt,
        code=code,
    )
    policy = create_policy(security)

    # 4. Compile and execute only if the policy explicitly allows it.
    sandbox_result = call_sandbox(code, policy)
    return {
        "language": language,
        "code": code,
        "explanation": explanation,
        "security": security,
        "policy": policy,
        "execution": sandbox_result,
    }
