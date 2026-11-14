"""Remote, OAuth-protected MCP server for the Abhishek Santra exam portal.

Run with: python mcp_remote.py
Required environment:
  PORTAL_BASE_URL, MCP_API_TOKEN, MCP_LOGIN_USERNAME, MCP_LOGIN_PASSWORD
"""
import html
import os
import io
import json
import base64

import secrets
import time
from typing import Any

import requests
import psycopg
from psycopg.rows import dict_row
from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams,
    OAuthAuthorizationServerProvider, RefreshToken, construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

BASE = os.environ.get("PORTAL_BASE_URL", "").rstrip("/")
PORTAL_TOKEN = os.environ.get("MCP_API_TOKEN", "")
LOGIN_USER = os.environ.get("MCP_LOGIN_USERNAME", "")
LOGIN_PASS = os.environ.get("MCP_LOGIN_PASSWORD", "")
PUBLIC_URL = os.environ.get("MCP_PUBLIC_URL", "").rstrip("/")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))

if not all((BASE, PORTAL_TOKEN, LOGIN_USER, LOGIN_PASS, PUBLIC_URL, DATABASE_URL)):
    raise RuntimeError(
        "Set PORTAL_BASE_URL, MCP_API_TOKEN, MCP_LOGIN_USERNAME, "
        "MCP_LOGIN_PASSWORD, MCP_PUBLIC_URL and DATABASE_URL."
    )

class PortalOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """OAuth provider with dynamic client registration and PKCE."""
    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.states: dict[str, dict[str, Any]] = {}
        # OAuth dynamic-client registrations survive Render restarts/redeploys.
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_info JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            rows = conn.execute("SELECT client_id, client_info FROM mcp_oauth_clients").fetchall()
        for row in rows:
            info = OAuthClientInformationFull.model_validate(row["client_info"])
            self.clients[row["client_id"]] = info

    async def get_client(self, client_id: str):
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        if not client_info.client_id:
            raise ValueError("Missing OAuth client ID")
        # Persist before returning success to the OAuth registration endpoint.
        payload = client_info.model_dump(mode="json", exclude_none=True)
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute(
                """INSERT INTO mcp_oauth_clients (client_id, client_info)
                   VALUES (%s, %s::jsonb)
                   ON CONFLICT (client_id) DO UPDATE SET client_info = EXCLUDED.client_info""",
                (client_info.client_id, json.dumps(payload)),
            )
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = params.state or secrets.token_urlsafe(24)
        self.states[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "explicit": bool(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,
            "scopes": params.scopes or ["portal"],
        }
        return f"{PUBLIC_URL}/login?state={state}"

    async def load_authorization_code(self, client, authorization_code: str):
        return self.codes.get(authorization_code)

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        code = self.codes.get(authorization_code.code)
        if code is None or code.expires_at < time.time():
            raise ValueError("Authorization code expired or invalid")
        if code.client_id != client.client_id:
            raise ValueError("OAuth client mismatch")
        token = "portal_" + secrets.token_urlsafe(48)
        self.tokens[token] = AccessToken(
            token=token, client_id=client.client_id or "",
            scopes=code.scopes, expires_at=int(time.time()) + 3600,
            resource=code.resource,
        )
        del self.codes[authorization_code.code]
        return OAuthToken(access_token=token, token_type="Bearer", expires_in=3600, scope=" ".join(code.scopes))

    async def load_access_token(self, token: str):
        item = self.tokens.get(token)
        if item and item.expires_at and item.expires_at <= time.time():
            self.tokens.pop(token, None)
            return None
        return item

    async def load_refresh_token(self, client, refresh_token: str):
        return None

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]):
        raise NotImplementedError("Refresh tokens are not enabled")

    async def revoke_token(self, token: str, token_type_hint: str | None = None):
        self.tokens.pop(token, None)

    async def login_page(self, state: str) -> HTMLResponse:
        if state not in self.states:
            raise HTTPException(400, "Invalid or expired login state")
        safe_state = html.escape(state, quote=True)
        page = f"""<!doctype html><html><head><meta name="viewport" content="width=device-width">
        <title>Exam Portal MCP Login</title></head><body style="font:16px Arial;max-width:420px;margin:60px auto;padding:20px">
        <h2>Exam Portal MCP</h2><p>Sign in to authorize Gemini to use your exam portal tools.</p>
        <form method="post" action="/login">
        <input type="hidden" name="state" value="{safe_state}">
        <p><label>Username<br><input name="username" required autocomplete="username"></label></p>
        <p><label>Password<br><input type="password" name="password" required autocomplete="current-password"></label></p>
        <button type="submit">Authorize Gemini</button></form></body></html>"""
        return HTMLResponse(page)

    async def login_callback(self, request: Request) -> Response:
        form = await request.form()
        state, username, password = form.get("state"), form.get("username"), form.get("password")
        if not all(isinstance(x, str) for x in (state, username, password)):
            raise HTTPException(400, "Missing login fields")
        data = self.states.get(state)
        if not data or not secrets.compare_digest(username, LOGIN_USER) or not secrets.compare_digest(password, LOGIN_PASS):
            raise HTTPException(401, "Invalid login or expired authorization request")
        code_value = "code_" + secrets.token_urlsafe(32)
        self.codes[code_value] = AuthorizationCode(
            code=code_value, client_id=data["client_id"],
            redirect_uri=AnyHttpUrl(data["redirect_uri"]),
            redirect_uri_provided_explicitly=data["explicit"],
            expires_at=time.time() + 300, scopes=data["scopes"],
            code_challenge=data["code_challenge"], resource=data["resource"],
        )
        del self.states[state]
        return RedirectResponse(
            construct_redirect_uri(data["redirect_uri"], code=code_value, state=state),
            status_code=302,
        )

provider = PortalOAuthProvider()
auth = AuthSettings(
    issuer_url=AnyHttpUrl(PUBLIC_URL),
    resource_server_url=AnyHttpUrl(PUBLIC_URL),
    client_registration_options=ClientRegistrationOptions(
        enabled=True, valid_scopes=["portal"], default_scopes=["portal"]
    ),
    required_scopes=["portal"],
)
mcp = FastMCP(
    name="Abhishek Santra English Guidance Exam Portal",
    instructions="Create exam workbooks, upload them as drafts, list exams, and retrieve results. Uploaded exams require teacher approval before publishing.",
    host=HOST, port=PORT, auth_server_provider=provider, auth=auth,
)

@mcp.custom_route("/login", methods=["GET"])
async def login_page(request: Request) -> Response:
    state = request.query_params.get("state", "")
    return await provider.login_page(state)

@mcp.custom_route("/login", methods=["POST"])
async def login_post(request: Request) -> Response:
    return await provider.login_callback(request)

def portal_call(method: str, path: str, **kwargs):
    response = requests.request(
        method, BASE + path,
        headers={"Authorization": "Bearer " + PORTAL_TOKEN},
        timeout=90, **kwargs,
    )
    if not response.ok:
        detail = response.text[:1500]
        raise RuntimeError(f"Portal API returned HTTP {response.status_code}: {detail}")
    return response.json()

def normalize_class_level(value: str) -> str:
    value = str(value).strip()
    if value.isdigit():
        value = f"Class {value}"
    if value not in {f"Class {i}" for i in range(5, 13)}:
        raise ValueError("class_level must be Class 5 through Class 12 (or just the grade number).")
    return value

@mcp.tool()
def create_exam_from_questions(title: str, class_level: str, questions_json: str,
                               shared_password: str, duration: int = 45,
                               review: int = 0, password_exam_limit: int = 1) -> dict:
    """Create a portal exam draft from questions GENERATED BY GEMINI from the teacher's prompt. Gemini must first generate the complete question paper and answer key, then pass questions_json as a JSON array. Each question object: question (string), type (mcq/fill/text), marks (number), answer (string), options (array of strings for MCQ). class_level accepts 8 or Class 8. This tool creates an Excel file internally; the teacher does not need to provide one. Exam is always saved as DRAFT for teacher review."""
    class_level = normalize_class_level(class_level)
    try:
        questions = json.loads(questions_json)
    except Exception as exc:
        raise ValueError("questions_json must be a valid JSON array.") from exc
    if not isinstance(questions, list) or not questions or len(questions) > 100:
        raise ValueError("Provide between 1 and 100 questions.")
    from openpyxl import Workbook
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Questions"
    sheet.append(["question", "type", "marks", "answer", "option_a", "option_b", "option_c", "option_d"])
    for index, q in enumerate(questions, 1):
        if not isinstance(q, dict):
            raise ValueError(f"Question {index} must be a JSON object.")
        kind = str(q.get("type", "")).lower().strip()
        if kind in ("multiple_choice", "multiple choice"):
            kind = "mcq"
        if kind not in ("mcq", "fill", "text"):
            raise ValueError(f"Question {index}: type must be mcq, fill or text.")
        prompt = str(q.get("question", "")).strip()
        answer = str(q.get("answer", "")).strip()
        try:
            marks = float(q.get("marks", 0))
        except Exception as exc:
            raise ValueError(f"Question {index}: invalid marks.") from exc
        options = q.get("options") or []
        if not prompt or not answer or marks <= 0:
            raise ValueError(f"Question {index}: question, positive marks and answer are required.")
        if kind == "mcq" and (not isinstance(options, list) or len(options) < 2 or len(options) > 4):
            raise ValueError(f"Question {index}: MCQ requires 2 to 4 options.")
        options = [str(x) for x in options] if kind == "mcq" else []
        sheet.append([prompt, kind, marks, answer] + (options + [""] * 4)[:4])
    output = io.BytesIO()
    workbook.save(output)
    workbook.close()
    encoded = base64.b64encode(output.getvalue()).decode("ascii")
    return portal_call("POST", "/api/mcp/exams/upload", json={
        "title": title, "class_level": class_level, "workbook_base64": encoded,
        "shared_password": shared_password, "duration": duration, "review": review,
        "password_exam_limit": password_exam_limit, "file_name": "gemini_generated_exam.xlsx",
    })

@mcp.tool()
def upload_exam_excel(title: str, class_level: str, workbook_base64: str, shared_password: str,
                      duration: int = 45, review: int = 0, password_exam_limit: int = 1,
                      file_name: str = "exam.xlsx") -> dict:
    """Upload a Gemini-created .xlsx workbook as a DRAFT. class_level accepts Class 5 through Class 12 or just the grade number (for example 8). Required headers: question,type,marks,answer. Optional: option_a,option_b,option_c,option_d. Types: mcq,fill,text. Teacher approval is required to publish."""
    class_level = normalize_class_level(class_level)
    return portal_call("POST", "/api/mcp/exams/upload", json={
        "title": title, "class_level": class_level, "workbook_base64": workbook_base64,
        "shared_password": shared_password, "duration": duration, "review": review,
        "password_exam_limit": password_exam_limit, "file_name": file_name,
    })

@mcp.tool()
def create_exam_draft(title: str, class_level: str, prompt: str, duration: int, review: int,
                      shared_password: str, password_exam_limit: int = 1) -> dict:
    """Create a legacy JSON exam draft for teacher approval."""
    return portal_call("POST", "/api/mcp/exams", json={
        "title": title, "class_level": class_level, "prompt": prompt,
        "duration": duration, "review": review, "shared_password": shared_password,
        "password_exam_limit": password_exam_limit,
    })

@mcp.tool()
def list_examinations() -> dict:
    """List examination titles, statuses and exam codes."""
    return portal_call("GET", "/api/mcp/exams")



@mcp.tool()
def delete_examination(exam_id: int) -> dict:
    """Archive an examination from active use by numeric exam ID. This safe delete closes and hides the exam from students but retains questions, submissions and historical results. It refuses while student attempts are in progress."""
    if not isinstance(exam_id, int) or exam_id <= 0:
        raise ValueError("exam_id must be a positive integer.")
    return portal_call("POST", f"/api/mcp/exams/{exam_id}/delete")

@mcp.tool()
def get_examination_results() -> dict:
    """Retrieve completed examination results, sorted by marks descending. Restricted to authorized portal users."""
    return portal_call("GET", "/api/mcp/results")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
