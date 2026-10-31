"""GitHub App authentication (JWT -> installation access token) without extra dependencies."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import requests

from netledger.config import GitSettings
from netledger.storage import StoreError


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: int | str, private_key_pem: str, now: int | None = None) -> str:
    """RS256-signed JWT identifying the GitHub App (valid for 9 minutes)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    issued = int(now or time.time()) - 60
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iat": issued, "exp": issued + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    try:
        key: Any = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except ValueError as exc:
        raise StoreError(f"github_app.private_key is not a valid PEM private key: {exc}") from exc
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def installation_token(settings: GitSettings, repo: str, session: requests.Session | None = None) -> str:
    app = settings.github_app
    if app is None:
        raise StoreError("git.github_app is not configured")
    api = settings.api_url.rstrip("/")
    http = session or requests.Session()
    headers = {
        "Authorization": f"Bearer {app_jwt(app.app_id, app.private_key)}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        installation_id = app.installation_id
        if not installation_id:
            resp = http.get(f"{api}/repos/{repo}/installation", headers=headers, timeout=30)
            if resp.status_code != 200:
                raise StoreError(f"GitHub App is not installed on {repo} (HTTP {resp.status_code})")
            installation_id = resp.json()["id"]
        resp = http.post(f"{api}/app/installations/{installation_id}/access_tokens", headers=headers, timeout=30)
        if resp.status_code != 201:
            raise StoreError(f"could not create a GitHub App installation token (HTTP {resp.status_code}: {resp.text[:200]})")
        return resp.json()["token"]
    except requests.RequestException as exc:
        raise StoreError(f"GitHub App authentication failed: {exc}") from exc
