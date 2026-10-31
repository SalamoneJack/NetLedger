"""GitHub REST API backend: commits directly via the Git Data API, no git binary or clone required."""

from __future__ import annotations

import base64
import logging
import time
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from netledger import __version__
from netledger.config import GitSettings
from netledger.storage import PublishResult, Store, StoreError, WebLinks, derive_web_url
from netledger.utils import git_blob_sha

log = logging.getLogger(__name__)

INIT_MARKER = "<!-- netledger:init -->"


class GitHubStore(Store):
    def __init__(self, settings: GitSettings, session: requests.Session | None = None):
        self.settings = settings
        self.api = settings.api_url.rstrip("/")
        self.repo = settings.repo or self._repo_from_url(settings.url)
        self.branch = settings.branch
        web = settings.web_url or derive_web_url(settings.url) or self._default_web_url()
        self.links = WebLinks(web, self.branch)
        self.session = session or self._new_session()
        self._base_commit: str | None = None
        self._head_commit: str | None = None
        self._head_tree: str | None = None
        self._index: dict[str, str] = {}
        self._blob_cache: dict[str, str] = {}
        self._journal: list[tuple[dict[str, str | None], str]] = []

    @staticmethod
    def _repo_from_url(url: str | None) -> str:
        web = derive_web_url(url) or ""
        parts = web.rstrip("/").split("/")
        if len(parts) < 5:
            raise StoreError("set git.repo to 'owner/name' for the github backend")
        return f"{parts[-2]}/{parts[-1]}"

    def _default_web_url(self) -> str:
        if self.api == "https://api.github.com":
            return f"https://github.com/{self.repo}"
        return f"{self.api.rsplit('/api', 1)[0]}/{self.repo}"

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=4, backoff_factor=1.5, status_forcelist=(502, 503, 504), allowed_methods=None, raise_on_status=False)
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"netledger/{__version__}",
        })
        session.verify = self.settings.verify_ssl
        return session

    def describe(self) -> str:
        host = "github.com" if self.api == "https://api.github.com" else self.api.split("//")[-1].split("/")[0]
        return f"{host}/{self.repo}@{self.branch}"

    # ------------------------------------------------------------------ HTTP

    def _request(self, method: str, path: str, expected: tuple[int, ...] = (200, 201), **kwargs: Any) -> requests.Response:
        url = path if path.startswith("http") else f"{self.api}/repos/{self.repo}{path}"
        try:
            resp = self.session.request(method, url, timeout=60, **kwargs)
        except requests.RequestException as exc:
            raise StoreError(f"GitHub API {method} {path}: {exc}") from exc
        if resp.status_code in expected:
            return resp
        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = int(resp.headers.get("X-RateLimit-Reset", "0") or 0)
            raise StoreError(f"GitHub API rate limit exceeded; resets in {max(0, reset - int(time.time()))}s")
        hints = {
            401: "the token is invalid or expired",
            403: "the token lacks permission (needs Contents: read & write)",
            404: f"repository {self.repo} not found or not accessible with this token",
        }
        detail = ""
        try:
            detail = resp.json().get("message", "")
        except ValueError:
            detail = resp.text[:200]
        hint = hints.get(resp.status_code, "")
        raise StoreError(f"GitHub API {method} {path} -> {resp.status_code} {detail}{'; ' + hint if hint else ''}")

    # ------------------------------------------------------------------ Store API

    def authorize(self) -> None:
        token = self.settings.token
        if self.settings.github_app:
            from netledger.storage.github_app import installation_token

            token = installation_token(self.settings, self.repo, session=self.session)
        self.session.headers["Authorization"] = f"Bearer {token}"

    def prepare(self) -> None:
        self.authorize()
        resp = self._request("GET", f"/git/ref/heads/{self.branch}", expected=(200, 404, 409))
        if resp.status_code == 409:
            self._initialize_empty_repo()
            resp = self._request("GET", f"/git/ref/heads/{self.branch}")
        elif resp.status_code == 404:
            self._create_branch()
            resp = self._request("GET", f"/git/ref/heads/{self.branch}")
        self._base_commit = self._head_commit = resp.json()["object"]["sha"]
        commit = self._request("GET", f"/git/commits/{self._head_commit}").json()
        self._head_tree = commit["tree"]["sha"]
        tree = self._request("GET", f"/git/trees/{self._head_tree}", params={"recursive": "1"}).json()
        if tree.get("truncated"):
            log.warning("repository tree is too large to list completely; unchanged files may be rewritten")
        self._index = {item["path"]: item["sha"] for item in tree.get("tree", []) if item.get("type") == "blob"}
        self._journal.clear()

    def _initialize_empty_repo(self) -> None:
        log.info("repository %s is empty; creating the initial commit", self.repo)
        content = f"# Network configuration backups\n\n{INIT_MARKER}\nManaged by NetLedger.\n"
        self._request(
            "PUT",
            "/contents/README.md",
            json={
                "message": "Initialize repository",
                "content": base64.b64encode(content.encode()).decode(),
                "branch": self.branch,
                "committer": {"name": self.settings.author_name, "email": self.settings.author_email},
            },
        )

    def _create_branch(self) -> None:
        repo = self._request("GET", "", expected=(200,)).json()
        default = repo.get("default_branch") or "main"
        ref = self._request("GET", f"/git/ref/heads/{default}").json()
        log.info("creating branch %s from %s", self.branch, default)
        self._request("POST", "/git/refs", json={"ref": f"refs/heads/{self.branch}", "sha": ref["object"]["sha"]})

    def read(self, path: str) -> str | None:
        sha = self._index.get(path)
        if not sha:
            return None
        if sha not in self._blob_cache:
            blob = self._request("GET", f"/git/blobs/{sha}").json()
            raw = base64.b64decode(blob.get("content", "")) if blob.get("encoding") == "base64" else blob.get("content", "").encode()
            self._blob_cache[sha] = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
        return self._blob_cache[sha]

    def versions(self, path: str, limit: int = 50) -> list[dict[str, Any]]:
        if "Authorization" not in self.session.headers:
            self.authorize()
        resp = self._request("GET", "/commits", params={"path": path, "sha": self.branch, "per_page": min(100, limit)})
        entries = []
        for item in resp.json()[:limit]:
            commit = item.get("commit") or {}
            author = commit.get("author") or {}
            message = commit.get("message") or ""
            entries.append({
                "sha": item.get("sha", ""), "author": author.get("name", ""), "date": author.get("date", ""),
                "subject": message.splitlines()[0] if message else "", "added": None, "removed": None,
            })
        return entries

    def show(self, rev: str, path: str) -> str | None:
        if "Authorization" not in self.session.headers:
            self.authorize()
        resp = self._request("GET", f"/contents/{quote(path)}", expected=(200, 404), params={"ref": rev})
        if resp.status_code == 404:
            return None
        data = resp.json()
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace").replace("\r\n", "\n")
        if data.get("sha"):  # files over 1 MB: fetch the blob
            blob = self._request("GET", f"/git/blobs/{data['sha']}").json()
            return base64.b64decode(blob.get("content", "")).decode("utf-8", errors="replace").replace("\r\n", "\n")
        return None

    def list_files(self, prefix: str) -> list[str]:
        prefix = prefix.rstrip("/") + "/"
        return sorted(p for p in self._index if p.startswith(prefix))

    def commit(self, changes: dict[str, str | None], message: str) -> str | None:
        entries = []
        new_shas: dict[str, str | None] = {}
        for path, content in changes.items():
            if content is None:
                if path in self._index:
                    entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
                    new_shas[path] = None
                continue
            data = content.encode("utf-8")
            sha = git_blob_sha(data)
            if self._index.get(path) == sha:
                continue
            created = self._request("POST", "/git/blobs", json={"content": base64.b64encode(data).decode(), "encoding": "base64"}).json()
            self._blob_cache[created["sha"]] = content
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": created["sha"]})
            new_shas[path] = created["sha"]
        if not entries:
            return None
        tree = self._request("POST", "/git/trees", json={"base_tree": self._head_tree, "tree": entries}).json()
        identity = {
            "name": self.settings.author_name,
            "email": self.settings.author_email,
            "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        commit = self._request(
            "POST",
            "/git/commits",
            json={"message": message, "tree": tree["sha"], "parents": [self._head_commit], "author": identity, "committer": identity},
        ).json()
        self._head_commit, self._head_tree = commit["sha"], tree["sha"]
        for path, sha in new_shas.items():
            if sha is None:
                self._index.pop(path, None)
            else:
                self._index[path] = sha
        self._journal.append((dict(changes), message))
        return commit["sha"]

    def publish(self) -> PublishResult:
        if not self._journal or self._head_commit == self._base_commit:
            return PublishResult(head=self._head_commit, message="nothing to push")
        if not self.settings.push:
            return PublishResult(commits=len(self._journal), head=self._head_commit, message="push disabled; commits not published")
        commits = len(self._journal)
        for attempt in range(1, 4):
            resp = self._request(
                "PATCH", f"/git/refs/heads/{self.branch}", expected=(200, 422), json={"sha": self._head_commit, "force": False}
            )
            if resp.status_code == 200:
                self._base_commit = self._head_commit
                self._journal.clear()
                return PublishResult(pushed=True, commits=commits, head=self._head_commit, message=f"pushed to {self.describe()}")
            if attempt == 3:
                break
            log.info("branch %s moved on the remote; replaying %d commit(s)", self.branch, commits)
            journal = list(self._journal)
            self.prepare()
            for changes, message in journal:
                self.commit(changes, message)
            if not self._journal:
                return PublishResult(head=self._head_commit, message="remote already up to date")
        raise StoreError(f"could not update {self.describe()}: branch kept moving")
