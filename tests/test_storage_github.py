"""GitHub REST backend against an in-memory fake of the Git Data API."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from netledger.config import GitSettings
from netledger.storage import StoreError
from netledger.storage.github import GitHubStore
from netledger.utils import git_blob_sha


class FakeResponse:
    def __init__(self, status: int, payload: Any = None, headers: dict[str, str] | None = None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.text = json.dumps(self._payload)

    def json(self) -> Any:
        return self._payload


class FakeGitHub:
    """Just enough of the GitHub Git Data API to exercise GitHubStore."""

    def __init__(self, empty: bool = False):
        self.headers: dict[str, str] = {}
        self.verify = True
        self.objects: dict[str, dict[str, Any]] = {}
        self.refs: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []
        if not empty:
            tree = self._tree({})
            self.refs["main"] = self._commit(tree, [], "init")

    def mount(self, *_: Any) -> None:
        pass

    def _sha(self, kind: str, body: Any) -> str:
        return hashlib.sha1(f"{kind}:{json.dumps(body, sort_keys=True)}".encode()).hexdigest()

    def _tree(self, files: dict[str, str]) -> str:
        sha = self._sha("tree", files)
        self.objects[sha] = {"type": "tree", "files": dict(files)}
        return sha

    def _commit(self, tree: str, parents: list[str], message: str) -> str:
        sha = self._sha("commit", [tree, parents, message])
        self.objects[sha] = {"type": "commit", "tree": tree, "parents": parents, "message": message}
        return sha

    def files_at(self, ref: str = "main") -> dict[str, str]:
        tree = self.objects[self.objects[self.refs[ref]]["tree"]]["files"]
        return {path: base64.b64decode(self.objects[sha]["content"]).decode() for path, sha in tree.items()}

    def request(self, method: str, url: str, json: Any = None, params: Any = None, timeout: Any = None) -> FakeResponse:  # noqa: A002
        path = url.split("/repos/acme/configs", 1)[1]
        self.calls.append((method, path))
        if method == "GET" and path.startswith("/git/ref/heads/"):
            branch = path.rsplit("/", 1)[1]
            if not self.refs:
                return FakeResponse(409, {"message": "Git Repository is empty."})
            if branch not in self.refs:
                return FakeResponse(404, {"message": "Not Found"})
            return FakeResponse(200, {"object": {"sha": self.refs[branch]}})
        if method == "PUT" and path == "/contents/README.md":
            blob = self._blob(json["content"])
            self.refs[json["branch"]] = self._commit(self._tree({"README.md": blob}), [], json["message"])
            return FakeResponse(201, {})
        if method == "GET" and path.startswith("/git/commits/"):
            obj = self.objects[path.rsplit("/", 1)[1]]
            return FakeResponse(200, {"tree": {"sha": obj["tree"]}})
        if method == "GET" and path.startswith("/git/trees/"):
            files = self.objects[path.rsplit("/", 1)[1]]["files"]
            return FakeResponse(200, {"tree": [{"path": p, "type": "blob", "sha": s} for p, s in files.items()], "truncated": False})
        if method == "GET" and path.startswith("/git/blobs/"):
            return FakeResponse(200, {"content": self.objects[path.rsplit("/", 1)[1]]["content"], "encoding": "base64"})
        if method == "POST" and path == "/git/blobs":
            return FakeResponse(201, {"sha": self._blob(json["content"])})
        if method == "POST" and path == "/git/trees":
            files = dict(self.objects[json["base_tree"]]["files"])
            for entry in json["tree"]:
                if entry["sha"] is None:
                    files.pop(entry["path"], None)
                else:
                    files[entry["path"]] = entry["sha"]
            return FakeResponse(201, {"sha": self._tree(files)})
        if method == "POST" and path == "/git/commits":
            return FakeResponse(201, {"sha": self._commit(json["tree"], json["parents"], json["message"])})
        if method == "PATCH" and path.startswith("/git/refs/heads/"):
            branch = path.rsplit("/", 1)[1]
            if self.refs.get(branch) not in self._ancestors(json["sha"]):
                return FakeResponse(422, {"message": "Update is not a fast forward"})
            self.refs[branch] = json["sha"]
            return FakeResponse(200, {})
        if method == "GET" and path == "":
            return FakeResponse(200, {"default_branch": "main"})
        if method == "POST" and path == "/git/refs":
            self.refs[json["ref"].split("/")[-1]] = json["sha"]
            return FakeResponse(201, {})
        return FakeResponse(404, {"message": f"unhandled {method} {path}"})

    def _ancestors(self, sha: str) -> set[str]:
        seen: set[str] = set()
        stack = list(self.objects[sha]["parents"])
        while stack:
            current = stack.pop()
            if current not in seen:
                seen.add(current)
                stack.extend(self.objects[current]["parents"])
        return seen

    def _blob(self, content_b64: str) -> str:
        data = base64.b64decode(content_b64)
        sha = git_blob_sha(data)
        self.objects[sha] = {"type": "blob", "content": content_b64}
        return sha


def store(fake: FakeGitHub, branch: str = "main") -> GitHubStore:
    settings = GitSettings(backend="github", repo="acme/configs", token="t", branch=branch)
    return GitHubStore(settings, session=fake)  # type: ignore[arg-type]


def test_commit_read_publish_and_skip_unchanged() -> None:
    fake = FakeGitHub()
    s = store(fake)
    s.prepare()
    assert fake.headers["Authorization"] == "Bearer t"
    sha1 = s.commit({"configs/a/running-config.cfg": "hostname a\n", "configs/a/device.json": "{}\n"}, "a: initial backup")
    assert sha1 and s.read("configs/a/running-config.cfg") == "hostname a\n"
    blobs_before = sum(1 for m, p in fake.calls if p == "/git/blobs")
    assert s.commit({"configs/a/running-config.cfg": "hostname a\n"}, "noop") is None
    assert sum(1 for m, p in fake.calls if p == "/git/blobs") == blobs_before  # unchanged file: no upload
    s.commit({"configs/a/running-config.cfg": "hostname a2\n", "configs/a/device.json": None}, "a: changed")
    result = s.publish()
    assert result.pushed and result.commits == 2
    assert fake.files_at() == {"configs/a/running-config.cfg": "hostname a2\n"}
    assert s.list_files("configs/a") == ["configs/a/running-config.cfg"]
    assert s.links.file("configs/a/running-config.cfg") == "https://github.com/acme/configs/blob/main/configs/a/running-config.cfg"


def test_empty_repository_is_initialized() -> None:
    fake = FakeGitHub(empty=True)
    s = store(fake)
    s.prepare()
    assert "README.md" in fake.files_at()
    s.commit({"x.txt": "1\n"}, "x")
    assert s.publish().pushed
    assert fake.files_at()["x.txt"] == "1\n"


def test_missing_branch_is_created_from_default() -> None:
    fake = FakeGitHub()
    s = store(fake, branch="backups")
    s.prepare()
    assert "backups" in fake.refs


def test_replay_when_branch_moves() -> None:
    fake = FakeGitHub()
    s = store(fake)
    s.prepare()
    s.commit({"configs/a/running-config.cfg": "v1\n"}, "a")
    # somebody else commits meanwhile
    other = store(fake)
    other.prepare()
    other.commit({"NOTES.md": "hi\n"}, "human")
    other.publish()
    result = s.publish()
    assert result.pushed
    assert fake.files_at() == {"NOTES.md": "hi\n", "configs/a/running-config.cfg": "v1\n"}


def test_api_errors_are_explained() -> None:
    class Denied(FakeGitHub):
        def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
            return FakeResponse(401, {"message": "Bad credentials"})

    with pytest.raises(StoreError, match="401 Bad credentials; the token is invalid or expired"):
        store(Denied()).prepare()


def test_github_app_jwt_and_installation_token() -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    from netledger.config import GitHubAppSettings
    from netledger.storage.github_app import app_jwt, installation_token

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    token = app_jwt(123456, pem, now=1_700_000_000)
    header, payload, signature = token.split(".")

    def b64(part: str) -> bytes:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

    assert json.loads(b64(header)) == {"alg": "RS256", "typ": "JWT"}
    assert json.loads(b64(payload)) == {"iat": 1_699_999_940, "exp": 1_700_000_480, "iss": "123456"}
    key.public_key().verify(b64(signature), f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())

    calls: list[tuple[str, str]] = []

    class Session:
        def get(self, url: str, headers: dict[str, str], timeout: int) -> FakeResponse:
            calls.append(("GET", url))
            assert headers["Authorization"].startswith("Bearer ey")
            return FakeResponse(200, {"id": 42})

        def post(self, url: str, headers: dict[str, str], timeout: int) -> FakeResponse:
            calls.append(("POST", url))
            return FakeResponse(201, {"token": "ghs_installation"})

    settings = GitSettings(backend="github", repo="acme/configs", github_app=GitHubAppSettings(app_id=123456, private_key=pem))
    assert installation_token(settings, "acme/configs", session=Session()) == "ghs_installation"  # type: ignore[arg-type]
    assert calls == [
        ("GET", "https://api.github.com/repos/acme/configs/installation"),
        ("POST", "https://api.github.com/app/installations/42/access_tokens"),
    ]
    with pytest.raises(StoreError, match="not a valid PEM"):
        app_jwt(1, "not a key")
