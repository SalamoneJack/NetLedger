"""Storage backends: where normalized configurations are committed."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlparse

if TYPE_CHECKING:
    from netledger.config import Settings


class StoreError(Exception):
    """Repository could not be prepared, committed to or published."""


@dataclass
class PublishResult:
    pushed: bool = False
    commits: int = 0
    head: str | None = None
    message: str = ""


def derive_web_url(url: str | None) -> str | None:
    """Browser URL of a repository from its clone URL (https or ssh)."""
    if not url:
        return None
    url = url.strip()
    if url.startswith(("http://", "https://")):
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if parsed.port and parsed.port not in (80, 443):
            host = f"{host}:{parsed.port}"
        path = parsed.path
    elif url.startswith("ssh://"):
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path
    else:
        match = re.match(r"^(?:[^@/]+@)?([^:/]+):(.+)$", url)
        if not match:
            return None
        host, path = match.group(1), "/" + match.group(2)
    path = re.sub(r"\.git/?$", "", path).rstrip("/")
    if not host or not path:
        return None
    return f"https://{host}{path}"


class WebLinks:
    """Builds links to files and commits on GitHub, GitLab and Bitbucket style hosts."""

    def __init__(self, web_url: str | None, branch: str):
        self.base = web_url.rstrip("/") if web_url else None
        self.branch = branch
        host = urlparse(self.base).hostname if self.base else ""
        self.style = "gitlab" if host and "gitlab" in host else "bitbucket" if host and "bitbucket" in host else "github"

    def file(self, path: str) -> str | None:
        if not self.base:
            return None
        path = quote(path)
        branch = quote(self.branch, safe="")
        if self.style == "gitlab":
            return f"{self.base}/-/blob/{branch}/{path}"
        if self.style == "bitbucket":
            return f"{self.base}/src/{branch}/{path}"
        return f"{self.base}/blob/{branch}/{path}"

    def tree(self, path: str) -> str | None:
        if not self.base:
            return None
        path = quote(path)
        branch = quote(self.branch, safe="")
        if self.style == "gitlab":
            return f"{self.base}/-/tree/{branch}/{path}"
        if self.style == "bitbucket":
            return f"{self.base}/src/{branch}/{path}"
        return f"{self.base}/tree/{branch}/{path}"

    def history(self, path: str) -> str | None:
        if not self.base:
            return None
        path = quote(path)
        branch = quote(self.branch, safe="")
        if self.style == "gitlab":
            return f"{self.base}/-/commits/{branch}/{path}"
        if self.style == "bitbucket":
            return f"{self.base}/history-node/{branch}/{path}"
        return f"{self.base}/commits/{branch}/{path}"

    def commit(self, sha: str) -> str | None:
        if not self.base:
            return None
        if self.style == "gitlab":
            return f"{self.base}/-/commit/{sha}"
        if self.style == "bitbucket":
            return f"{self.base}/commits/{sha}"
        return f"{self.base}/commit/{sha}"


class Store(ABC):
    """A place to commit files. Paths are POSIX-style and relative to the repository root."""

    links: WebLinks

    @abstractmethod
    def prepare(self) -> None:
        """Connect to / synchronize with the remote before a run."""

    @abstractmethod
    def read(self, path: str) -> str | None:
        """Current committed content of ``path`` (None if it does not exist)."""

    @abstractmethod
    def list_files(self, prefix: str) -> list[str]:
        """Files under directory ``prefix``."""

    @abstractmethod
    def commit(self, changes: dict[str, str | None], message: str) -> str | None:
        """Write/delete files and commit. ``None`` content deletes. Returns the commit id or None."""

    @abstractmethod
    def publish(self) -> PublishResult:
        """Push pending commits to the remote."""

    @abstractmethod
    def describe(self) -> str:
        """Human readable location, e.g. ``github.com/acme/net-configs@main``."""

    @property
    def local_path(self) -> Path | None:
        """Working directory for backends that keep a local clone."""
        return None

    def versions(self, path: str, limit: int = 50) -> list[dict[str, Any]]:
        """Commits that touched ``path``, newest first: sha, author, date, subject, added, removed."""
        raise NotImplementedError

    def show(self, rev: str, path: str) -> str | None:
        """Content of ``path`` at commit ``rev`` (None if it did not exist)."""
        raise NotImplementedError


def links_for(settings: Settings) -> WebLinks:
    """Repository links for the configured backend, without connecting to it."""
    git = settings.git
    web = git.web_url or derive_web_url(git.url)
    if not web and git.backend == "github" and git.repo:
        api = git.api_url.rstrip("/")
        web = f"https://github.com/{git.repo}" if api == "https://api.github.com" else f"{api.rsplit('/api', 1)[0]}/{git.repo}"
    return WebLinks(web, git.branch)


def create_store(settings: Settings) -> Store:
    git = settings.git
    if git.backend == "github":
        from netledger.storage.github import GitHubStore

        return GitHubStore(git)
    from netledger.storage.gitcli import GitCLIStore

    workdir = settings.resolve_path(git.workdir) if git.workdir else settings.data_path / "repo"
    return GitCLIStore(git, workdir)
