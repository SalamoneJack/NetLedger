"""Git backend using the ``git`` executable (GitHub, GitLab, Gitea, Bitbucket, Azure DevOps, ...)."""

from __future__ import annotations

import base64
import logging
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from netledger.config import GitSettings
from netledger.storage import PublishResult, Store, StoreError, WebLinks, derive_web_url

log = logging.getLogger(__name__)


class GitCLIStore(Store):
    def __init__(self, settings: GitSettings, workdir: Path):
        self.settings = settings
        self.path = Path(workdir)
        self.branch = settings.branch
        self.remote = settings.url if settings.backend == "git" else None
        self.links = WebLinks(settings.web_url or derive_web_url(self.remote), self.branch)
        self._journal: list[tuple[dict[str, str | None], str]] = []
        self._token: str | None = settings.token
        self._env: dict[str, str] | None = None

    # ------------------------------------------------------------------ plumbing

    @property
    def local_path(self) -> Path:
        return self.path

    def describe(self) -> str:
        if self.remote:
            parsed = derive_web_url(self.remote) or self.remote
            return f"{parsed.replace('https://', '')}@{self.branch}"
        return f"{self.path} (local)@{self.branch}"

    def _build_env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG"))}
        s = self.settings
        root = self.path.resolve()
        env.update({
            # Pin git to this repository: never discover a parent repository by walking up.
            "GIT_DIR": str(root / ".git"),
            "GIT_WORK_TREE": str(root),
            "GIT_CEILING_DIRECTORIES": str(root.parent),
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_AUTHOR_NAME": s.author_name,
            "GIT_AUTHOR_EMAIL": s.author_email,
            "GIT_COMMITTER_NAME": s.author_name,
            "GIT_COMMITTER_EMAIL": s.author_email,
            "LC_ALL": "C",
            "LANGUAGE": "C",
        })
        config: list[tuple[str, str]] = [
            ("credential.helper", ""),
            ("core.autocrlf", "false"),
            ("core.safecrlf", "false"),
            ("core.quotepath", "false"),
            ("init.defaultBranch", self.branch),
            ("safe.directory", str(self.path.resolve()).replace("\\", "/")),
        ]
        if not s.sign_commits:
            config.append(("commit.gpgsign", "false"))
        if not s.verify_ssl:
            config.append(("http.sslVerify", "false"))
        if self.remote and self.remote.startswith(("http://", "https://")) and self._token:
            parsed = urlparse(self.remote)
            scope = f"{parsed.scheme}://{parsed.netloc.split('@')[-1]}/"
            basic = base64.b64encode(f"{s.username}:{self._token}".encode()).decode()
            config.append((f"http.{scope}.extraHeader", f"Authorization: Basic {basic}"))
        env["GIT_CONFIG_COUNT"] = str(len(config))
        for index, (key, value) in enumerate(config):
            env[f"GIT_CONFIG_KEY_{index}"] = key
            env[f"GIT_CONFIG_VALUE_{index}"] = value
        if s.ssh_key:
            key = str(Path(os.path.expanduser(s.ssh_key))).replace("\\", "/")
            command = f'ssh -i "{key}" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new'
            if s.ssh_known_hosts:
                known = str(Path(os.path.expanduser(s.ssh_known_hosts))).replace("\\", "/")
                command += f' -o UserKnownHostsFile="{known}"'
            env["GIT_SSH_COMMAND"] = command
        return env

    def _git(self, *args: str, check: bool = True, input_text: str | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        if self._env is None:
            self._env = self._build_env()
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=str(cwd or self.path),
                env=self._env,
                input=input_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
            )
        except FileNotFoundError:
            raise StoreError("the 'git' executable was not found; install Git or use git.backend: github") from None
        except subprocess.TimeoutExpired:
            raise StoreError(f"git {args[0]} timed out") from None
        if check and result.returncode != 0:
            raise StoreError(f"git {' '.join(args[:2])} failed: {self._redact(result.stderr.strip() or result.stdout.strip())}")
        return result

    def _redact(self, text: str) -> str:
        if self._token:
            text = text.replace(self._token, "***")
        return text

    def _ref_exists(self, ref: str) -> bool:
        return self._git("rev-parse", "--verify", "--quiet", ref, check=False).returncode == 0

    # ------------------------------------------------------------------ Store API

    def prepare(self) -> None:
        if shutil.which("git") is None:
            raise StoreError("the 'git' executable was not found; install Git or use git.backend: github")
        if self.settings.github_app and not self._token:
            from netledger.storage.github_app import installation_token

            repo = self.settings.repo or _repo_from_url(self.remote)
            self._token = installation_token(self.settings, repo)
            self._env = None
        self.path.mkdir(parents=True, exist_ok=True)
        if (self.path / ".git").exists() and self._git("rev-parse", "--git-dir", check=False).returncode != 0:
            if not self.remote:
                raise StoreError(f"{self.path} contains a damaged Git repository; repair or move it (local backend has no remote copy)")
            broken = self.path.with_name(f"{self.path.name}.broken-{int(time.time())}")
            log.warning("working copy %s is damaged; moving it to %s and cloning again", self.path, broken)
            self.path.rename(broken)
            self.path.mkdir(parents=True)
        if not (self.path / ".git").exists():
            self._git("init", "-q")
            self._git("symbolic-ref", "HEAD", f"refs/heads/{self.branch}")
        for key, value in (("core.autocrlf", "false"), ("core.quotepath", "false")):
            self._git("config", key, value)
        if self.remote:
            remotes = self._git("remote").stdout.split()
            if "origin" in remotes:
                self._git("remote", "set-url", "origin", self.remote)
            else:
                self._git("remote", "add", "origin", self.remote)
            fetched = self._fetch()
        else:
            fetched = False
        local = self._ref_exists(f"refs/heads/{self.branch}")
        if fetched:
            if not local:
                self._git("checkout", "-q", "-f", "-B", self.branch, f"origin/{self.branch}")
            else:
                self._git("checkout", "-q", "-f", self.branch)
                ahead = int(self._git("rev-list", "--count", f"origin/{self.branch}..{self.branch}").stdout.strip() or 0)
                if ahead:
                    if self._git("rebase", "-q", f"origin/{self.branch}", check=False).returncode != 0:
                        self._git("rebase", "--abort", check=False)
                        log.warning("discarding %d unpublished local commit(s) that conflict with the remote", ahead)
                        self._git("reset", "-q", "--hard", f"origin/{self.branch}")
                else:
                    self._git("reset", "-q", "--hard", f"origin/{self.branch}")
        elif local:
            self._git("checkout", "-q", "-f", self.branch)
        else:
            self._git("symbolic-ref", "HEAD", f"refs/heads/{self.branch}")
        if self._ref_exists("HEAD"):
            self._git("reset", "-q", "--hard")
        self._git("clean", "-q", "-fd")
        self._journal.clear()

    def _fetch(self) -> bool:
        result = self._git("fetch", "-q", "--prune", "origin", f"+refs/heads/{self.branch}:refs/remotes/origin/{self.branch}", check=False)
        if result.returncode == 0:
            return True
        stderr = result.stderr.lower()
        if "couldn't find remote ref" in stderr or "could not find remote ref" in stderr:
            log.info("remote branch %s does not exist yet; it will be created on first push", self.branch)
            return False
        raise StoreError(f"cannot fetch {self.describe()}: {self._redact(result.stderr.strip())}")

    def read(self, path: str) -> str | None:
        target = self.path / path
        if not target.is_file():
            return None
        return target.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")

    def list_files(self, prefix: str) -> list[str]:
        base = self.path / prefix
        if not base.is_dir():
            return []
        files = []
        for item in base.rglob("*"):
            if item.is_file() and ".git" not in item.relative_to(self.path).parts:
                files.append(item.relative_to(self.path).as_posix())
        return sorted(files)

    def _write(self, changes: dict[str, str | None]) -> None:
        for rel, content in changes.items():
            target = self.path / rel
            if content is None:
                if target.exists():
                    target.unlink()
                    parent = target.parent
                    while parent != self.path and parent.is_dir() and not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(content)

    def _commit_written(self, paths: list[str], message: str) -> str | None:
        if len(paths) > 200:
            self._git("add", "-A")
        else:
            self._git("add", "-A", "--", *paths)
        if self._git("diff", "--cached", "--quiet", check=False).returncode == 0:
            return None
        self._git("commit", "-q", "-F", "-", input_text=message)
        return self._git("rev-parse", "HEAD").stdout.strip()

    def commit(self, changes: dict[str, str | None], message: str) -> str | None:
        if not changes:
            return None
        self._write(changes)
        sha = self._commit_written(list(changes), message)
        if sha:
            self._journal.append((dict(changes), message))
        return sha

    def _unpublished(self) -> int:
        if not self._ref_exists("HEAD"):
            return 0
        if self._ref_exists(f"refs/remotes/origin/{self.branch}"):
            return int(self._git("rev-list", "--count", f"refs/remotes/origin/{self.branch}..HEAD").stdout.strip() or 0)
        return int(self._git("rev-list", "--count", "HEAD").stdout.strip() or 0)

    def publish(self) -> PublishResult:
        if not self.remote or not self.settings.push:
            commits = len(self._journal)
            return PublishResult(pushed=False, commits=commits, head=self._head(), message="committed locally" if commits else "no changes")
        commits = self._unpublished()
        if not commits:
            return PublishResult(head=self._head(), message="nothing to push")
        for attempt in range(1, 4):
            result = self._git("push", "-q", "origin", f"HEAD:refs/heads/{self.branch}", check=False)
            if result.returncode == 0:
                self._git("update-ref", f"refs/remotes/origin/{self.branch}", "HEAD", check=False)
                self._journal.clear()
                return PublishResult(pushed=True, commits=commits, head=self._head(), message=f"pushed to {self.describe()}")
            stderr = result.stderr.lower()
            if attempt < 3 and any(word in stderr for word in ("rejected", "non-fast-forward", "fetch first", "stale info")):
                log.info("push rejected (remote moved); replaying %d commit(s) on top of the remote", commits)
                self._replay()
                continue
            raise StoreError(f"git push to {self.describe()} failed: {self._redact(result.stderr.strip())}")
        raise StoreError(f"git push to {self.describe()} kept getting rejected")

    def _replay(self) -> None:
        if not self._fetch():
            return
        journal = list(self._journal)
        self._git("reset", "-q", "--hard", f"origin/{self.branch}")
        self._journal.clear()
        for changes, message in journal:
            self._write(changes)
            if self._commit_written(list(changes), message):
                self._journal.append((changes, message))

    def _head(self) -> str | None:
        result = self._git("rev-parse", "HEAD", check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    def versions(self, path: str, limit: int = 50) -> list[dict[str, Any]]:
        if not (self.path / ".git").exists() or not self._ref_exists("HEAD"):
            return []
        raw = self._git("log", f"-n{limit}", "--format=%x1e%H%x1f%an%x1f%aI%x1f%s", "--numstat", "--", path).stdout
        entries: list[dict[str, Any]] = []
        for record in raw.split("\x1e"):
            lines = record.strip("\n").splitlines()
            if not lines:
                continue
            sha, author, date, subject = (lines[0].split("\x1f") + ["", "", "", ""])[:4]
            added = removed = 0
            for numstat in lines[1:]:
                parts = numstat.split("\t")
                if len(parts) == 3 and parts[2] == path:
                    added = int(parts[0]) if parts[0].isdigit() else 0
                    removed = int(parts[1]) if parts[1].isdigit() else 0
            entries.append({"sha": sha, "author": author, "date": date, "subject": subject, "added": added, "removed": removed})
        return entries

    def show(self, rev: str, path: str) -> str | None:
        if not (self.path / ".git").exists():
            return None
        result = self._git("show", f"{rev}:{path}", check=False)
        return result.stdout.replace("\r\n", "\n") if result.returncode == 0 else None

    def log(self, path: str | None = None, limit: int = 20) -> list[dict[str, str]]:
        """Recent commits (optionally for a path) from the local clone."""
        if not self._ref_exists("HEAD"):
            return []
        args = ["log", f"-n{limit}", "--format=%H%x1f%an%x1f%aI%x1f%s"]
        if path:
            args += ["--", path]
        entries = []
        for line in self._git(*args).stdout.splitlines():
            sha, author, date, subject = (line.split("\x1f") + ["", "", "", ""])[:4]
            entries.append({"sha": sha, "author": author, "date": date, "subject": subject})
        return entries


def remove_tree(path: Path) -> None:
    """``shutil.rmtree`` that also removes read-only files (git objects on Windows)."""

    def on_error(func, target, _exc):  # noqa: ANN001
        os.chmod(target, stat.S_IWRITE)
        func(target)

    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=on_error)
    else:
        shutil.rmtree(path, onerror=on_error)


def _repo_from_url(url: str | None) -> str:
    from netledger.storage import derive_web_url

    web = derive_web_url(url) or ""
    parts = web.rstrip("/").split("/")
    if len(parts) < 2:
        raise StoreError("cannot determine owner/repo from git.url; set git.repo")
    return f"{parts[-2]}/{parts[-1]}"
