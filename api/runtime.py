from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

MIN_NODE22 = (22, 0, 0)
MAX_NODE22 = (23, 0, 0)
REJECTED_NODE_MAJOR = 24


@dataclass(frozen=True)
class LighthouseRuntime:
    node_executable: str
    node_version: str
    lighthouse_entry: str
    lighthouse_version: str
    chrome_path: str | None
    chrome_version: str | None
    source: str


class RuntimeManager:
    def __init__(self, project_root: str | Path | None = None) -> None:
        self.project_root = Path(project_root or os.environ.get("BEACON_PROJECT_ROOT") or Path.cwd()).resolve()
        self.beacon_root = Path(os.environ.get("BEACON_HOME") or "/tmp/beacon").resolve()
        self.runtime_root = self.beacon_root / "runtime"
        self.node_root = self.runtime_root / "node22"
        self.temp_root = Path(os.environ.get("BEACON_TEMP") or self.beacon_root / "temp").resolve()
        self.cache_root = self.beacon_root / "cache"

    def ensure_layout(self) -> None:
        for path in [self.beacon_root, self.runtime_root, self.node_root, self.temp_root, self.cache_root]:
            path.mkdir(parents=True, exist_ok=True)

    def lighthouse_runtime(self) -> LighthouseRuntime | None:
        self.ensure_layout()
        for node_path, source in self._node_candidates():
            version = self.node_version(node_path)
            if not version:
                continue
            if self._node_major(version) == REJECTED_NODE_MAJOR:
                logger.info("Rejecting Node %s for Lighthouse runtime: %s", version, node_path)
                continue
            if not self._is_node22(version):
                continue
            lighthouse_entry = self._lighthouse_entry(node_path)
            if not lighthouse_entry:
                continue
            chrome_path = self.chrome_path()
            return LighthouseRuntime(
                node_executable=str(node_path),
                node_version=version,
                lighthouse_entry=str(lighthouse_entry),
                lighthouse_version=self.lighthouse_version(node_path, lighthouse_entry) or "Verification Failed",
                chrome_path=str(chrome_path) if chrome_path else None,
                chrome_version=self.chrome_version(chrome_path) if chrome_path else None,
                source=source,
            )
        return None

    def lighthouse_command(self) -> list[str] | None:
        runtime = self.lighthouse_runtime()
        if not runtime:
            return None
        return [runtime.node_executable, runtime.lighthouse_entry]

    def lighthouse_environment(self, chrome_path: str | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env["BEACON_HOME"] = str(self.beacon_root)
        env["BEACON_TEMP"] = str(self.temp_root)
        env["npm_config_cache"] = str(self.cache_root / "npm")
        if chrome_path:
            env["CHROME_PATH"] = chrome_path
        return env

    def temp_dir(self, prefix: str) -> Path:
        self.ensure_layout()
        import tempfile

        return Path(tempfile.mkdtemp(prefix=prefix, dir=self.temp_root))

    def _node_candidates(self) -> list[tuple[Path, str]]:
        candidates: list[tuple[Path, str]] = []
        for relative in [Path("node.exe"), Path("nodejs") / "node.exe", Path("bin") / "node.exe"]:
            path = self.node_root / relative
            if path.exists():
                candidates.append((path, "Beacon bundled runtime"))
        for path in self._which_all("node"):
            candidates.append((path, "System Node"))

        seen: set[str] = set()
        unique: list[tuple[Path, str]] = []
        for path, source in candidates:
            key = str(path).lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append((path, source))
        return unique

    def _lighthouse_entry(self, node_path: Path) -> Path | None:
        candidates = [
            self.runtime_root / "node_modules" / "lighthouse" / "cli" / "index.js",
            self.project_root / "node_modules" / "lighthouse" / "cli" / "index.js",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        script = (
            "try {"
            " const {createRequire}=require('module');"
            f" const req=createRequire({json.dumps(str(self.project_root / 'package.json'))});"
            " console.log(req.resolve('lighthouse/cli/index.js'));"
            "} catch (e) { process.exit(1); }"
        )
        result = self._run([str(node_path), "-e", script], timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            path = Path(result.stdout.strip())
            if path.exists():
                return path
        return None

    def chrome_path(self) -> Path | None:
        env_path = os.environ.get("CHROME_PATH")
        if env_path and Path(env_path).exists():
            return Path(env_path)
        for executable in ["chromium", "chromium-browser", "google-chrome", "chrome"]:
            path = shutil.which(executable)
            if path:
                return Path(path)
        return None

    def chrome_version(self, chrome_path: Path | None = None) -> str | None:
        path = chrome_path or self.chrome_path()
        if not path:
            return None
        result = self._run([str(path), "--version"])
        return result.stdout.strip() or None

    def node_version(self, node_path: Path) -> str | None:
        result = self._run([str(node_path), "--version"])
        return result.stdout.strip() if result.returncode == 0 else None

    def lighthouse_version(self, node_path: Path, lighthouse_entry: str | Path) -> str | None:
        package_json = Path(lighthouse_entry).parents[1] / "package.json"
        if package_json.exists():
            try:
                return json.loads(package_json.read_text(encoding="utf-8")).get("version")
            except (OSError, json.JSONDecodeError):
                pass
        result = self._run([str(node_path), str(lighthouse_entry), "--version"], timeout=15)
        return result.stdout.strip() if result.returncode == 0 else None

    def _run(self, command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(command, 1, "", str(exc))

    def _which_all(self, executable: str) -> list[Path]:
        result = self._run(["which", "-a", executable]) if os.name != "nt" else self._run(["where.exe", executable])
        if result.returncode != 0:
            return []
        return [Path(line.strip()) for line in result.stdout.splitlines() if line.strip()]

    def _is_node22(self, version: str) -> bool:
        parsed = self._parse_version(version)
        return MIN_NODE22 <= parsed < MAX_NODE22

    def _node_major(self, version: str) -> int | None:
        parsed = self._parse_version(version)
        return parsed[0] if parsed else None

    def _parse_version(self, version: str) -> tuple[int, int, int]:
        clean = version.strip().lstrip("v")
        parts = clean.split(".")
        try:
            return int(parts[0]), int(parts[1]), int(parts[2])
        except (IndexError, ValueError):
            return 0, 0, 0