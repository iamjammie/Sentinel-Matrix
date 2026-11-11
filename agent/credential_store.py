"""
SENTINEL MATRIX — credential store.

Prefers the OS keyring (Windows Credential Manager / macOS Keychain / Secret Service) when the
optional `keyring` package is installed. Falls back to a restrictive-permission local file
(0600) ONLY if the operator opts in by providing a cred_path. Credentials are never logged.
"""
from __future__ import annotations
import os, json, stat, logging
from typing import Optional

LOG = logging.getLogger("sentinel-agent.creds")
SERVICE = "sentinel-matrix-agent"

class CredentialStore:
    def __init__(self, file_path: Optional[str] = None):
        self.file_path = file_path
        self._keyring = None
        try:
            import keyring  # type: ignore
            self._keyring = keyring
            LOG.info("credential store: OS keyring backend available")
        except Exception:
            if file_path:
                LOG.warning("credential store: keyring unavailable, using restricted file %s", file_path)
            else:
                LOG.info("credential store: no persistent backend (per-request tokens only)")

    def _key(self, platform: str, target: str) -> str:
        return f"{platform}:{target}"

    def get(self, platform: str, target: str) -> Optional[str]:
        k = self._key(platform, target)
        if self._keyring:
            try:
                return self._keyring.get_password(SERVICE, k)
            except Exception as e:  # pragma: no cover
                LOG.warning("keyring read failed: %s", type(e).__name__)
        if self.file_path and os.path.exists(self.file_path):
            data = self._read_file()
            return data.get(k)
        return None

    def save(self, platform: str, target: str, token: str) -> None:
        k = self._key(platform, target)
        if self._keyring:
            self._keyring.set_password(SERVICE, k, token)
            return
        if not self.file_path:
            raise RuntimeError("no credential backend configured; set cred_path in config.yaml to persist tokens")
        data = self._read_file()
        data[k] = token
        self._write_file(data)

    def remove(self, platform: str, target: str) -> None:
        k = self._key(platform, target)
        if self._keyring:
            try:
                self._keyring.delete_password(SERVICE, k)
            except Exception:
                pass
            return
        if self.file_path and os.path.exists(self.file_path):
            data = self._read_file()
            data.pop(k, None)
            self._write_file(data)

    def _read_file(self) -> dict:
        try:
            with open(self.file_path) as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_file(self, data: dict) -> None:
        tmp = self.file_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.file_path)
        try:
            os.chmod(self.file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except Exception:  # pragma: no cover (Windows)
            pass
