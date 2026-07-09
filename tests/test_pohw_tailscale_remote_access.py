import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "pohw-install-tailscale-remote-access.sh"


class TailscaleRemoteAccessTest(unittest.TestCase):
    def write_fake_tailscale(self, root: Path, *, backend_state: str = "NeedsLogin") -> Path:
        (root / "tailscale.state").write_text(backend_state, encoding="utf-8")
        fake = root / "tailscale"
        fake.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$POHW_FAKE_TAILSCALE_LOG"
state_file="$POHW_FAKE_TAILSCALE_STATE"
state="$(cat "$state_file")"
case "${1:-}" in
  status)
    if [[ "$state" == "Running" ]]; then
      printf '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.42"]}}\\n'
    else
      printf '{"BackendState":"NeedsLogin","Self":{"TailscaleIPs":[]}}\\n'
    fi
    exit 0
    ;;
  up)
    printf 'Running\\n' > "$state_file"
    ;;
  set)
    exit 0
    ;;
  ip)
    if [[ "$state" == "Running" ]]; then
      printf '100.64.0.42\\n'
    fi
    ;;
esac
exit 0
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def write_fake_systemctl(self, root: Path) -> Path:
        fake = root / "systemctl"
        fake.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$POHW_FAKE_SYSTEMCTL_LOG"
exit 0
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def write_fake_ufw(self, root: Path) -> Path:
        fake = root / "ufw"
        fake.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$POHW_FAKE_UFW_LOG"
exit 0
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def run_installer(
        self,
        root: Path,
        authkey_file: Optional[Path],
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(
            {
                "POHW_TAILSCALE_BIN": str(root / "tailscale"),
                "POHW_TAILSCALE_SYSTEMCTL_BIN": str(root / "systemctl"),
                "POHW_TAILSCALE_UFW_BIN": str(root / "ufw"),
                "POHW_TAILSCALE_SKIP_ROOT_CHECK": "true",
                "POHW_TAILSCALE_INSTALL_IF_MISSING": "false",
                "POHW_TAILSCALE_HOSTNAME": "pibtc",
                "POHW_TAILSCALE_SSH_USER": "ubuntu",
                "POHW_FAKE_TAILSCALE_STATE": str(root / "tailscale.state"),
                "POHW_FAKE_TAILSCALE_LOG": str(root / "tailscale.log"),
                "POHW_FAKE_SYSTEMCTL_LOG": str(root / "systemctl.log"),
                "POHW_FAKE_UFW_LOG": str(root / "ufw.log"),
            }
        )
        if authkey_file is not None:
            env["POHW_TAILSCALE_AUTHKEY_FILE"] = str(authkey_file)
        return subprocess.run(
            ["bash", str(INSTALLER)],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_configures_tailscale_with_authkey_file_without_printing_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-tailscale-ok-") as temp:
            root = Path(temp)
            self.write_fake_tailscale(root)
            self.write_fake_systemctl(root)
            self.write_fake_ufw(root)
            authkey = root / "tailscale.authkey"
            authkey.write_text("tskey-auth-test-only\n", encoding="utf-8")
            authkey.chmod(0o600)

            result = self.run_installer(root, authkey)
            tailscale_log = (root / "tailscale.log").read_text(encoding="utf-8")
            systemctl_log = (root / "systemctl.log").read_text(encoding="utf-8")
            ufw_log = (root / "ufw.log").read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("enable --now tailscaled", systemctl_log)
        self.assertIn(
            "allow in on tailscale0 to any port 22 proto tcp comment SSH over Tailscale",
            ufw_log,
        )
        self.assertIn("up --hostname=pibtc --accept-dns=false --accept-routes=false", tailscale_log)
        self.assertIn("--auth-key=file:", tailscale_log)
        self.assertIn("set --ssh", tailscale_log)
        self.assertNotIn("tskey-auth-test-only", result.stdout)
        self.assertNotIn("tskey-auth-test-only", result.stderr)

    def test_needs_login_json_status_without_authkey_fails_before_up(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-tailscale-needs-login-") as temp:
            root = Path(temp)
            self.write_fake_tailscale(root, backend_state="NeedsLogin")
            self.write_fake_systemctl(root)
            self.write_fake_ufw(root)

            result = self.run_installer(root, authkey_file=None)
            tailscale_log = (root / "tailscale.log").read_text(encoding="utf-8")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Tailscale is not authenticated yet.", result.stdout)
        self.assertIn("POHW_TAILSCALE_AUTHKEY_FILE", result.stderr)
        self.assertNotIn("up --hostname", tailscale_log)
        self.assertNotIn("set --ssh", tailscale_log)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_rejects_permissive_authkey_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-tailscale-bad-mode-") as temp:
            root = Path(temp)
            self.write_fake_tailscale(root)
            self.write_fake_systemctl(root)
            self.write_fake_ufw(root)
            authkey = root / "tailscale.authkey"
            authkey.write_text("tskey-auth-test-only\n", encoding="utf-8")
            authkey.chmod(0o644)

            result = self.run_installer(root, authkey)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("too permissive", result.stderr)


if __name__ == "__main__":
    unittest.main()
