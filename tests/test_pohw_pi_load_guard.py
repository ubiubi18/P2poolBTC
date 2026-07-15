import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "pohw-install-pi-load-guard.sh"


class PiLoadGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = INSTALLER.read_text(encoding="utf-8")

    def test_observer_only_units_are_disabled_and_condition_gated(self) -> None:
        for unit in (
            "bitcoind-mainnet.service",
            "bitcoind-pohw-experiment-1.service",
            "pohw-fork-chain-node.service",
            "pohw-gossip-mesh.service",
            "pohw-mining-adapter.service",
        ):
            self.assertIn(unit, self.script)
        self.assertIn(
            '"$SYSTEMCTL_BIN" disable --now "${observer_only_units[@]}"',
            self.script,
        )
        self.assertIn("pohw-pi-observer-only.conf", self.script)
        self.assertIn("90-pi-observer-only.conf", self.script)
        self.assertIn('verify_inactive_units "${observer_only_units[@]}"', self.script)
        self.assertIn('"$SYSTEMCTL_BIN" reset-failed', self.script)

        gate_install = self.script.index("90-pi-observer-only.conf")
        reload_call = self.script.index('"$SYSTEMCTL_BIN" daemon-reload', gate_install)
        disable_call = self.script.index(
            '"$SYSTEMCTL_BIN" disable --now "${observer_only_units[@]}"',
            reload_call,
        )
        verify_call = self.script.rindex("verify_inactive_units ")
        success = self.script.index('echo "Pi load guard installed."')
        self.assertLess(gate_install, reload_call)
        self.assertLess(reload_call, disable_call)
        self.assertLess(disable_call, verify_call)
        self.assertLess(verify_call, success)

        dropin = (
            ROOT / "deploy" / "systemd" / "pohw-pi-observer-only.conf"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "ConditionPathExists=/etc/pohw/enable-pi-local-pohw-runtime", dropin
        )

    def test_all_local_launch_markers_are_removed(self) -> None:
        for marker in (
            "/etc/pohw/enable-local-bitcoin",
            "/etc/pohw/enable-experiment-0-fork",
            "/etc/pohw/enable-experiment-0-mining",
            "/etc/pohw/enable-experiment-1-mining",
            "/etc/pohw/enable-pi-local-pohw-runtime",
        ):
            self.assertIn(marker, self.script)

    def test_inactive_verifier_fails_closed_with_fake_systemctl(self) -> None:
        start = self.script.index("verify_inactive_units() {")
        end = self.script.index("\n}\n", start) + len("\n}\n")
        function = self.script[start:end]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            fake_systemctl = temp / "systemctl"
            fake_systemctl.write_text(
                """#!/bin/sh
set -eu
[ "$1" = show ] || exit 64
property=${2#--property=}
unit=$4
if [ "$unit" = queryfail.service ]; then
  exit 70
fi
if [ "$property" = LoadState ]; then
  if [ "$unit" = missing.service ]; then
    printf 'not-found\\n'
  elif [ "$unit" = empty.service ]; then
    :
  else
    printf 'loaded\\n'
  fi
elif [ "$property" = ActiveState ]; then
  case "$unit" in
    active.service) printf 'active\\n' ;;
    activating.service) printf 'activating\\n' ;;
    failed.service) printf 'failed\\n' ;;
    *) printf 'inactive\\n' ;;
  esac
else
  exit 65
fi
""",
                encoding="utf-8",
            )
            fake_systemctl.chmod(
                fake_systemctl.stat().st_mode | stat.S_IXUSR
            )
            harness = temp / "verify.sh"
            harness.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "SYSTEMCTL_BIN=$1\n"
                "shift\n"
                f"{function}\n"
                'verify_inactive_units "$@"\n',
                encoding="utf-8",
            )
            harness.chmod(harness.stat().st_mode | stat.S_IXUSR)

            clean = subprocess.run(
                [
                    str(harness),
                    str(fake_systemctl),
                    "inactive.service",
                    "missing.service",
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PATH": "/usr/bin:/bin"},
            )
            self.assertEqual(clean.returncode, 0, clean.stderr)

            for unsafe_state in (
                "active.service",
                "activating.service",
                "failed.service",
                "queryfail.service",
                "empty.service",
            ):
                with self.subTest(state=unsafe_state):
                    result = subprocess.run(
                        [str(harness), str(fake_systemctl), unsafe_state],
                        check=False,
                        capture_output=True,
                        text=True,
                        env={**os.environ, "PATH": "/usr/bin:/bin"},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{unsafe_state}=",
                        result.stderr,
                    )


if __name__ == "__main__":
    unittest.main()
