import json
import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "scripts" / "pohw-host-firewall.py"
BOOT_UNIT = REPO_ROOT / "deploy" / "systemd" / "pohw-host-firewall.service"
CONFIG_EXAMPLE = (
    REPO_ROOT / "deploy" / "nftables" / "pohw-host-firewall.json.example"
)
ACK = "I_UNDERSTAND_THIS_REPLACES_THE_POHW_FIREWALL_TABLE"

SPEC = importlib.util.spec_from_file_location("pohw_host_firewall", TOOL)
assert SPEC is not None and SPEC.loader is not None
FIREWALL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FIREWALL
SPEC.loader.exec_module(FIREWALL)


class HostFirewallTest(unittest.TestCase):
    def write_executable(self, path: Path, content: str) -> Path:
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
        path.chmod(0o700)
        return path

    def setup_fake_tools(self, root: Path) -> tuple[Path, Path, dict[str, str]]:
        nft = self.write_executable(
            root / "nft",
            r"""
            #!/usr/bin/env python3
            import json
            import os
            import pathlib
            import sys

            state_path = pathlib.Path(os.environ["FAKE_NFT_STATE"])
            log_path = pathlib.Path(os.environ["FAKE_NFT_LOG"])
            state = json.loads(state_path.read_text()) if state_path.exists() else {
                "installed": False,
                "ruleset": "",
            }
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(sys.argv[1:]) + "\n")

            if sys.argv[1:5] == ["--json", "--numeric", "list", "tables"]:
                tables = []
                if state["installed"]:
                    tables.append({"table": {
                        "family": "inet", "name": "pohw_host_firewall"
                    }})
                print(json.dumps({"nftables": tables}))
                raise SystemExit(0)

            if sys.argv[1:5] == ["--json", "--numeric", "list", "table"]:
                if not state["installed"]:
                    raise SystemExit(1)
                ports = json.loads(os.environ.get("FAKE_EXPECTED_PORTS", "{}"))
                comments = {
                    "pohw:accept-loopback": ["iifname", "lo", "accept"],
                    "pohw:accept-tailscale": ["iifname", "tailscale0", "accept"],
                    "pohw:drop-invalid": ["state", "invalid", "drop"],
                    "pohw:accept-established-related": [
                        "state", "established", "related", "accept"
                    ],
                    "pohw:accept-icmp": ["icmp", "accept"],
                    "pohw:accept-icmpv6": ["ipv6-icmp", "accept"],
                    "pohw:drop-all-other-input": ["drop"],
                }
                if ports["ssh"]:
                    comments["pohw:accept-ssh"] = [
                        "tcp", "dport", "accept", *map(str, ports["ssh"])
                    ]
                if ports["p2p"]:
                    comments["pohw:accept-public-p2p"] = [
                        "tcp", "dport", "accept", *map(str, ports["p2p"])
                    ]
                entries = [
                    {"chain": {
                        "family": "inet",
                        "table": "pohw_host_firewall",
                        "name": "input",
                        "type": "filter",
                        "hook": "input",
                        "prio": -10,
                        "policy": "drop",
                    }}
                ]
                for comment, tokens in comments.items():
                    expressions = list(tokens)
                    if comment in {
                        "pohw:accept-ssh", "pohw:accept-public-p2p"
                    }:
                        port_values = [int(value) for value in tokens if value.isdigit()]
                        if (
                            comment == "pohw:accept-ssh"
                            and os.environ.get("FAKE_NFT_EXTRA_SSH_PORT")
                        ):
                            port_values.append(int(os.environ["FAKE_NFT_EXTRA_SSH_PORT"]))
                        expressions.insert(0, {"match": {
                            "left": {"payload": {
                                "protocol": "tcp", "field": "dport"
                            }},
                            "right": {"set": port_values},
                        }})
                    entries.append({"rule": {
                        "family": "inet",
                        "table": "pohw_host_firewall",
                        "chain": "input",
                        "comment": comment,
                        "expr": expressions,
                    }})
                print(json.dumps({"nftables": entries}))
                raise SystemExit(0)

            if len(sys.argv) == 4 and sys.argv[1:3] == ["--check", "--file"]:
                if os.environ.get("FAKE_NFT_FAIL_CHECK") == "true":
                    raise SystemExit(1)
                pathlib.Path(os.environ["FAKE_NFT_CHECKED"]).write_text(
                    pathlib.Path(sys.argv[3]).read_text(), encoding="utf-8"
                )
                raise SystemExit(0)

            if len(sys.argv) == 3 and sys.argv[1] == "--file":
                ruleset = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
                state["installed"] = True
                state["ruleset"] = ruleset
                state_path.write_text(json.dumps(state), encoding="utf-8")
                raise SystemExit(0)

            raise SystemExit(64)
            """,
        )
        ss = self.write_executable(
            root / "ss",
            r"""
            #!/usr/bin/env python3
            import os
            import sys

            if os.environ.get("FAKE_SS_FAIL") == "true":
                raise SystemExit(1)
            sys.stdout.write(os.environ.get("FAKE_SS_OUTPUT", ""))
            """,
        )
        env = dict(os.environ)
        env.update(
            {
                "FAKE_NFT_STATE": str(root / "nft-state.json"),
                "FAKE_NFT_LOG": str(root / "nft.log"),
                "FAKE_NFT_CHECKED": str(root / "checked.nft"),
                "FAKE_EXPECTED_PORTS": json.dumps({"ssh": [], "p2p": [8333]}),
            }
        )
        return nft, ss, env

    def run_tool(
        self,
        nft: Path,
        ss: Path,
        env: dict[str, str],
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(TOOL),
                "--nft-bin",
                str(nft),
                "--ss-bin",
                str(ss),
                *arguments,
            ],
            cwd=REPO_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def mark_installed(self, env: dict[str, str]) -> None:
        Path(env["FAKE_NFT_STATE"]).write_text(
            json.dumps({"installed": True, "ruleset": "existing"}), encoding="utf-8"
        )

    def test_status_passes_for_managed_policy_and_explicit_listeners(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-status-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            self.mark_installed(env)
            env["FAKE_EXPECTED_PORTS"] = json.dumps(
                {"ssh": [22], "p2p": [8333]}
            )
            env["FAKE_SS_OUTPUT"] = (
                "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                "LISTEN 0 128 [::]:8333 [::]:*\n"
                "LISTEN 0 128 127.0.0.1:8332 0.0.0.0:*\n"
            )

            result = self.run_tool(
                nft,
                ss,
                env,
                "--status",
                "--json",
                "--ssh-port",
                "22",
                "--public-p2p-port",
                "8333",
            )
            report = json.loads(result.stdout)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(report["ok"])
            self.assertEqual(report["findings"], [])
            self.assertFalse(report["persistenceManaged"])

    def test_status_reports_missing_table_and_wildcard_sensitive_listener(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-findings-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            env["FAKE_SS_OUTPUT"] = "LISTEN 0 128 0.0.0.0:8332 0.0.0.0:*\n"

            result = self.run_tool(nft, ss, env, "--json")
            report = json.loads(result.stdout)
            codes = {finding["code"] for finding in report["findings"]}

            self.assertEqual(result.returncode, 1)
            self.assertIn("managed_table_missing", codes)
            self.assertIn("sensitive_wildcard_listener", codes)
            self.assertNotIn("0.0.0.0", result.stdout)

    def test_status_reports_unexpected_unclassified_wildcard_listener(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-wildcard-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            self.mark_installed(env)
            env["FAKE_SS_OUTPUT"] = "LISTEN 0 128 *:8443 *:*\n"

            result = self.run_tool(
                nft, ss, env, "--json", "--public-p2p-port", "8333"
            )
            report = json.loads(result.stdout)

            self.assertEqual(result.returncode, 1)
            self.assertEqual(report["findings"][0]["code"], "unexpected_wildcard_listener")
            self.assertEqual(report["findings"][0]["port"], 8443)

    def test_status_reports_specific_non_loopback_sensitive_listener(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-specific-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            self.mark_installed(env)
            env["FAKE_SS_OUTPUT"] = "LISTEN 0 128 192.0.2.8:8332 0.0.0.0:*\n"

            result = self.run_tool(
                nft, ss, env, "--json", "--public-p2p-port", "8333"
            )
            report = json.loads(result.stdout)

            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                report["findings"][0]["code"],
                "sensitive_non_loopback_listener",
            )
            self.assertNotIn("192.0.2.8", result.stdout)

    def test_status_rejects_extra_port_hidden_in_managed_rule(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-rule-drift-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            self.mark_installed(env)
            env["FAKE_EXPECTED_PORTS"] = json.dumps(
                {"ssh": [22], "p2p": [8333]}
            )
            env["FAKE_NFT_EXTRA_SSH_PORT"] = "8332"

            result = self.run_tool(
                nft,
                ss,
                env,
                "--json",
                "--ssh-port",
                "22",
                "--public-p2p-port",
                "8333",
            )
            report = json.loads(result.stdout)

            self.assertEqual(result.returncode, 1)
            self.assertIn(
                "managed_port_set_drift",
                {finding["code"] for finding in report["findings"]},
            )

    def test_apply_requires_exact_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-ack-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)

            result = self.run_tool(nft, ss, env, "--apply", "yes", "--json")

            self.assertEqual(result.returncode, 2)
            self.assertIn("does not match", json.loads(result.stdout)["error"])
            self.assertFalse(Path(env["FAKE_NFT_STATE"]).exists())

    def test_apply_checks_then_atomically_loads_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-apply-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            env["FAKE_SS_OUTPUT"] = (
                "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                "LISTEN 0 128 0.0.0.0:8333 0.0.0.0:*\n"
            )
            env["FAKE_EXPECTED_PORTS"] = json.dumps(
                {"ssh": [22], "p2p": [8333]}
            )

            first = self.run_tool(
                nft,
                ss,
                env,
                "--apply",
                ACK,
                "--json",
                "--ssh-port",
                "22",
                "--public-p2p-port",
                "8333",
            )
            first_rules = json.loads(
                Path(env["FAKE_NFT_STATE"]).read_text(encoding="utf-8")
            )["ruleset"]
            second = self.run_tool(
                nft,
                ss,
                env,
                "--apply",
                ACK,
                "--json",
                "--ssh-port",
                "22",
                "--public-p2p-port",
                "8333",
            )
            second_rules = json.loads(
                Path(env["FAKE_NFT_STATE"]).read_text(encoding="utf-8")
            )["ruleset"]
            log = [
                json.loads(line)
                for line in Path(env["FAKE_NFT_LOG"]).read_text().splitlines()
            ]

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertNotIn("delete table", first_rules)
            self.assertIn("delete table inet pohw_host_firewall", second_rules)
            self.assertIn('iifname "lo"', second_rules)
            self.assertIn('iifname "tailscale0"', second_rules)
            self.assertIn("ct state { established, related }", second_rules)
            self.assertIn("meta l4proto icmp", second_rules)
            self.assertIn("meta l4proto ipv6-icmp", second_rules)
            self.assertIn("tcp dport { 22 }", second_rules)
            self.assertIn("tcp dport { 8333 }", second_rules)
            self.assertIn("policy drop", second_rules)
            self.assertNotIn("8332 } ct state new counter accept", second_rules)
            check_indexes = [index for index, item in enumerate(log) if "--check" in item]
            load_indexes = [
                index
                for index, item in enumerate(log)
                if item and item[0] == "--file"
            ]
            self.assertEqual(len(check_indexes), 2)
            self.assertEqual(len(load_indexes), 2)
            self.assertLess(check_indexes[0], load_indexes[0])
            self.assertLess(check_indexes[1], load_indexes[1])

    def test_failed_nft_check_prevents_load(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-check-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            env["FAKE_NFT_FAIL_CHECK"] = "true"

            result = self.run_tool(nft, ss, env, "--apply", ACK, "--json")
            log = [
                json.loads(line)
                for line in Path(env["FAKE_NFT_LOG"]).read_text().splitlines()
            ]

            self.assertEqual(result.returncode, 2)
            self.assertTrue(any("--check" in item for item in log))
            self.assertFalse(any(item and item[0] == "--file" for item in log))
            self.assertFalse(Path(env["FAKE_NFT_STATE"]).exists())

    def test_rejects_sensitive_port_as_public_p2p(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-port-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)

            result = self.run_tool(
                nft, ss, env, "--public-p2p-port", "40407", "--json"
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("sensitive service ports", json.loads(result.stdout)["error"])
            self.assertFalse(Path(env["FAKE_NFT_LOG"]).exists())

    def test_no_public_ssh_rule_is_inferred(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-no-ssh-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            env["FAKE_EXPECTED_PORTS"] = json.dumps({"ssh": [], "p2p": [8333]})

            result = self.run_tool(
                nft,
                ss,
                env,
                "--apply",
                ACK,
                "--json",
                "--public-p2p-port",
                "8333",
            )
            rules = json.loads(
                Path(env["FAKE_NFT_STATE"]).read_text(encoding="utf-8")
            )["ruleset"]

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("pohw:accept-ssh", rules)
            self.assertEqual(json.loads(result.stdout)["sshTcpPorts"], [])

    def test_root_execution_rejects_untrusted_binary_override(self) -> None:
        with self.assertRaisesRegex(FIREWALL.FirewallError, "trusted nft path"):
            FIREWALL.validate_privileged_binary(
                "/tmp/fake-nft",
                expected=Path("/usr/sbin/nft"),
                label="nft",
                euid=0,
            )

    def test_strict_config_drives_the_exact_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-config-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            self.mark_installed(env)
            config = root / "firewall.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "pohw-host-firewall-config/v1",
                        "publicSshTcpPorts": [],
                        "publicP2pTcpPorts": [8333],
                        "sensitiveTcpPorts": [18443],
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_tool(nft, ss, env, "--config", str(config), "--json")
            report = json.loads(result.stdout)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["sshTcpPorts"], [])
            self.assertEqual(report["publicP2pTcpPorts"], [8333])

    def test_config_rejects_duplicate_keys_and_cli_port_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-config-bad-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)
            config = root / "firewall.json"
            config.write_text(
                '{"schema":"pohw-host-firewall-config/v1",'
                '"schema":"pohw-host-firewall-config/v1",'
                '"publicSshTcpPorts":[],"publicP2pTcpPorts":[],'
                '"sensitiveTcpPorts":[]}\n',
                encoding="utf-8",
            )

            duplicate = self.run_tool(
                nft, ss, env, "--config", str(config), "--json"
            )
            ambiguous = self.run_tool(
                nft,
                ss,
                env,
                "--config",
                str(config),
                "--ssh-port",
                "22",
            )

            self.assertEqual(duplicate.returncode, 2)
            self.assertIn("duplicate firewall configuration key", duplicate.stdout)
            self.assertEqual(ambiguous.returncode, 2)
            self.assertIn("cannot be combined", ambiguous.stderr)

    def test_boot_unit_uses_installed_helper_and_strict_config(self) -> None:
        unit = BOOT_UNIT.read_text(encoding="utf-8")
        config = json.loads(CONFIG_EXAMPLE.read_text(encoding="utf-8"))

        self.assertIn("Before=network-pre.target", unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", unit)
        self.assertIn("/usr/local/libexec/pohw-host-firewall.py", unit)
        self.assertIn("--config /etc/pohw/host-firewall.json --apply", unit)
        self.assertEqual(config["schema"], "pohw-host-firewall-config/v1")
        self.assertEqual(config["publicSshTcpPorts"], [])

    def test_rejects_sensitive_port_disguised_as_ssh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-ssh-port-") as temp:
            root = Path(temp)
            nft, ss, env = self.setup_fake_tools(root)

            result = self.run_tool(nft, ss, env, "--ssh-port", "8332", "--json")

            self.assertEqual(result.returncode, 2)
            self.assertIn("declared as SSH", json.loads(result.stdout)["error"])
            self.assertFalse(Path(env["FAKE_NFT_LOG"]).exists())

    def test_missing_ss_fails_closed_without_package_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-missing-") as temp:
            root = Path(temp)
            nft, _ss, env = self.setup_fake_tools(root)
            self.mark_installed(env)

            result = self.run_tool(
                nft, root / "does-not-exist", env, "--json", "--public-p2p-port", "8333"
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("install it explicitly", json.loads(result.stdout)["error"])

    def test_apply_with_missing_ss_does_not_load_rules(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-firewall-apply-missing-") as temp:
            root = Path(temp)
            nft, _ss, env = self.setup_fake_tools(root)

            result = self.run_tool(
                nft, root / "does-not-exist", env, "--apply", ACK, "--json"
            )

            self.assertEqual(result.returncode, 2)
            self.assertFalse(Path(env["FAKE_NFT_STATE"]).exists())
            self.assertFalse(Path(env["FAKE_NFT_LOG"]).exists())


if __name__ == "__main__":
    unittest.main()
