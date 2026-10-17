import unittest
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bigspeshl_guard.config import DEFAULT_CONFIG, load_config, save_config, validate_config
from bigspeshl_guard.capture import packet_to_event, run_live_capture
from bigspeshl_guard.discord_notify import DiscordNotifier
from bigspeshl_guard.engine import GuardEngine, ThreatEvent
from bigspeshl_guard.firewall import NftablesFirewall
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


class GuardEngineTests(unittest.TestCase):
    def test_each_attack_uses_its_own_threshold_and_block_time(self):
        engine = GuardEngine(
            window_seconds=10,
            attack_policies={
                "syn_flood": {"threshold_requests": 3, "block_seconds": 17},
                "udp_reflection": {"threshold_requests": 5, "block_seconds": 27},
                "http_flood": {"threshold_requests": 7, "block_seconds": 37},
            },
        )
        event = engine.observe(ThreatEvent("192.0.2.1", "192.0.2.9", "tcp", packets=3, port=80))

        self.assertEqual(event["attack_type"], "syn_flood")
        self.assertEqual(event["requests_in_window"], 3)
        self.assertEqual(event["block_seconds"], 17)
        self.assertIn("192.0.2.1", engine.blocklist)

    def test_updating_policy_keeps_existing_blocks(self):
        engine = GuardEngine(
            attack_policies={
                "syn_flood": {"threshold_requests": 1, "block_seconds": 17},
                "udp_reflection": {"threshold_requests": 5, "block_seconds": 27},
                "http_flood": {"threshold_requests": 7, "block_seconds": 37},
            }
        )
        engine.observe(ThreatEvent("192.0.2.1", "192.0.2.9", "tcp", packets=1))
        existing_expiry = engine.blocklist["192.0.2.1"]
        engine.update_policy(
            20,
            {
                "syn_flood": {"threshold_requests": 2, "block_seconds": 30},
                "udp_reflection": {"threshold_requests": 5, "block_seconds": 27},
                "http_flood": {"threshold_requests": 7, "block_seconds": 37},
            },
        )

        self.assertEqual(engine.window_seconds, 20)
        self.assertEqual(engine.blocklist["192.0.2.1"], existing_expiry)

    def test_protocol_and_port_statistics_cover_recent_window(self):
        engine = GuardEngine(window_seconds=10)
        engine.observe(ThreatEvent("192.0.2.1", "192.0.2.9", "tcp", packets=4, port=80))
        engine.observe(ThreatEvent("192.0.2.1", "192.0.2.9", "udp", packets=6, port=53))
        engine.observe(
            ThreatEvent(
                "192.0.2.2",
                "192.0.2.9",
                "http",
                packets=2,
                port=443,
                timestamp=datetime.now(timezone.utc) - timedelta(seconds=20),
            )
        )

        stats = engine.traffic_stats()
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0]["requests"], 10)
        self.assertEqual(stats[0]["protocols"], {"TCP": 4, "UDP": 6})
        self.assertEqual(stats[0]["ports"], [53, 80])

    def test_blocked_source_is_not_counted_again_until_expiry(self):
        engine = GuardEngine(
            attack_policies={
                "syn_flood": {"threshold_requests": 1, "block_seconds": 1},
                "udp_reflection": {"threshold_requests": 50, "block_seconds": 10},
                "http_flood": {"threshold_requests": 50, "block_seconds": 10},
            }
        )
        engine.observe(ThreatEvent("192.0.2.1", "192.0.2.9", "tcp", packets=1))
        denied = engine.observe(ThreatEvent("192.0.2.1", "192.0.2.9", "tcp", packets=100))

        self.assertEqual(denied["status"], "denied")
        self.assertEqual(engine.summary()["threat_count"], 1)
        engine.blocklist["192.0.2.1"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        after_expiry = engine.observe(
            ThreatEvent("192.0.2.1", "192.0.2.9", "tcp", packets=1)
        )
        self.assertEqual(after_expiry["action"], "block")

    def test_config_rejects_invalid_values_and_requires_discord_credentials(self):
        invalid_threshold = {
            **DEFAULT_CONFIG,
            "attacks": {"syn_flood": {"threshold_requests": 0}},
        }
        with self.assertRaises(ValueError):
            validate_config(invalid_threshold)

        enabled_without_credentials = {
            **DEFAULT_CONFIG,
            "discord": {"enabled": True, "bot_token": "", "channel_id": "", "guild_id": ""},
        }
        with self.assertRaises(ValueError):
            validate_config(enabled_without_credentials)

    def test_config_is_saved_and_discord_alert_checks_guild(self):
        with TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "config.json"
            config = validate_config(DEFAULT_CONFIG)
            saved_path = save_config(config, config_path)
            self.assertEqual(load_config(saved_path), config)

        notifier = DiscordNotifier(
            {
                "enabled": True,
                "bot_token": "never-print-this",
                "channel_id": "123",
                "guild_id": "456",
            }
        )
        notifier._request = Mock(return_value={"guild_id": "456"})
        notifier.send_alert(
            {
                "source_ip": "192.0.2.1",
                "attack": "SYN flood",
                "protocol": "TCP",
                "port": 80,
                "requests_in_window": 500,
                "window_seconds": 10,
                "action": "block",
                "block_seconds": 1200,
            }
        )
        self.assertEqual(notifier._request.call_count, 2)
        self.assertIn("messages", notifier._request.call_args_list[1].args[1])

    def test_live_packet_parser_classifies_syn_udp_http_and_other_tcp(self):
        syn = packet_to_event(
            IP(src="192.0.2.1", dst="192.0.2.9") / TCP(sport=40000, dport=443, flags="S")
        )
        udp = packet_to_event(
            IP(src="192.0.2.2", dst="192.0.2.9") / UDP(sport=40000, dport=53)
        )
        http = packet_to_event(
            IP(src="192.0.2.3", dst="192.0.2.9")
            / TCP(sport=40000, dport=80, flags="PA")
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        )
        regular_tcp = packet_to_event(
            IP(src="192.0.2.4", dst="192.0.2.9") / TCP(sport=40000, dport=443, flags="A")
        )

        self.assertEqual(syn.metadata["attack_type"], "syn_flood")
        self.assertEqual(udp.metadata["attack_type"], "udp_reflection")
        self.assertEqual(http.metadata["attack_type"], "http_flood")
        self.assertTrue(regular_tcp.metadata["capture_only"])
        engine = GuardEngine(
            attack_policies={
                "syn_flood": {"threshold_requests": 1, "block_seconds": 30},
                "udp_reflection": {"threshold_requests": 1, "block_seconds": 30},
                "http_flood": {"threshold_requests": 1, "block_seconds": 30},
            }
        )
        self.assertIsNone(engine.observe(regular_tcp))
        self.assertEqual(engine.observe(http)["attack_type"], "http_flood")

    def test_nftables_uses_only_owned_table_and_protects_configured_networks(self):
        def nft_runner(arguments, **kwargs):
            stdout = ""
            if arguments[:3] == ["nft", "list", "set"]:
                address_type = "ipv4_addr" if arguments[-1] == "blocked_ipv4" else "ipv6_addr"
                stdout = f"type {address_type}; flags timeout; elements = {{ }};"
            elif arguments[:3] == ["nft", "list", "chain"]:
                stdout = (
                    "type filter hook input priority filter - 100; policy accept;\n"
                    "ip saddr @blocked_ipv4 drop\nip6 saddr @blocked_ipv6 drop"
                )
            return CompletedProcess(arguments, 0, stdout=stdout, stderr="")

        runner = Mock(side_effect=nft_runner)
        firewall = NftablesFirewall(
            protected_networks=["192.0.2.0/24"],
            runner=runner,
            system="Linux",
        )
        with patch("bigspeshl_guard.firewall.shutil.which", return_value="/usr/sbin/nft"):
            firewall.ensure_ready()
        self.assertTrue(firewall.block_ip("198.51.100.4", 120))
        self.assertTrue(firewall.block_ip("2001:db8::4", 60))
        self.assertFalse(firewall.block_ip("192.0.2.4", 120))

        commands = [call.args[0] for call in runner.call_args_list]
        self.assertFalse(any("flush" in command or "delete" in command for command in commands))
        add_element_call = next(
            call for call in runner.call_args_list
            if call.args[0] == ["nft", "-f", "-"]
            and "add element" in call.kwargs.get("input", "")
        )
        self.assertIn("timeout 120s", add_element_call.kwargs["input"])
        ipv6_add_call = next(
            call for call in runner.call_args_list
            if call.args[0] == ["nft", "-f", "-"]
            and "blocked_ipv6" in call.kwargs.get("input", "")
        )
        self.assertIn("timeout 60s", ipv6_add_call.kwargs["input"])

    def test_live_capture_counts_only_packets_to_selected_interface_addresses(self):
        engine = GuardEngine(
            attack_policies={
                "syn_flood": {"threshold_requests": 1, "block_seconds": 30},
                "udp_reflection": {"threshold_requests": 1, "block_seconds": 30},
                "http_flood": {"threshold_requests": 1, "block_seconds": 30},
            }
        )
        inbound_packet = (
            IP(src="198.51.100.8", dst="192.0.2.9") / UDP(sport=40000, dport=53)
        )
        outbound_packet = (
            IP(src="192.0.2.9", dst="198.51.100.8") / UDP(sport=40000, dport=53)
        )

        def fake_sniff(**kwargs):
            kwargs["prn"](inbound_packet)
            kwargs["prn"](inbound_packet)
            kwargs["prn"](outbound_packet)
            raise KeyboardInterrupt()

        on_alert = Mock()
        with patch("bigspeshl_guard.capture.platform.system", return_value="Linux"):
            with patch(
                "bigspeshl_guard.capture.psutil.net_if_addrs",
                return_value={
                    "eth0": [SimpleNamespace(family=socket.AF_INET, address="192.0.2.9")]
                },
            ):
                with patch("scapy.sendrecv.sniff", side_effect=fake_sniff):
                    run_live_capture(engine, "eth0", on_alert, Mock())

        rows = engine.traffic_stats()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_ip"], "198.51.100.8")
        self.assertEqual(on_alert.call_count, 1)


if __name__ == "__main__":
    unittest.main()
