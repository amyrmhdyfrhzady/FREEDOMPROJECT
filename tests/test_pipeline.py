import base64
import importlib.util
import io
import json
import os
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("freedom", ROOT / "scripts" / "freedom.py")
freedom = importlib.util.module_from_spec(spec)
sys.modules["freedom"] = freedom
spec.loader.exec_module(freedom)


class ParserTests(unittest.TestCase):
    def test_vmess_uri(self):
        payload = base64.b64encode(json.dumps({"add": "127.0.0.1", "port": "443", "id": "00000000-0000-0000-0000-000000000000"}).encode()).decode()
        self.assertEqual(freedom.parse_uri("vmess://" + payload)["protocol"], "vmess")

    def test_vmess_xray_config(self):
        payload = base64.b64encode(json.dumps({"add": "example.com", "port": "443", "id": "uuid", "aid": "0", "scy": "auto", "net": "tcp"}).encode()).decode()
        record = freedom.parse_uri("vmess://" + payload)
        config = freedom.xray_config(record, 1080)
        server = config["outbounds"][0]["settings"]["vnext"][0]
        self.assertEqual(server["address"], "example.com")
        self.assertEqual(server["port"], 443)

    def test_vless_uri(self):
        item = freedom.parse_uri("vless://uuid@127.0.0.1:443?security=tls#node")
        self.assertEqual((item["host"], item["port"], item["protocol"]), ("127.0.0.1", 443, "vless"))

    def test_invalid_ipv6_uri_is_ignored(self):
        self.assertIsNone(freedom.parse_uri("vless://uuid@[2001:db8::1:443?security=tls#broken"))

    def test_invalid_ipv6_does_not_stop_following_configs(self):
        content = (
            "vless://uuid@[2001:db8::1:443?security=tls#broken\n"
            "vless://uuid@127.0.0.1:443?security=tls#valid\n"
        )
        records = freedom.extract_text(content, "fixture", False)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["host"], "127.0.0.1")

    def test_shadowsocks_uri(self):
        auth = base64.urlsafe_b64encode(b"aes-128-gcm:password").decode().rstrip("=")
        item = freedom.parse_uri(f"ss://{auth}@127.0.0.1:8388#node")
        self.assertEqual(item["protocol"], "ss")

    def test_clash_yaml(self):
        content = "proxies:\n  - name: node\n    type: trojan\n    server: 127.0.0.1\n    port: 443\n    password: pass\n    tls: true\n"
        records = freedom.extract_text(content, "fixture", False)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["protocol"], "trojan")

    def test_base64_subscription(self):
        raw = "vless://uuid@127.0.0.1:443?security=tls#node\n"
        encoded = base64.b64encode(raw.encode()).decode()
        records = freedom.extract_text(encoded, "fixture", False)
        self.assertEqual(len(records), 1)

    def test_duplicate_identity_ignores_fragment(self):
        a = freedom.parse_uri("vless://uuid@127.0.0.1:443?security=tls#one")
        b = freedom.parse_uri("vless://uuid@127.0.0.1:443?security=tls#two")
        self.assertEqual(a["host"], b["host"])

    def test_xray_trojan_config(self):
        record = freedom.parse_uri("trojan://password@127.0.0.1:443?security=tls&sni=example.com#node")
        config = freedom.xray_config(record, 1080)
        server = config["outbounds"][0]["settings"]["servers"][0]
        self.assertEqual(server["password"], "password")
        self.assertNotIn("users", server)

    def test_plain_shadowsocks_auth_config(self):
        record = freedom.parse_uri("ss://aes-128-gcm:password@127.0.0.1:8388#node")
        config = freedom.xray_config(record, 1080)
        server = config["outbounds"][0]["settings"]["servers"][0]
        self.assertEqual(server["method"], "aes-128-gcm")
        self.assertEqual(server["password"], "password")

    def test_singbox_tuic_config(self):
        record = freedom.parse_uri("tuic://uuid:password@127.0.0.1:443?sni=example.com#node")
        config = freedom.singbox_config(record, 1080)
        self.assertEqual(config["outbounds"][0]["type"], "tuic")

    def test_protocol_aliases(self):
        self.assertEqual(freedom.parse_uri("hy2://password@127.0.0.1:443")["protocol"], "hysteria2")
        self.assertEqual(freedom.parse_uri("socks5://127.0.0.1:1080")["protocol"], "socks")

    def test_ssr_uri_detection(self):
        body = "127.0.0.1:8388:auth_sha1_v4:aes-128-ctr:tls1.2_ticket_auth:cGFzcw"
        encoded = base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")
        record = freedom.parse_uri("ssr://" + encoded + "/?remarks=dGVzdA")
        self.assertEqual(record["protocol"], "ssr")

    def test_vless_reality_config(self):
        record = freedom.parse_uri("vless://uuid@127.0.0.1:443?security=reality&sni=example.com&pbk=public&sid=1234&fp=chrome#node")
        config = freedom.xray_config(record, 1080)
        reality = config["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["password"], "public")

    def test_parse_stage_personal_priority_and_dedup(self):
        original = (freedom.ROOT, freedom.CONFIGS, freedom.WORK)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            configs = root / "configs"
            work = root / ".work"
            (work / "external").mkdir(parents=True)
            configs.mkdir()
            personal_uri = "vless://same@127.0.0.1:443?security=tls#personal"
            (configs / "personal.txt").write_text(personal_uri + "\n")
            (work / "external" / "external_0001.txt").write_text(personal_uri + "\nvless://external@127.0.0.1:444?security=tls#external\n")
            freedom.ROOT, freedom.CONFIGS, freedom.WORK = root, configs, work
            freedom.parse_all()
            data = json.loads((work / "records.json").read_text())
            self.assertEqual(len(data["personal"]), 1)
            self.assertEqual(len(data["external"]), 1)
            self.assertTrue(data["personal"][0]["personal"])
            self.assertEqual(len(data["all_sources"]), 3)
        freedom.ROOT, freedom.CONFIGS, freedom.WORK = original

    def test_download_stage_reads_external_list(self):
        original = (freedom.ROOT, freedom.CONFIGS, freedom.WORK)
        class Response(io.BytesIO):
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            configs = root / "configs"
            work = root / ".work"
            configs.mkdir()
            (configs / "external-sources.list").write_text("# source\nhttps://example.test/sub\nhttps://example.test/sub\n")
            freedom.ROOT, freedom.CONFIGS, freedom.WORK = root, configs, work
            with patch.object(freedom.urllib.request, "urlopen", return_value=Response(b"vless://id@127.0.0.1:443\n")):
                freedom.download()
            status = json.loads((work / "download_status.json").read_text())
            self.assertEqual(len(status), 1)
            self.assertEqual(status[0]["status"], "success")
        freedom.ROOT, freedom.CONFIGS, freedom.WORK = original

    def test_failed_publish_preserves_previous_output(self):
        original = (freedom.ROOT, freedom.WORK, freedom.OUTPUT)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work = root / ".work"
            output = root / "output"
            work.mkdir()
            output.mkdir()
            (output / "subscribe.txt").write_bytes(b"old-output")
            (root / "subscribe.txt").write_bytes(b"old-output")
            record = freedom.parse_uri("vless://uuid@127.0.0.1:443?security=tls#node")
            record.update(id="bad", source="external_0001.txt", personal=False)
            (work / "records.json").write_text(json.dumps({"personal": [], "external": [record]}))
            (work / "validation.json").write_text(json.dumps({"bad": {"status": "unhealthy"}}))
            (work / "download_status.json").write_text("[]")
            freedom.ROOT, freedom.WORK, freedom.OUTPUT = root, work, output
            with self.assertRaises(RuntimeError):
                freedom.publish()
            self.assertEqual((output / "subscribe.txt").read_bytes(), b"old-output")
            self.assertEqual((root / "subscribe.txt").read_bytes(), b"old-output")
        freedom.ROOT, freedom.WORK, freedom.OUTPUT = original

    def test_validation_runner_with_mock_core(self):
        original_which = freedom.shutil.which
        original_run = freedom.subprocess.run
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "xray"
            binary.write_text(f"#!{sys.executable}\nimport json, socket, sys\nargs=sys.argv\nif '-test' in args: sys.exit(0)\np=args[args.index('-c')+1]\nc=json.load(open(p))\ns=socket.socket()\ns.bind(('127.0.0.1', c['inbounds'][0]['port']))\ns.listen()\nwhile True:\n conn, _ = s.accept()\n conn.close()\n")
            binary.chmod(0o755)
            def fake_which(name):
                return str(binary) if name == "xray" else original_which(name)
            def fake_run(args, *call_args, **kwargs):
                if args and args[0] == "curl":
                    return subprocess.CompletedProcess(args, 0, stdout="204", stderr="")
                return original_run(args, *call_args, **kwargs)
            record = freedom.parse_uri("vless://uuid@127.0.0.1:443?security=tls#node")
            with patch.object(freedom.shutil, "which", side_effect=fake_which), patch.object(freedom.subprocess, "run", side_effect=fake_run):
                result = freedom.run_test({**record, "id": "mock-test"})
            self.assertEqual(result["status"], "healthy")

    def test_validation_runner_with_mock_singbox(self):
        original_which = freedom.shutil.which
        original_run = freedom.subprocess.run
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "sing-box"
            binary.write_text(f"#!{sys.executable}\nimport json, socket, sys\nargs=sys.argv\nif args[1] == 'check': sys.exit(0)\np=args[args.index('-c')+1]\nc=json.load(open(p))\ns=socket.socket()\ns.bind(('127.0.0.1', c['inbounds'][0]['listen_port']))\ns.listen()\nwhile True:\n conn, _ = s.accept()\n conn.close()\n")
            binary.chmod(0o755)
            def fake_which(name):
                return str(binary) if name == "sing-box" else original_which(name)
            def fake_run(args, *call_args, **kwargs):
                if args and args[0] == "curl":
                    return subprocess.CompletedProcess(args, 0, stdout="204", stderr="")
                return original_run(args, *call_args, **kwargs)
            record = freedom.parse_uri("hysteria2://password@127.0.0.1:443?sni=example.com#node")
            with patch.object(freedom.shutil, "which", side_effect=fake_which), patch.object(freedom.subprocess, "run", side_effect=fake_run):
                result = freedom.run_test({**record, "id": "mock-singbox-test"})
            self.assertEqual(result["status"], "healthy")

    def test_ssr_validation_is_explicitly_unsupported(self):
        record = freedom.parse_uri("ssr://" + base64.urlsafe_b64encode(b"127.0.0.1:8388:auth_sha1_v4:aes-128-ctr:plain:cA").decode().rstrip("="))
        result = freedom.run_test({**record, "id": "ssr-test"})
        self.assertEqual(result["status"], "unsupported")

    def test_publish_caps_and_root_copy(self):
        original = (freedom.ROOT, freedom.WORK, freedom.OUTPUT, freedom.MAX_EXTERNAL, freedom.MAX_PER_PROTOCOL)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work = root / ".work"
            output = root / "output"
            work.mkdir()
            personal = freedom.parse_uri("vless://p@127.0.0.1:443?security=tls#personal")
            external = [freedom.parse_uri(f"vless://e{i}@127.0.0.1:{4400+i}?security=tls#e{i}") for i in range(3)]
            records = [{**personal, "id": "p", "source": "personal.txt", "personal": True}]
            records += [{**item, "id": f"e{i}", "source": f"external_{i}.txt", "personal": False} for i, item in enumerate(external)]
            (work / "records.json").write_text(json.dumps({"personal": records[:1], "external": records[1:]}))
            validation = {item["id"]: {"status": "healthy"} for item in records}
            (work / "validation.json").write_text(json.dumps(validation))
            (work / "download_status.json").write_text("[]")
            freedom.ROOT, freedom.WORK, freedom.OUTPUT = root, work, output
            freedom.MAX_EXTERNAL, freedom.MAX_PER_PROTOCOL = 2, 1
            freedom.publish()
            main_data = base64.b64decode((output / "subscribe.txt").read_bytes()).decode().splitlines()
            self.assertEqual(len(main_data), 3)
            self.assertEqual((root / "subscribe.txt").read_bytes(), (output / "subscribe.txt").read_bytes())
            proto_data = base64.b64decode((output / "subscribe-vless.txt").read_bytes()).decode().splitlines()
            self.assertEqual(len(proto_data), 1)
            stats = json.loads((root / "stats.json").read_text())
            self.assertEqual(stats["current"]["configs"]["unique"], 4)
            self.assertEqual(stats["current"]["published"]["main"], 3)
            self.assertEqual(len(stats["history"]), 1)
        freedom.ROOT, freedom.WORK, freedom.OUTPUT, freedom.MAX_EXTERNAL, freedom.MAX_PER_PROTOCOL = original


if __name__ == "__main__":
    unittest.main()
