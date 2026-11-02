import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class TestCLI(unittest.TestCase):
    def _run(self, payload):
        env = dict(os.environ)
        env["PYTHONPATH"] = ROOT
        proc = subprocess.run(
            [sys.executable, "-m", "nameforge"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT,
        )
        return proc

    def test_heuristic_cli(self):
        payload = {
            "schema_version": "nameforge-1.0",
            "context": {
                "address": 0x1000,
                "size": 0x40,
                "current_name": None,
                "state": "detected",
                "instructions": [{"address": 0x1000, "text": "nop"} for _ in range(3)],
                "instructions_truncated": False,
                "callers": [],
                "callees": [],
                "strings": [{"address": 0x2000, "value": "player_speed"}],
                "constants": [],
                "style": {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64,
                          "inferred_case": None, "examples": []},
            },
            "style": {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64},
            "max_suggestions": 3,
        }
        proc = self._run(payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["suggestions"])
        self.assertEqual(data["suggestions"][0]["name"], "player_speed")

    def test_empty_returns_empty_list(self):
        payload = {
            "context": {"instructions": [], "strings": [], "callees": []},
            "style": {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64},
        }
        proc = self._run(payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["suggestions"], [])

    def test_openai_mocked(self):
        import urllib.request
        from nameforge.provider import openai_suggest

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({
                    "choices": [{"message": {"content": json.dumps({
                        "suggestions": [{"name": "player_update", "confidence": 0.9,
                                         "reason": "llamado por player"}]
                    })}}]
                }).encode()

        original = urllib.request.urlopen
        urllib.request.urlopen = lambda req, timeout=None: FakeResp()
        try:
            res = openai_suggest(
                {"instructions": [], "strings": [], "callees": []},
                {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64},
                {"api_key": "test", "timeout": 5},
            )
            self.assertEqual(res[0]["name"], "player_update")
        finally:
            urllib.request.urlopen = original


if __name__ == "__main__":
    unittest.main()