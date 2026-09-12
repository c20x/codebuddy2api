"""本机请求流水：只保留元数据，不写 token。"""

import json
import tempfile
import time
import unittest
from pathlib import Path

from usage_history import UsageHistory, estimate_credits


class UsageHistoryTests(unittest.TestCase):
    def test_finish_persists_metadata_without_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage-history.json"
            history = UsageHistory(path, max_items=3)
            history.begin("ab12", protocol="chat", nickname="demo", multiplier=0.79)
            history.finish("ab12", ok=True, t0=time.time() - 1, model="glm-5.2",
                           result={"usage": {"total_tokens": 1000},
                                   "choices": [{"finish_reason": "stop"}]})
            items = history.snapshot()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["protocol"], "chat")
            self.assertEqual(items[0]["tokens"], 1000)
            self.assertEqual(items[0]["credits"], 0.79)
            self.assertTrue(items[0]["credits_estimated"])
            self.assertEqual(estimate_credits(2000, 0.5), 1.0)
            saved = json.loads(path.read_text(encoding="utf-8"))
            blob = json.dumps(saved)
            self.assertNotIn("accessToken", blob)
            self.assertNotIn("Bearer", blob)

    def test_max_items_keeps_latest_only(self):
        history = UsageHistory(max_items=2)
        history.finish("a", ok=True, model="one")
        history.finish("b", ok=False, status=429, error="rate", model="two")
        history.finish("c", ok=True, model="three")
        items = history.snapshot()
        self.assertEqual([item["id"] for item in items], ["c", "b"])
        self.assertFalse(items[1]["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
