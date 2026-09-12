"""本机账号池管理页离线回归：只检查静态页与路由，不读凭据。"""

import unittest

from fastapi.testclient import TestClient

import converter


class WebuiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(converter.app)

    def test_ui_routes_serve_html_without_tokens(self):
        for path in ("/", "/admin"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn("text/html", response.headers["content-type"])
                self.assertIn("账号池", response.text)
                self.assertIn("/admin/credentials", response.text)
                self.assertNotIn("accessToken", response.text)
                self.assertNotIn("refreshToken", response.text)
                self.assertNotIn("private-access-token", response.text)

    def test_health_is_unchanged_and_public(self):
        self.assertEqual(self.client.get("/health").json(), {"status": "ok"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
