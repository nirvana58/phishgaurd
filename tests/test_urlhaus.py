import asyncio
import os
import unittest
from unittest.mock import patch

from core import urlhaus


class DummyResponse:
    def __init__(self, status_code=401, payload=None):
        self.status_code = status_code
        self._payload = payload or {"error": "Unauthorized"}
        self.text = str(self._payload)

    def json(self):
        return self._payload


class DummyAsyncClient:
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, data=None):
        return DummyResponse()


class UrlHausTests(unittest.TestCase):
    def test_lookup_url_reports_missing_auth_key_when_unauthorized(self):
        os.environ.pop("URLHAUS_AUTH_KEY", None)
        os.environ.pop("ABUSECH_AUTH_KEY", None)
        os.environ.pop("URLHAUS_API_KEY", None)

        with patch("core.urlhaus.httpx.AsyncClient", DummyAsyncClient):
            result = asyncio.run(urlhaus.lookup_url("https://example.com"))

        self.assertFalse(result["available"])
        self.assertIn("auth", result["reason"].lower())


if __name__ == "__main__":
    unittest.main()
