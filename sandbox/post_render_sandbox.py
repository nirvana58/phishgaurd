"""Send a URL to a deployed PhishGuard sandbox HTTP service."""

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser(
        description="POST a URL to a Render-hosted sandbox service."
    )
    parser.add_argument(
        "target_url",
        help="URL for the sandbox service to visit",
    )
    parser.add_argument(
        "--service-url",
        default=os.environ.get("SANDBOX_SERVICE_URL"),
        help="Base URL of the deployed service (or set SANDBOX_SERVICE_URL)",
    )
    parser.add_argument(
        "--path",
        default="/detonate",
        help="POST route on the service (default: /detonate)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60,
        help="Request timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--screenshot",
        help="Save the returned screenshot to this path, if available",
    )
    args = parser.parse_args()

    if not args.service_url:
        parser.error("provide --service-url or set SANDBOX_SERVICE_URL")

    endpoint = urljoin(args.service_url.rstrip("/") + "/", args.path.lstrip("/"))
    body = json.dumps({"url": args.target_url}).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    token = os.environ.get("SANDBOX_API_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(endpoint, data=body, headers=headers, method="POST")

    try:
        with urlopen(request, timeout=args.timeout) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            print(f"HTTP {response.status}")
    except HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace")
        print(f"HTTP {error.code}", file=sys.stderr)
        if response_body:
            print(response_body, file=sys.stderr)
        return 1
    except (URLError, TimeoutError) as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 1

    try:
        result = json.loads(response_body)
    except json.JSONDecodeError:
        print(response_body)
        return 0

    if isinstance(result, dict):
        screenshot = result.pop("screenshot_base64", None)
        if screenshot and args.screenshot:
            destination = Path(args.screenshot)
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(base64.b64decode(screenshot, validate=True))
            except (OSError, ValueError) as error:
                print(f"Could not save screenshot: {error}", file=sys.stderr)
                return 1
            print(f"Screenshot saved: {destination}")

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())