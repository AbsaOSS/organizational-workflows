#
# Copyright 2026 ABSA Group Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""AquaSec API authentication via HMAC-SHA256 signed requests."""

import hashlib
import hmac
import json
import logging
import time

import requests

from security.constants import AQUA_AUTH_URL, HTTP_TIMEOUT, LOGGING_PREFIX

logger = logging.getLogger(__name__)


class AquaSecAuthenticator:
    """Authenticates with the AquaSec API and returns a bearer token."""

    def __init__(self, api_key: str, api_secret: str, group_id: str) -> None:
        self.api_key = api_key
        self.api_secret = api_secret
        self.group_id = group_id

    def _generate_signature(self, string_to_sign: str) -> str:
        """Generate HMAC-SHA256 signature for AquaSec API request.

        Args:
            string_to_sign: String to sign with HMAC.

        Returns:
            Hexadecimal signature string.
        """
        return hmac.HMAC(
            self.api_secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def authenticate(self) -> str:
        """Authenticate with AquaSec API and return bearer token.

        Returns:
            Bearer token string.

        Raises:
            SystemExit: If authentication fails.
        """
        logger.info("%sAPI authentication starting.", LOGGING_PREFIX)

        timestamp = int(time.time())
        method = "POST"
        auth_endpoint = f"{AQUA_AUTH_URL}/v2/tokens"
        post_body = json.dumps(
            {"group_id": int(self.group_id), "allowed_endpoints": ["ANY:*"], "validity": 240},
            separators=(",", ":"),
        )
        string_to_sign = f"{timestamp}{method}/v2/tokens{post_body}"

        signature = self._generate_signature(string_to_sign)

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "X-Timestamp": str(timestamp),
            "X-Signature": signature,
        }

        try:
            response = requests.post(auth_endpoint, headers=headers, data=post_body, timeout=HTTP_TIMEOUT)
        except requests.RequestException as e:
            raise SystemExit(f"ERROR: AquaSec authentication request failed: {e}") from e

        if response.status_code != 200:
            raise SystemExit(f"ERROR: AquaSec authentication failed. Status {response.status_code}: {response.text}")

        bearer_token = response.json().get("data", "")
        if not bearer_token:
            raise SystemExit("ERROR: AquaSec API response missing bearer token data.")

        logger.info("%sAPI authentication successful.", LOGGING_PREFIX)
        return bearer_token
