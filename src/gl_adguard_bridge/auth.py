"""Authentication module for GL.iNet router authentication."""

import hashlib
import hmac
import time
from typing import Any, Dict

import httpx
from loguru import logger

from gl_adguard_bridge.config import Settings


class RouterAuth:
    """Handle authentication with the GL.iNet router using the RPC API.

    API documentation:
    https://web.archive.org/web/20240121142533/https://dev.gl-inet.com/router-4.x-api/
    """

    def __init__(self, settings: Settings):
        """Initialize the GL.iNet router authentication handler.

        Args:
            settings: Application settings
        """
        self.settings = settings

        # Configure HTTPX client with SSL verification settings
        if isinstance(self.settings.router_ssl_verify, str):
            # If it's a string, treat it as a path to a CA bundle
            logger.info(
                f"Using custom CA bundle for SSL verification: {self.settings.router_ssl_verify}"
            )
            self.client = httpx.AsyncClient(verify=self.settings.router_ssl_verify)
        elif self.settings.router_ssl_verify is False:
            # If SSL verification is disabled, log a warning
            logger.warning("SSL certificate verification is disabled. This is insecure!")
            self.client = httpx.AsyncClient(verify=False)
        else:
            # Default: use system CA certificates
            logger.debug("Using system CA certificates for SSL verification")
            self.client = httpx.AsyncClient()

        # Initialize session ID
        self.sid: str = ""

    async def authenticate(self) -> str:
        """Authenticate with the GL.iNet router and get a session ID.

        Uses the GL.iNet authentication API flow:
        1. Get challenge parameters
        2. Calculate hash
        3. Login with hash
        4. Get session ID (sid)

        Returns:
            str: The session ID (sid) from the authentication response
        """
        logger.info(f"Authenticating with GL.iNet router at {self.settings.router_host}")
        logger.debug(f"Starting authentication process with router at {self.settings.router_host}")

        try:
            # Step 1: Get challenge parameters
            logger.debug("Step 1: Getting challenge parameters")
            challenge_data = await self._get_challenge()
            logger.debug(f"Received challenge data with ID: {challenge_data['id']}")

            # Step 2: Calculate hash
            logger.debug("Step 2: Calculating password hash")
            password_hash = self._calculate_password_hash(
                challenge_data["salt"], self.settings.router_password
            )
            logger.debug("Password hash calculated successfully")

            # Step 3: Login with hash
            logger.debug("Step 3: Sending login request with password hash")
            login_response = await self._login(
                username=self.settings.router_username,
                password_hash=password_hash,
            )

            # Step 4: Extract and store session ID
            logger.debug("Step 4: Extracting session ID from login response")
            if "sid" not in login_response:
                logger.error(f"GL.iNet authentication failed: {login_response}")
                raise ValueError("GL.iNet authentication response did not contain a session ID")

            self.sid = login_response["sid"]
            logger.debug(f"Session ID retrieved successfully: {self.sid[:5]}...")
            logger.info("GL.iNet router authentication successful")
            return self.sid

        except httpx.TransportError:
            logger.exception("SSL error connecting to GL.iNet router")
            logger.info(
                "If the router uses a self-signed certificate, "
                "set ROUTER_SSL_VERIFY=False or provide a CA bundle"
            )
            raise
        except Exception:
            logger.exception("GL.iNet router authentication request failed")
            raise

    async def _get_challenge(self) -> Dict[str, Any]:
        """Get challenge parameters from the router.

        Returns:
            Dict: Challenge parameters including id and salt
        """
        # Create RPC request for challenge method
        payload = {
            "jsonrpc": "2.0",
            "method": "challenge",
            "params": {
                "username": self.settings.router_username,
            },
            "id": str(int(time.time() * 1000)),
        }

        # Log the request payload
        logger.debug(f"Sending challenge request: {payload}")

        response = await self.client.post(
            self.settings.router_rpc_url,
            json=payload,
            timeout=10.0,
        )
        response.raise_for_status()

        result = response.json()
        # Log the response
        logger.debug(f"Received challenge response: {result}")

        if "result" not in result:
            raise ValueError(f"Invalid challenge response: {result}")

        return result["result"]

    def _calculate_password_hash(self, salt: str, password: str) -> str:
        """Calculate password hash using salt.

        Args:
            salt: Salt string from challenge
            password: User password

        Returns:
            str: Hashed password
        """
        # Create HMAC using SHA-256
        key = salt.encode()
        msg = password.encode()
        digest = hmac.new(key, msg, digestmod=hashlib.sha256).hexdigest()
        return digest

    async def _login(self, username: str, password_hash: str) -> Dict[str, Any]:
        """Login to the router using the challenge ID and password hash.

        Args:
            challenge_id: Challenge ID from the challenge response
            username: Router username
            password_hash: Hashed password

        Returns:
            Dict: Login response including sid
        """
        # Create RPC request for login method
        payload = {
            "jsonrpc": "2.0",
            "method": "login",
            "params": {"username": username, "hash": password_hash},
            "id": str(int(time.time() * 1000)),
        }

        # Log the request payload with redacted password
        logger.debug(f"Sending login request: {payload}")

        response = await self.client.post(
            self.settings.router_rpc_url,
            json=payload,
            timeout=10.0,
        )
        response.raise_for_status()

        result = response.json()
        # Log the response
        logger.debug(f"Received login response: {result}")

        if "result" not in result:
            raise ValueError(f"Invalid login response: {result}")

        return result["result"]

    def get_auth_cookie(self) -> dict:
        """Get the authentication cookie for AdGuard Home requests.

        Returns:
            dict: Cookie dict with the Admin-Token cookie
        """
        if not self.sid:
            logger.warning("No GL.iNet session ID available, authentication required")
            return {}

        return {"Admin-Token": self.sid}

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
