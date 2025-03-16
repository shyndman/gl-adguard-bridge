"""Proxy module for forwarding requests to AdGuard Home behind a GL.iNet router."""

from typing import Any, Dict, Optional

import httpx
from loguru import logger
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from gl_adguard_bridge.auth import RouterAuth
from gl_adguard_bridge.config import Settings


class AdGuardProxy:
    """Proxy for AdGuard Home requests behind a GL.iNet router."""

    def __init__(self, settings: Settings, auth: RouterAuth):
        """Initialize the AdGuard Home proxy.

        Args:
            settings: Application settings
            auth: GL.iNet router authentication handler
        """
        self.settings = settings
        self.auth = auth

        # Configure client with the same SSL verification settings as the router
        # Note: We're using the same SSL verification for AdGuard as for the router
        # This may need to be separated in the future if they have different requirements
        if isinstance(self.settings.router_ssl_verify, str):
            logger.info(
                f"Using custom CA bundle for AdGuard SSL verification: "
                f"{self.settings.router_ssl_verify}"
            )
            self.client = httpx.AsyncClient(
                base_url=settings.adguard_url, verify=self.settings.router_ssl_verify
            )
        elif self.settings.router_ssl_verify is False:
            logger.warning(
                "SSL certificate verification is disabled for AdGuard. This is insecure!"
            )
            self.client = httpx.AsyncClient(base_url=settings.adguard_url, verify=False)
        else:
            logger.debug("Using system CA certificates for AdGuard SSL verification")
            self.client = httpx.AsyncClient(base_url=settings.adguard_url)

    async def handle_request(self, request: Request) -> Response:
        """Handle an incoming request and forward it to AdGuard Home.

        Args:
            request: The incoming request

        Returns:
            Response: The response from AdGuard Home
        """
        # Get the path and query parameters
        path = request.url.path
        query_params = dict(request.query_params)

        logger.debug(f"Handling {request.method} request to {path}")

        # Get request body if present
        body = await request.body() if request.method in ["POST", "PUT", "PATCH"] else None

        # Get headers, excluding host
        headers = dict(request.headers)
        headers.pop("host", None)

        # Add GL.iNet authentication cookie
        cookies = self.auth.get_auth_cookie()
        if cookies:
            logger.debug("Using existing authentication session")
        else:
            logger.debug("No authentication session available")

        try:
            # First attempt
            logger.debug("Attempting to forward request to AdGuard Home")
            return await self._forward_request(
                method=request.method,
                path=path,
                headers=headers,
                cookies=cookies,
                params=query_params,
                body=body,
            )
        except httpx.HTTPStatusError as e:
            # If authentication error (403), try to reauthenticate with GL.iNet router
            # and retry once
            if e.response.status_code // 100 == 4:
                logger.info(
                    "Authentication failed, attempting to reauthenticate with GL.iNet router"
                )
                logger.debug(f"Received {e.response.status_code}, initiating reauthentication")
                await self.auth.authenticate()
                cookies = self.auth.get_auth_cookie()
                logger.debug("Reauthentication completed, retrying request")

                # Second attempt after reauthentication
                return await self._forward_request(
                    method=request.method,
                    path=path,
                    headers=headers,
                    cookies=cookies,
                    params=query_params,
                    body=body,
                )
            else:
                # For other errors, return the error response
                logger.debug(f"Received error response: {e.response.status_code}")
                return Response(
                    content=e.response.content,
                    status_code=e.response.status_code,
                    headers=dict(e.response.headers),
                )
        except httpx.TransportError as e:
            # Handle SSL/TLS errors specifically
            logger.error(f"SSL/TLS error connecting to AdGuard Home: {e}")
            logger.info(
                "If AdGuard uses a self-signed certificate, "
                "set ROUTER_SSL_VERIFY=False or provide a CA bundle"
            )
            return JSONResponse(
                content={"error": f"SSL/TLS error: {str(e)}"},
                status_code=502,
            )
        except Exception as e:
            # Handle any other exceptions
            logger.error(f"Error forwarding request: {e}")
            return JSONResponse(
                content={"error": str(e)},
                status_code=500,
            )

    async def _forward_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        params: Dict[str, Any],
        body: Optional[bytes] = None,
    ) -> Response:
        """Forward a request to AdGuard Home with GL.iNet router authentication.

        Args:
            method: HTTP method
            path: Request path
            headers: Request headers
            cookies: Request cookies (including GL.iNet authentication cookie)
            params: Query parameters
            body: Request body

        Returns:
            Response: The response from AdGuard Home
        """
        logger.debug(f"Forwarding {method} request to {path}")

        # Create redacted versions of headers and cookies for logging
        log_headers = {**headers}
        log_cookies = {**cookies}

        # Redact sensitive headers if they exist
        sensitive_headers = ["authorization", "cookie", "set-cookie"]
        for header in sensitive_headers:
            if header in log_headers:
                log_headers[header] = "[REDACTED]"

        # Log request details at DEBUG level
        logger.debug(
            f"Request details:\n"
            f"  Method: {method}\n"
            f"  Path: {path}\n"
            f"  Headers: {log_headers}\n"
            f"  Cookies: {log_cookies}\n"
            f"  Params: {params}"
        )

        # Log body for JSON requests at DEBUG level, with potential password redaction
        if body and "application/json" in headers.get("content-type", ""):
            try:
                import json

                log_body = json.loads(body)

                # Redact password fields in JSON body
                if isinstance(log_body, dict):
                    if "password" in log_body:
                        log_body["password"] = "[REDACTED]"
                    if "params" in log_body and isinstance(log_body["params"], dict):
                        if "password" in log_body["params"]:
                            log_body["params"]["password"] = "[REDACTED]"

                logger.debug(f"  Body: {log_body}")
            except Exception:
                logger.debug(f"  Body: [binary data, {len(body)} bytes]")
        elif body:
            logger.debug(f"  Body: [binary data, {len(body)} bytes]")

        response = await self.client.request(
            method=method,
            url=path,
            headers=headers,
            cookies=cookies,
            params=params,
            content=body,
            timeout=30.0,
        )

        response.raise_for_status()

        # Log response at DEBUG level
        logger.debug(
            f"Response from AdGuard Home:\n"
            f"  Status: {response.status_code}\n"
            f"  Headers: {dict(response.headers)}"
        )

        # Log response content for JSON responses
        if "application/json" in response.headers.get("content-type", ""):
            try:
                logger.debug(f"  Content: {response.json()}")
            except Exception:
                logger.debug(f"  Content: [non-JSON data, {len(response.content)} bytes]")

        # Remove content-length header since response may have been modified
        response.headers.pop("content-length", None)

        # Create a Starlette response from the httpx response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
