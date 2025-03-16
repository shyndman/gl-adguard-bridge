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

        # Get request body if present
        body = await request.body() if request.method in ["POST", "PUT", "PATCH"] else None

        # Get headers, excluding host
        headers = dict(request.headers)
        headers.pop("host", None)

        # Add GL.iNet authentication cookie
        cookies = self.auth.get_auth_cookie()

        try:
            # First attempt
            return await self._forward_request(
                method=request.method,
                path=path,
                headers=headers,
                cookies=cookies,
                params=query_params,
                body=body,
            )
        except httpx.HTTPStatusError as e:
            # If authentication error (401), try to reauthenticate with GL.iNet router
            # and retry once
            if e.response.status_code == 401:
                logger.info(
                    "Authentication failed, attempting to reauthenticate with GL.iNet router"
                )
                await self.auth.authenticate()
                cookies = self.auth.get_auth_cookie()

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
                return Response(
                    content=e.response.content,
                    status_code=e.response.status_code,
                    headers=dict(e.response.headers),
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

        # Create a Starlette response from the httpx response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
