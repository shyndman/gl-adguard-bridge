"""Main server module for GL-AdGuard-Bridge for GL.iNet routers."""

import sys

import uvicorn
from loguru import logger
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from gl_adguard_bridge.auth import RouterAuth
from gl_adguard_bridge.config import get_settings
from gl_adguard_bridge.proxy import AdGuardProxy


class Server:
    """GL-AdGuard-Bridge server for GL.iNet routers."""

    def __init__(self):
        """Initialize the GL.iNet router proxy server."""
        # Load settings
        self.settings = get_settings()

        # Configure logging
        logger.remove()
        logger.add(
            sys.stderr,
            level=self.settings.log_level,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
                "<level>{message}</level>"
            ),
        )

        # Initialize authentication and proxy
        self.auth = RouterAuth(self.settings)
        self.proxy = AdGuardProxy(self.settings, self.auth)

        # Create Starlette application
        self.app = Starlette(
            debug=self.settings.log_level == "DEBUG",
            routes=[
                Route(
                    "/{path:path}",
                    self.handle_request,
                    methods=[
                        "GET", "POST", "PUT", "DELETE",
                        "PATCH", "HEAD", "OPTIONS"
                    ]
                ),
            ],
            on_startup=[self.startup],
            on_shutdown=[self.shutdown],
        )

    async def startup(self):
        """Startup event handler."""
        logger.info(
            f"Starting GL-AdGuard-Bridge server for GL.iNet routers on "
            f"{self.settings.host}:{self.settings.port}"
        )
        logger.info(f"Forwarding requests to {self.settings.adguard_url}")

        # Authenticate with the router
        try:
            await self.auth.authenticate()
        except Exception as e:
            logger.error(f"Failed to authenticate with GL.iNet router: {e}")
            # Continue anyway, we'll try to authenticate on the first request

    async def shutdown(self):
        """Shutdown event handler."""
        logger.info("Shutting down GL-AdGuard-Bridge server")
        await self.auth.close()
        await self.proxy.close()

    async def handle_request(self, request: Request) -> Response:
        """Handle all incoming requests.

        Args:
            request: The incoming request

        Returns:
            Response: The response from AdGuard Home
        """
        return await self.proxy.handle_request(request)

    def run(self):
        """Run the server."""
        uvicorn.run(
            self.app,
            host=self.settings.host,
            port=self.settings.port,
            log_level=self.settings.log_level.lower(),
        )


def create_app():
    """Create the Starlette application for the GL.iNet router proxy.

    Returns:
        Starlette: The Starlette application
    """
    server = Server()
    return server.app
