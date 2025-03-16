"""Configuration module for GL-AdGuard-Bridge."""

import os

from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Application settings loaded from environment variables."""

    # Router authentication settings
    router_host: str = Field(
        ...,
        description="Hostname or IP address of the GL.iNet router (e.g., 192.168.8.1)"
    )
    router_username: str = Field(
        "root",
        description="Username for GL.iNet router authentication (usually 'root')"
    )
    router_password: str = Field(
        ...,
        description="Password for GL.iNet router authentication"
    )

    # AdGuard Home settings
    adguard_url: str = Field(..., description="URL of the actual AdGuard Home instance")

    # Server settings
    host: str = Field("0.0.0.0", description="Host to bind the server to")
    port: int = Field(8000, description="Port to run the server on")

    # Logging settings
    log_level: str = Field("INFO", description="Logging level")

    @property
    def router_rpc_url(self) -> str:
        """Get the full URL for the GL.iNet router RPC endpoint.

        According to the GL.iNet API documentation:
        https://web.archive.org/web/20240121142533/https://dev.gl-inet.com/router-4.x-api/
        The HTTP request path for all APIs is /rpc
        """
        return f"https://{self.router_host}/rpc"


def get_settings() -> Settings:
    """Load settings from environment variables."""
    return Settings(
        router_host=os.environ["ROUTER_HOST"],
        router_username=os.environ.get("ROUTER_USERNAME", "root"),
        router_password=os.environ["ROUTER_PASSWORD"],
        adguard_url=os.environ["ADGUARD_URL"],
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
    )
