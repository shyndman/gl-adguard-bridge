# GL-AdGuard-Bridge

HTTP proxy server to support Home Assistant integration with AdGuard Home behind GL.iNet routers requiring authentication.

## Purpose

This proxy server sits between Home Assistant and AdGuard Home when the AdGuard Home instance is behind a GL.iNet router that requires authentication. The proxy:

1. Receives requests intended for the AdGuard Home API
2. Authenticates with the GL.iNet router using its API
3. Forwards the requests to the real AdGuard Home with the necessary authentication cookies
4. Returns the responses to Home Assistant
5. Handles reauthentication if needed

## GL.iNet Router Compatibility

This proxy is specifically designed to work with GL.iNet routers using their authentication API as documented here:
https://web.archive.org/web/20240121142533/https://dev.gl-inet.com/router-4.x-api/

The proxy uses the GL.iNet authentication endpoints to obtain a session ID (sid) and adds it as an "Admin-Token" cookie for AdGuard Home requests. The authentication follows the standard GL.iNet API flow:

1. Get challenge parameters from the router
2. Calculate password hash using the provided salt
3. Login with the hash to obtain a session ID
4. Use the session ID as a cookie for subsequent requests

## Configuration

The server is configured using environment variables:

- `ROUTER_HOST`: Hostname or IP address of the GL.iNet router (e.g., 192.168.8.1)
- `ROUTER_USERNAME`: Username for GL.iNet router authentication (defaults to "root")
- `ROUTER_PASSWORD`: Password for GL.iNet router authentication
- `ADGUARD_URL`: URL of the actual AdGuard Home instance
- `LOG_LEVEL`: Logging level (default: INFO)
- `HOST`: Host to bind the server to (default: 0.0.0.0)
- `PORT`: Port to run the server on (default: 8000)

## Running with Docker

```bash
docker run -p 8000:8000 \
  -e ROUTER_HOST=192.168.8.1 \
  -e ROUTER_PASSWORD=password \
  -e ADGUARD_URL=http://adguard.local \
  gl-adguard-bridge
```

## Development

1. Clone the repository
2. Install dependencies with uv: `uv pip install -e ".[dev]"`
3. Run the server: `python -m gl_adguard_bridge`

## License

MIT
