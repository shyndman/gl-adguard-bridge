"""Main entry point for GL-AdGuard-Bridge."""

from gl_adguard_bridge.server import Server


def main():
    """Run the GL-AdGuard-Bridge server."""
    server = Server()
    server.run()


if __name__ == "__main__":
    main()
