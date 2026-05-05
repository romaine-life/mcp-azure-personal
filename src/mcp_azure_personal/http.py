"""HTTP entrypoint for the personal Azure MCP server."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route

from .tools import register_tools


def build_app() -> Starlette:
    mcp = FastMCP(
        "azure-personal-mcp",
        stateless_http=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )
    register_tools(mcp)

    async def healthz(_: Request) -> Response:
        return Response("ok", media_type="text/plain")

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with mcp.session_manager.run():
            yield

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        lifespan=lifespan,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("PORT", "8080"))
    uvicorn_kwargs = {"host": "127.0.0.1", "port": port}

    import uvicorn

    uvicorn.run(build_app(), **uvicorn_kwargs)


if __name__ == "__main__":
    main()
