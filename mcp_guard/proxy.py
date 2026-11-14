"""The transparent stdio proxy.

    agent (MCP client)  <--stdio-->  mcp-guard  <--stdio-->  downstream MCP server

The proxy does not implement MCP methods itself. It uses the official SDK's two
stdio transports back to back and pumps JSON-RPC messages between them:

  * `stdio_server()`  - our own stdin/stdout, facing the agent
  * `stdio_client()`  - spawns the downstream server, facing its stdin/stdout

Every message is forwarded unchanged, except at three inspection points:

  1. response to `tools/list`  -> guard.filter_tools()   (tool poisoning)
  2. request  `tools/call`     -> guard.check_call()     (action policy)
  3. response to `tools/call`  -> guard.check_result()   (indirect injection)

Because we only look at the JSON-RPC envelope plus those two methods, the proxy
works for both the handshake protocol (<= 2025-11-25) and the stateless
2026-07-28 protocol, and passes through methods it knows nothing about.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import anyio
from mcp import StdioServerParameters, stdio_client, stdio_server
from mcp.shared.message import SessionMessage
from mcp_types import INTERNAL_ERROR, ErrorData, JSONRPCError, JSONRPCRequest, JSONRPCResponse

from .config import ServerConfig
from .guard import Guard, blocked_result


def _log(text: str) -> None:
    # stdout is the protocol channel, so diagnostics go to stderr only.
    print(f"[mcp-guard] {text}", file=sys.stderr, flush=True)


async def run_proxy(server: ServerConfig, guard: Guard | None) -> None:
    """Run until the agent closes our stdin or the downstream server exits."""
    params = StdioServerParameters(command=server.command, args=server.args, env=server.env or None, cwd=server.cwd)

    async with stdio_server() as (from_agent, to_agent), stdio_client(params) as (from_server, to_server):
        # Requests we forwarded and still expect a response for: id -> (method, tool name).
        # Only tools/list and tools/call are tracked; everything else needs no inspection.
        pending: dict[Any, tuple[str, str]] = {}

        async def agent_to_server() -> None:
            async for item in from_agent:
                if isinstance(item, Exception):
                    _log(f"dropped unparseable message from agent: {item}")
                    continue
                message = item.message
                if isinstance(message, JSONRPCRequest) and message.method == "tools/call" and guard:
                    params_ = message.params or {}
                    tool = str(params_.get("name", ""))
                    try:
                        block_reason = await guard.check_call(tool, params_.get("arguments") or {})
                    except Exception as exc:  # fail closed: never forward an unchecked call
                        _log(f"check_call failed: {exc!r}")
                        block_reason = "MCP Guard internal error while checking this call."
                    if block_reason is not None:
                        reply = JSONRPCResponse(jsonrpc="2.0", id=message.id, result=blocked_result(block_reason))
                        await to_agent.send(SessionMessage(reply))
                        continue
                    pending[message.id] = ("tools/call", tool)
                elif isinstance(message, JSONRPCRequest) and message.method == "tools/list" and guard:
                    pending[message.id] = ("tools/list", "")
                await to_server.send(item)

        async def server_to_agent() -> None:
            async for item in from_server:
                if isinstance(item, Exception):
                    _log(f"dropped unparseable message from server: {item}")
                    continue
                message = item.message
                if isinstance(message, JSONRPCError):
                    pending.pop(message.id, None)
                elif isinstance(message, JSONRPCResponse) and message.id in pending and guard:
                    method, tool = pending.pop(message.id)
                    try:
                        if method == "tools/list":
                            tools = message.result.get("tools") or []
                            result = {**message.result, "tools": await guard.filter_tools(tools)}
                        else:
                            result = await guard.check_result(tool, message.result)
                        item = SessionMessage(JSONRPCResponse(jsonrpc="2.0", id=message.id, result=result))
                    except Exception as exc:  # fail closed: never forward an unchecked response
                        _log(f"inspection of {method} response failed: {exc!r}")
                        error = ErrorData(code=INTERNAL_ERROR, message="MCP Guard internal error")
                        item = SessionMessage(JSONRPCError(jsonrpc="2.0", id=message.id, error=error))
                await to_agent.send(item)

        async with anyio.create_task_group() as tg:

            async def run_then_stop(pump) -> None:
                # Either side closing ends the proxy: stop the other pump too.
                await pump()
                tg.cancel_scope.cancel()

            async def server_side() -> None:
                await server_to_agent()
                # The downstream server went away while the agent is still connected.
                # Our stdin reader is blocked in a thread that cannot be cancelled, so a
                # normal shutdown would hang until the agent hangs up: flush and exit hard.
                _log("downstream server closed the connection; exiting")
                await to_agent.aclose()
                await anyio.sleep(0.2)
                os._exit(1)

            tg.start_soon(run_then_stop, agent_to_server)
            tg.start_soon(server_side)

        # Closing our write stream lets the SDK's stdout writer task finish, so the
        # process exits promptly instead of waiting to be killed by the agent host.
        await to_agent.aclose()
