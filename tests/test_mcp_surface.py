"""End-to-end over the real MCP stdio transport.

Proves the tool surface actually works as an MCP server, and that a provider
payload never reaches the client on an error path.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_stdio_server_lists_and_calls_tools(tmp_path):
    import asyncio
    import json

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from conftest import write_policy

    policy = write_policy(tmp_path, mode="dry_run")
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))

    async def run():
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m", "mailgate.server",
                "--policy", str(policy),
                "--state-dir", str(tmp_path / "state"),
                "--no-approval-socket",
            ],
            env=env,
            cwd=str(ROOT),
        )
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                tools = {t.name for t in (await session.list_tools()).tools}
                assert tools == {
                    "list_accounts", "list_folders", "list_messages", "get_message",
                    "apply_labels", "move_message",
                }
                acc = json.loads((await session.call_tool("list_accounts", {})).content[0].text)
                assert acc["mode"] == "dry_run"
                assert acc["accounts"][0]["account"] == "demo"
                lst = json.loads(
                    (
                        await session.call_tool(
                            "list_messages", {"account": "demo", "folder": "INBOX", "limit": 3}
                        )
                    ).content[0].text
                )
                assert len(lst["messages"]) == 3
                handle = lst["messages"][0]["handle"]
                got = json.loads(
                    (
                        await session.call_tool(
                            "get_message", {"account": "demo", "handle": handle}
                        )
                    ).content[0].text
                )
                assert got["body"].startswith("<<<UNTRUSTED_EMAIL_BODY ")
                mv = json.loads(
                    (
                        await session.call_tool(
                            "move_message",
                            {
                                "account": "demo", "handle": handle,
                                "destination": "Archive-2024",
                                "reason_code": "other", "idempotency_key": "k1",
                            },
                        )
                    ).content[0].text
                )
                assert mv["status"] == "denied"
                assert mv["code"] == "destructive_destination"
                # an unreachable account yields a structured code, not a traceback
                err = json.loads(
                    (
                        await session.call_tool("list_folders", {"account": "nope"})
                    ).content[0].text
                )
                assert err["error"] == "unknown_account"
                assert "Traceback" not in json.dumps(err)

    asyncio.run(asyncio.wait_for(run(), timeout=60))
