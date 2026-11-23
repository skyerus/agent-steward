import json
import urllib.error
import urllib.request


def check(port, expected_tool_count, test_denial=False):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

    def exchange(method, params, identity=None):
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if identity is not None:
            body["id"] = identity
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/mcp", json.dumps(body).encode(), headers
        )
        try:
            response = urllib.request.urlopen(request, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            text = response.read().decode()
            sid = response.headers.get("Mcp-Session-Id")
            if sid:
                headers["Mcp-Session-Id"] = sid
            if response.headers.get_content_type() == "text/event-stream":
                text = "\n".join(line[5:].strip() for line in text.splitlines() if line.startswith("data:"))
            return response.status, json.loads(text) if text else {}

    status, initialized = exchange("initialize", {"protocolVersion": "2025-11-25",
        "clientInfo": {"name": "sable-verification", "version": "1"}, "capabilities": {}}, 1)
    assert status == 200 and "result" in initialized, (port, status, list(initialized))
    headers["MCP-Protocol-Version"] = initialized["result"]["protocolVersion"]
    status, _ = exchange("notifications/initialized", {})
    assert status in (200, 202, 204), (port, status)
    status, listing = exchange("tools/list", {}, 2)
    assert status == 200, (port, status)
    tools = listing["result"]["tools"]
    assert len(tools) >= expected_tool_count, (port, len(tools))
    for tool in tools:
        assert "review_context_messages" in tool["inputSchema"]["required"], (port, tool["name"])
    print(f"{port}: {len(tools)} tools require review context", flush=True)
    if test_denial:
        names = {tool["name"].split("__")[-1]: tool["name"] for tool in tools}
        fixture = {"id": "verification-fixture", "revision": 1}
        for index, (tool, params) in enumerate((
            ("list_connections", {}),
            ("diagnose_connection", fixture),
            ("add_connection", {"label": "Unauthorized smoke fixture", "endpoint": "https://fixture.example.com/mcp"}),
            ("edit_connection", {**fixture, "endpoint": "https://fixture.example.com/mcp"}),
            ("delete_connection", fixture),
            ("begin_sign_in", fixture),
            ("begin_oauth_client_setup", fixture),
            ("confirm_sign_in", {**fixture, "code": "12345678"}),
            ("list_connection_tools", fixture),
            ("call_connection_tool", {**fixture, "name": "read_status", "arguments": {}}),
            ("list_connection_access", fixture),
            ("grant_connection_access", {**fixture, "agentId": "fixture-agent"}),
            ("revoke_connection_access", {**fixture, "agentId": "fixture-agent"}),
            ("list_managed_agents", {}),
            ("create_agent", {"agentId": "fixture-agent", "name": "Fixture Agent"}),
            ("rename_agent", {"agentId": "fixture-agent", "name": "Renamed Fixture"}),
            ("set_agent_instructions", {"agentId": "fixture-agent", "instructions": "Synthetic instructions."}),
            ("bind_agent_channel", {"agentId": "fixture-agent", "channelId": "123456789012345678"}),
            ("prepare_discord_server", {"server": "Fixture Discord", "agentIds": ["fixture-agent"]}),
            ("discord_server_setup_status", {"requestId": "0" * 32}),
            ("list_discord_access", {}),
            ("update_discord_channel_access", {"channel": "fixture", "onlyUsers": []}),
            ("update_discord_dm_access", {"user": "123456789012345678", "agentId": "main"}),
            ("cancel_discord_server_setup", {"requestId": "0" * 32}),
        ), start=3):
            _, result = exchange("tools/call", {"name": names[tool],
                "arguments": {**params, "review_context_messages": 1}}, index)
            assert "A current Luna approval" in json.dumps(result), (tool, result.get("id"), list(result))
            print(f"{tool}: blocked without Luna permit", flush=True)


if __name__ == "__main__":
    for port in (17891, 17892, 17893, 17894):
        check(port, 1)
    check(17895, 24, test_denial=True)
