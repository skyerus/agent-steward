---
name: integration-setup
description: Set up, reconnect, edit, or remove integrations from Discord through the shared integration broker. Use when a requester asks to connect a service or sends the browser pairing code for a pending connection.
---

# Integration setup

Use the reviewed `integrations` MCP tools.

- When a tool requires a connection ID and revision, pass both from the same connection returned by `list_connections` or the preceding management call. Refresh the connection details if its revision changes.
- Use `list_connections` to find current connections. For a new connection, use the service's official HTTPS MCP endpoint and a clear label. If the service needs a different setup flow, explain the specific dependency.
- Use `add_connection` for the current agent. Use `diagnose_connection` with the returned ID and revision to find the provider's setup method.
- For `browser_oauth`, start with `begin_sign_in`. Use `begin_oauth_client_setup` for `github_manifest` or `secure_client_intake` on a connection you manage. On GitHub, use the organization or repository permission level requested by the user. The requester creates the app in GitHub, installs it on their selected repositories, returns to the paired tab, and completes sign-in. Other providers use the paired browser's private client credential form.
- Send the broker's link to the requester. Ask them to open it on their device and paste the eight-digit pairing code back into Discord.
- When the requester sends the code, call `confirm_sign_in` for the same connection. Include the original setup request and the current code message in `review_context_messages`. Ask the requester to return to the same browser tab, check confirmation, and complete the provider consent screen.
- Check `list_connections` after consent and use `diagnose_connection` with `verify: true` to confirm the remote MCP server responds. Report the verified result. A destination edit requires fresh sign-in, and a rename keeps the existing sign-in.

Own setup and troubleshooting through verification. Use diagnostics and the available official provider guidance to identify the failed stage, then try the supported next steps. If the requester needs to approve or enter something on a provider page, tell them exactly what to do. Escalate only when a specific step requires access or capabilities beyond your tools. State what failed, what you tried, and what help is needed.

For Luna denials, use the reason to correct the call or its context. Look for the original authorization in the authenticated conversation and resolve recipient names with the available tools. Ask for clarification only when the intent or target is still uncertain after checking.

The requester uses the browser for provider consent. Ask only for the broker's pairing code in Discord. The broker holds provider credentials and answers each reviewed call.

New connections are private to their owning agent. Direct requests to share or revoke access to Integration Admin. After an administrator grants access, the recipient agent can find the connection in `list_connections`. An account shared with other agents is managed by Integration Admin.

## Native Git with GitHub

When a requester needs native Git as well as GitHub MCP, use an existing GitHub App installation connection if appropriate. Otherwise, Integration Admin creates a connection using `add_connection` with `endpoint: https://api.githubcopilot.com/mcp/` and `agentId: integration-admin`. Then call `begin_github_installation` with its ID and revision, the exact GitHub account, the requested `read` or `write` access, and `organization: true` for an organisation. After pairing, the owner registers the app, installs it on all repositories of the requested account, and clicks **Verify installation** in the paired tab. If verification fails, check the installation account and selected permissions. Use `diagnose_connection` to verify and share only as requested.

Use `authorize_git_read` for clone or fetch and `authorize_git_push` for one reviewed branch or tag update. Pass the returned permit as the named HTTP header using command-scoped Git config, trust the private relay CA from the tool result, and keep provider keys and permits out of chat and Git config files. Integration Admin can deliver reviewed helper code to a downstream native workspace with `deploy_agent_connector`. Use the broker tools for provider calls and omit credentials from connector source.

## Requesting scoped access

Use `request_integration_access` and send the returned approval link for any connected integration. For native Git, specify the exact repository and read or write. For Discord, specify the channel name, mention or ID, with separate `threadPermission` if needed. For any MCP connection, set `provider: mcp` and use its exact label or ID as `resource`. Use the existing tool catalog to request exact `tools`. Only use `allTools: true` when the user asked for the whole connection, including future tools. A standing grant uses `audience: all-downstream` and must be requested by Integration Admin.

The approval page displays the account, resource, scope, and recipient. Pair a new approval browser in your private Integration Admin DM with `pair_approval_browser` using the exact request ID and code from that message. Return to the browser and approve. Subsequent links work from that paired browser until its session expires. Check `integration_access_status` after approval. Use the connection ID and revision from the approved grant when requesting a native Git permit.

After a scoped MCP grant is approved, use `list_connections` and `list_connection_tools` to discover the approved connection and tools. Execute through `call_connection_tool`. Agent Steward scopes MCP access to the named operations. A provider's finer-grained permissions still apply.

Use `discord_read_messages` and `discord_post_message` for approved Discord resources. Supply exact channel and server IDs. A thread grant follows the actual parent returned by Discord. Existing Discord bot permissions apply. Integration Admin can list and revoke exact scopes with `list_scoped_integration_access` and `revoke_scoped_integration_access`. All integration operations go through the reviewer.
