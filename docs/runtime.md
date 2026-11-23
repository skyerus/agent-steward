# Runtime requirements

Prepare the runtime on the target host before running the [integration installer](../INSTALL.md). The setup uses the following versions from the original deployment.

| Component | Tested version |
| --- | --- |
| OpenClaw | [`fc6c8a5e5786a144ff73df49df504e366db4803e`](https://github.com/skyerus/openclaw/tree/fc6c8a5e5786a144ff73df49df504e366db4803e) |
| Node.js | `26.13.1` |
| agentgateway | `1.7.0` |
| Model Context Protocol SDK | `1.32.2` |
| Casbin | `5.51.1` |

## Host layout

- Run the OpenClaw gateway as `sable-claw`, with its state in `/var/lib/sable-claw/state` and the launcher at `/opt/sable/review-gateway/claw`.
- Run the native worker as `sable-codex`. Its workspace root is `/var/lib/sable-codex/workspaces`, and it publishes the runtime receipt at `/run/sable-native-policy/receipt.json`. Its private TLS relay uses `/etc/sable-codex/Caddyfile` and listens on loopback port `17759`.
- Prepare the review services `sable-review-policy.service` and `sable-agentgateway.service`. The gateway reads `/opt/sable/review-gateway/agentgateway.yaml`. Use a separate identity for the credential broker and keep provider secrets, the broker socket, and the review configuration outside the worker's reach.
- Install Node.js and npm under `/opt/sable/node` and the MCP SDK under `/opt/sable/integrations/node_modules`. The installer installs its own locked Casbin dependencies.
- Point a hostname at the target host for the HTTPS browser consent callback. The installer uses Caddy for public consent and adds Git routing to the existing private relay.

Configure the host's inference account and Discord bot privately. Run the installer with the new hostname and Discord administrator IDs. Verify Discord routing and the review gate before connecting providers. Integration Admin can then enrol and share the accounts on the new host. Keep any credential transfer in your private deployment process.
