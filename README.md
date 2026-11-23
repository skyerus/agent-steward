# Agent Steward

Run a self-hosted fleet from Discord. Integration Admin creates agents, sets up their channels and workspaces, and manages integration access. Agents can schedule their own work and connect accounts they are authorised to use.

The broker owns provider credentials and binds them to a connection and destination. The review gateway sends Luna the proposed operation and verified Discord context before each integration call. Local workspace work runs under a separate Linux user. Integration Admin can deploy connector source to downstream workspaces and register GitHub Apps to power native Git and GitHub MCP through the same broker.

## Install or migrate

The included installer configures Agent Steward on a prepared Linux host with systemd, an OpenClaw gateway, an isolated native worker and a Discord bot. A VPS is one way to run this host. See the [runtime requirements](docs/runtime.md) and the [installation guide](INSTALL.md).

The tested OpenClaw source is [the Discord voice evidence branch in the fork, pinned at `fc6c8a5e`](https://github.com/skyerus/openclaw/tree/fc6c8a5e5786a144ff73df49df504e366db4803e). Keep that revision pinned while the Discord voice changes are upstreamed.

## Test

With Node.js 26, Python 3 and Git installed, run:

```sh
npm ci --prefix broker --ignore-scripts
npm test --prefix broker
python3 -m unittest discover -s broker -p 'test_*.py'
bash -n install-integration-setup.sh
```

The Linux ownership tests require root and the `sable-codex` and `sable-claw` service users. They use temporary workspaces. Provider tests use fixtures and require no GitHub or Discord credentials.
