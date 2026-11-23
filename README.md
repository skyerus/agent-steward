# Agent Steward

**Manage a self-hosted AI agent fleet from Discord.**

Start with one admin agent and use it to create OpenClaw agents, provision private channels and writable workspaces, and grant access to integrations. Agents can schedule their own work and set up their own connections. Agent Steward brings routine administration into Discord so you can operate a growing fleet from the same place.

The credential broker keeps API keys and OAuth credentials outside agent workspaces. Before an MCP tool call or native Git operation, Luna reviews the proposed action against verified Discord context or the authorisation saved for a scheduled job.

## What you can manage

- **Agent provisioning** from a private Discord chat, including instructions, channels, workspaces, and integration access.
- **Integration setup and sharing** with browser-based OAuth, per-agent grants, and connector code deployment.
- **Git and GitHub MCP** through one GitHub App connection, with reviewed clone, pull, push, and API operations.

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
