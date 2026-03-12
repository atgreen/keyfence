# Example: Claude Code with GitHub Token

This example shows how to give an agent access to GitHub without ever
putting the real GitHub PAT in the agent's environment.

## The problem

You want an agent to `git push`, `gh pr create`, and interact with your
GitHub repos. But handing your PAT directly to an AI agent means:

- The token could leak through logs, tool output, or prompt injection.
- There is no way to limit which hosts the token can reach.
- If the token escapes the container, it works everywhere, forever.

## The solution

KeyFence sits between the agent and GitHub as an HTTPS proxy sidecar in
a podman pod. You give KeyFence your real GitHub PAT, and it gives you
back a `kf_` token that:

1. Only works through the KeyFence proxy.
2. Only reaches the destinations you specify (github.com, api.github.com).
3. Expires after a short TTL.

The agent never sees the real PAT. If the `kf_` token leaks, it is useless
outside the proxy and expires quickly.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  podman pod (shared network namespace)              │
│                                                     │
│  ┌───────────────┐         ┌──────────────────┐    │
│  │ Agent         │─127.0.0.1──▶  KeyFence     │    │
│  │               │  :10210 │   (proxy + swap)  │    │
│  │ GITHUB_TOKEN  │         │                   │    │
│  │  = kf_abc...  │         │  kf_abc → ghp_... │    │
│  └───────────────┘         └────────┬─────────┘    │
│                                     │               │
└─────────────────────────────────────┼───────────────┘
                                      │
                                      ▼
                               github.com
                               api.github.com
```

- Both containers share **localhost** via the pod's network namespace.
- The `kf_` token is swapped for the real PAT inside KeyFence at proxy time.

## Quick start

```bash
export GITHUB_TOKEN=ghp_your_real_pat_here
./setup.sh
```

## What happens if the token leaks?

If an attacker extracts the `kf_` token from the agent's environment:

- **Outside the proxy**: The token is meaningless. GitHub does not recognize
  `kf_` tokens. There is no way to use it without going through KeyFence.
- **After TTL expiry**: Even through the proxy, the token is rejected.
  Default TTL in this example is 1 hour.
- **Wrong destination**: If someone tries to use the token to reach
  `evil.com` through the proxy, KeyFence blocks it because the token is
  locked to `github.com` and `api.github.com`.

## Cleanup

```bash
podman pod rm -f keyfence-github
podman volume rm keyfence-github-certs
```

## Files

| File                  | Purpose                                          |
|-----------------------|--------------------------------------------------|
| `Containerfile.agent` | Agent image (Alpine + gh CLI + git)              |
| `setup.sh`            | Automated setup: build, pod, token, run agent    |
| `README.md`           | This file                                        |
