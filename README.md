# Secure Secret Drop

Dead-simple secret sharing with an AI agent. It uses Cloudflare's free Quick Tunnels to generate a single-use URL hosted on the agent's machine, so you can securely drop a secret, password, or credential—then have it disappear.

## Requirements

- A local AI agent that can run shell commands and read a `SKILL.md`
- Python 3
- `cloudflared`

No Cloudflare account, domain, or login is required. If `cloudflared` is missing, the skill guides the agent through installing it from an official source.

## Install

```bash
npx skills add moeadham/secure-secret-drop
```

## Use it

Ask your agent naturally:

> Create a secure secret drop for `OPENAI_API_KEY` and save it to `/path/to/project/.env`.

Your agent will send you a temporary link. Open it, enter the value, submit once, and reply that you are done.

You can also request multiple fields or JSON output:

> Create a secure secret drop for `CLIENT_ID` and `CLIENT_SECRET`, then save them to `/path/to/config.json`.

## What to expect

- The link expires automatically and accepts one submission.
- Secret values are not printed in chat or command output.
- Existing destination keys are not replaced without explicit approval.
- Temporary forms can be cancelled at any time.
- macOS and Linux are supported.

Cloudflare terminates HTTPS for the temporary Quick Tunnel, so it is part of the trust boundary. This skill is intended for short-lived development secret handoffs.
