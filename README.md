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

Just say:

> Send me a secure drop link.

Your agent will send you a temporary, single-use link. Open it, enter the requested secret, submit it, and reply that you are done.

## What to expect

- The link expires automatically and accepts one submission.
- Secret values are not printed in chat or command output.
- Existing destination keys are not replaced without explicit approval.
- Temporary forms can be cancelled at any time.
- macOS and Linux are supported.

Cloudflare terminates HTTPS for the temporary Quick Tunnel, so it is part of the trust boundary. This skill is intended for short-lived development secret handoffs.
