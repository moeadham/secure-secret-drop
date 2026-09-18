# `cloudflared` setup for Secure Secret Drop

## What is required

Secure Secret Drop uses `cloudflared` only to create an anonymous, temporary Quick Tunnel. It requires the executable and outbound network access. It does **not** require a Cloudflare account, domain, login, API token, certificate, named tunnel, DNS record, configuration file, or background service.

Do not run `cloudflared tunnel login`, `cloudflared tunnel create`, `cloudflared service install`, or any DNS command for this skill. Do not modify or restart an existing named tunnel. The handoff CLI launches Quick Tunnels with `--config /dev/null`, so existing Cloudflare configuration is deliberately ignored.

Official sources:

- Installation documentation: https://developers.cloudflare.com/tunnel/downloads/
- Linux package repository: https://pkg.cloudflare.com/
- Releases: https://github.com/cloudflare/cloudflared/releases

Cloudflare supports `cloudflared` releases from approximately the latest year. Prefer the current stable package from an official channel rather than a stale distro copy.

## Agent setup procedure

1. Resolve the installed skill directory and run:

   ```bash
   python3 <skill-dir>/scripts/handoff.py doctor
   ```

2. If `cloudflared=ok`, do not reinstall, update, authenticate, or reconfigure it. Continue with the normal workflow.
3. If `cloudflared=missing`, inspect the OS, architecture, available package manager, and whether `sudo` is needed. Explain the exact installation command and obtain any approval required by the host policy. When terminal tools are available, perform the setup rather than delegating routine shell work to the user.
4. Install from one of the official methods below. Do not use an untrusted mirror or an arbitrary install script.
5. Verify the executable and rerun the skill check:

   ```bash
   cloudflared --version
   python3 <skill-dir>/scripts/handoff.py doctor
   ```

   Both commands must succeed before `create` is used.

## macOS

Homebrew is Cloudflare's documented installation method:

```bash
brew install cloudflared
```

Apple Silicon Homebrew normally installs it at `/opt/homebrew/bin/cloudflared`; Intel Homebrew normally uses `/usr/local/bin/cloudflared`. The CLI checks both paths even when a background agent has a restricted `PATH`.

If Homebrew is absent, do not install Homebrew solely for this skill without approval. Use Cloudflare's current Darwin release from the official downloads page, verify the downloaded artifact when verification material is available, and install the executable in a user-writable location such as `~/.local/bin/cloudflared`. Set `CLOUDFLARED_BIN` if that directory is not in the agent's `PATH`.

## Debian and Ubuntu

Use Cloudflare's stable `any` APT repository:

```bash
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update
sudo apt-get install cloudflared
```

Use the current signing key and repository instructions from `https://pkg.cloudflare.com/`; Cloudflare periodically rotates package-signing keys.

## RHEL, Fedora, CentOS, and Amazon Linux

Use Cloudflare's stable RPM repository:

```bash
curl -fsSL https://pkg.cloudflare.com/cloudflared.repo \
  | sudo tee /etc/yum.repos.d/cloudflared.repo >/dev/null
sudo dnf install cloudflared
```

On systems that use `yum` rather than `dnf`, replace the last command with:

```bash
sudo yum install cloudflared
```

## Arch Linux

Install the distribution package:

```bash
sudo pacman -Syu cloudflared
```

## Other Linux systems or no root access

Use the architecture-specific binary from Cloudflare's official downloads page. Determine architecture with `uname -m`, choose the matching current stable asset, verify it against release verification material when available, make it executable, and place it at `~/.local/bin/cloudflared`. Never guess the architecture or execute an HTML/error response as a binary.

If the executable is not in the process `PATH`, invoke the skill with an explicit path:

```bash
CLOUDFLARED_BIN="$HOME/.local/bin/cloudflared" \
  python3 <skill-dir>/scripts/handoff.py doctor
```

Set the same environment variable for subsequent invocations, or add `~/.local/bin` to the agent service's `PATH` and restart that service.

## Troubleshooting

- **`doctor` still says missing:** check `command -v cloudflared`, executable permissions, and the `PATH` of the actual agent process. Use `CLOUDFLARED_BIN=/absolute/path/to/cloudflared` when needed.
- **Do not solve a Quick Tunnel problem by logging in:** Quick Tunnels are credentialless. Login or named-tunnel configuration is unrelated.
- **Existing named tunnel on the machine:** leave it running and untouched. This skill uses `--config /dev/null` and terminates only child processes whose recorded command identity matches the specific receipt.
- **Network failure after installation:** confirm outbound HTTPS works and that the environment permits Cloudflare Tunnel traffic. Do not open an inbound firewall port; the connector initiates outbound connections.
- **Unsupported or old binary:** update through the same official package channel, verify `cloudflared --version`, then rerun `doctor`.
