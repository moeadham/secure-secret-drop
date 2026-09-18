# Security model

## Invariants

- Public TLS terminates at Cloudflare; there is no browser E2EE in this MVP.
- The origin listens on an OS-assigned port at IPv4 loopback only.
- Quick Tunnel startup always passes `--no-autoupdate --config /dev/null` and an explicit `127.0.0.1` origin.
- Form URL capability and CSRF nonce are independently generated with Python `secrets`; neither appears in process arguments or nonsecret state.
- GET/HEAD render only. A lock serializes POST acceptance, receipt creation, and state transition so one POST wins.
- Expected fields must appear exactly once. Unknown, duplicate, missing, oversized, malformed, and wrong-content-type submissions are rejected before receipt creation.
- Responses use `no-store`, a deny-by-default CSP with `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`.
- The HTTP server suppresses access logging. `cloudflared` receives only the loopback origin URL, never form data.
- Child termination first checks recorded PID command identity tokens. No broad `pkill` is used, so unrelated/named tunnel processes are not targeted.

## Residual risks

Cloudflare can technically observe values because its edge terminates TLS. A compromised browser, Cloudflare edge, local account, host, or plaintext receipt can expose values. Capability URLs can be used by anyone who obtains them before expiry, though CSRF prevents a blind POST without first loading the form. Disk encryption is recommended. This tool is not a vault and intentionally retains only short-lived plaintext receipts with mode 0600.

## Lifecycle

Pending forms expire at their deadline and remove private capability material. Successful POST removes capability material, marks submitted, and tears down serving. Consumption atomically writes the approved destination at mode 0600, then removes the receipt. Cancel/expiry remove both receipt and private-form data. Minimal state retains receipt ID, field names, timestamps, terminal status, loopback port, and validated child process metadata; it never contains submitted values.
