# Zireael-RMM

A self-hosted remote support tool for family and personal use. The Linux server provides a passkey-protected web console; a single Windows agent executable provides remote desktop, PowerShell, and file transfers. **Preview:** local and container checks have passed, but the Windows agent and public-network deployment still need real-world testing.

## Run the server

Install Docker and the Docker Compose plugin on a Linux host. Point a domain at that host and allow inbound TCP **8443**. For a new Let's Encrypt certificate, also route public TCP **80** to the host. Then run:

```sh
git clone https://github.com/Harrison-Wells-Cyber/Zireael-RMM.git
cd Zireael-RMM
./start.sh --domain support.example.com
```

Replace `support.example.com` with your domain. The script builds the image, checks settings, starts the container, and prints a one-time setup token. Open `https://YOUR-DOMAIN:8443/admin`, enter the token within 15 minutes, and register a passkey. Add a second passkey for recovery. Further administrators can be invited from **Users**; each registers their own passkey. Docker restarts the container and retains its data volume. Keep the same project directory and Docker volume when updating.

The launcher accepts `--bind` and `--port` for a different public listener, and `--origin` when the browser uses a different HTTPS origin (for example, through a reverse proxy). Run `./start.sh --help` for all flags. It checks existing Certbot or app-cached certificates before opening the HTTP challenge port. A cached certificate still needs port 80 for later HTTP-01 renewal unless you route public 443 for TLS-ALPN renewal. External certificate managers can be used with `--tls-cert` and `--tls-key`, optionally `--cert-dir` for symlinked certificate trees; supplied files must be readable by container UID 65532. For root-only Certbot keys, copy the certificate and key to a protected directory readable by that UID and pass `--cert-dir`; refresh those copies after renewal. Files are reloaded on new TLS handshakes. Other compatible ACME issuers can be selected with `--acme-directory`.

## Help someone

Send them the public homepage, `https://YOUR-DOMAIN:8443/`. It always shows the default one-line PowerShell command. They paste it into ordinary PowerShell and tell you the eight-character pairing code. In **Agents**, enter that code to approve the pending device, then click the online device to use desktop, PowerShell, or files. The default installation needs no elevation and reconnects when that Windows user signs in.

For access before sign-in, create a private **service** support link in the console and have the person run its command in an already elevated PowerShell. For one session with no persistence, create a **temporary** link instead. Each private link is single-use and expires after 15 minutes.

The command shown in a browser must itself be trusted: TLS inspection that can alter the page can alter the command. The agent's encrypted inner connection protects subsequent agent traffic through TLS inspection, but cannot authenticate a replaced installer command. Admin browser traffic also requires a trusted HTTPS path.

## Status and licensing

The server, web console, agent transport, and Windows cross-builds have been checked locally. Real Windows desktop behavior, service sessions, and internet exposure remain to be tested. This is not a security certification; use an isolated test deployment first. Agent certificates currently expire after one year without automatic renewal. Binaries are not code-signed and there is no automatic updater or account recovery beyond a second passkey and protected backups.

Original project code is [CC0](LICENSE). Bundled desktop components and dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md) and the license/provenance files in `third_party/`.
