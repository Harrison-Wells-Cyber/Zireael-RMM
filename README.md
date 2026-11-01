# Zireael-RMM

A self-hosted remote support tool for family and personal use. The Linux server provides a passkey-protected web console; a single Windows agent executable provides remote desktop, PowerShell, and file transfers. **Preview:** PowerShell and file transfers have passed an initial Windows test. Remote desktop now uses a built-in Go engine with a pop-out/fullscreen browser viewer.

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

Send them the public homepage, `https://YOUR-DOMAIN:8443/`. It always shows the default one-line PowerShell command. They paste it into ordinary PowerShell. In **Agents**, click **Approve device** beside the pending computer within 24 hours, then click the online device to use desktop, PowerShell, or files. The default installation needs no elevation and reconnects when that Windows user signs in.

The default command downloads a verified PowerShell package with the agent EXE embedded inside it. It extracts, verifies and installs the agent, then removes the temporary installer. You can also download this `.ps1` from **Agent downloads** for a default user installation.

For access before sign-in, create a private **service** support link in the console and have the person run its command in an already elevated PowerShell. For one session with no persistence, create a **temporary** link instead. Each private link is single-use and expires after 15 minutes. For a direct EXE download, use **Agent downloads** in the console, create a support link, then expand **Install from a downloaded EXE** for its installation command.

**Update or repair:** rerun the normal installation command. A matching installation keeps its device identity and approval while the executable, startup settings and uninstall entry are refreshed. Installation explicitly enables and checks Windows sign-in startup; later changes in Windows Startup Apps are respected.

**Uninstall:** open Windows **Settings → Apps → Installed apps**, find **Zireael-RMM**, and choose **Uninstall**. For older builds, the public homepage has a **Remove the support app** section with a one-paste removal command. Service and other administrator-installed copies require elevation. Removal stops the agent and deletes its installation files, identity, service/startup registrations, saved startup approval, uninstall entry and old installer staging files.

**Start fresh:** if an old identity is damaged or was revoked, use the clean replacement command in the console. The support-link version preserves your selected user/service/temporary mode; the general Agent downloads option replaces the default user installation. A downloaded PS1 also accepts `-Replace` or `-Uninstall`. Clean replacement creates a new identity, so approve it and revoke the previous device entry. Keep the server data volume when updating the server.

The command shown in a browser must itself be trusted: TLS inspection that can alter the page can alter the command. The agent's encrypted inner connection protects subsequent agent traffic through TLS inspection, but cannot authenticate a replaced installer command. Admin browser traffic also requires a trusted HTTPS path.

## Status and licensing

The server, web console, agent transport, and Windows cross-builds have been checked locally. The Go desktop engine uses DXGI capture with GDI fallback, monitor/session selection, keyboard/mouse input, and view-only mode. Basic Windows support is working in the first operator test; service sessions, reconnects, and varied display setups still need broader testing. Agent certificates currently expire after one year without automatic renewal. The Windows EXE includes the swallow icon and product metadata. Binaries are not code-signed and there is no background automatic updater or account recovery beyond a second passkey and protected backups.

Original project code is [CC0](LICENSE). Dependencies use permissive licenses and retain their required notices in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). These texts are also embedded in both binaries; `server licenses` or `ZireaelRMM.exe licenses` prints them.
