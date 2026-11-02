<p align="center">
  <img src="internal/console/web/swallow.png" width="88" alt="Zireael-RMM swallow">
</p>
<h1 align="center">Zireael-RMM</h1>
<p align="center">Self-hosted remote support for Windows, written in Go.<br>Linux server · Windows agent · Passkey-protected web console</p>
<p align="center"><a href="#quick-start">Quick start</a> · <a href="#connect-a-computer">Connect a computer</a> · <a href="#updates-and-removal">Updates</a> · <a href="#configuration">Configuration</a></p>

- **Remote desktop:** monitor selection, view-only, clipboard, pop-out and fullscreen.
- **PowerShell and files:** run commands and transfer files up to 1 GiB.
- **Admin console:** individual passkeys, multiple admins, device approval and audit history.
- **Outbound connections:** encrypted agent traffic; no port forwarding on supported computers.

**Public preview.** The default Docker build includes the Windows x64 agent. Windows binaries are currently unsigned.

## Quick start

You need **Linux**, **Git**, **Docker with the Compose plugin**, and a domain pointing to your server. Allow TCP **8443**, plus TCP **80** for Let's Encrypt certificate issuance and HTTP-01 renewal.

```sh
git clone https://github.com/Harrison-Wells-Cyber/Zireael-RMM.git
cd Zireael-RMM
./start.sh --domain support.example.com
```

Replace the domain. Use `sudo` if your account needs it for Docker. The launcher builds everything, configures HTTPS, and prints your setup token.

1. Open **`https://support.example.com:8443/admin`**.
2. Enter the token within **15 minutes** and register a passkey.
3. Add a spare passkey under **Users**. Invite other admins there; all admins have full control.

Keep and back up the Docker volume mounted at `/data`. It stores your accounts, devices and deployment keys.

## Connect a computer

1. Send the person **`https://support.example.com:8443/`**.
2. They open ordinary PowerShell and paste the command shown there.
3. In **Agents**, click **Approve device** within 24 hours, then open the online computer.

The default installer is a verified `.ps1` containing the EXE. It installs for the current user without an elevation prompt and starts at Windows sign-in.

Create a **support link** in the console to choose another mode:

| Mode | Available | Install using |
| --- | --- | --- |
| **User — default** | While the user is signed in and online | Ordinary PowerShell |
| **Service** | While Windows is running and online | Elevated PowerShell |
| **Temporary** | Until the support connection ends | Ordinary PowerShell |

Service commands run as LocalSystem; remote desktop needs a signed-in session. Personal links are single-use and expire after **15 minutes**. Direct downloads are under **Agent downloads**; use the generated installation command for the EXE.

## Updates and removal

Update the server first, keeping the same directory, data volume and startup options:

```sh
git pull
./start.sh --domain support.example.com
```

Agents reconnect after the server restarts. Temporary agents must be started again.

- **Update an agent:** open it and click **Update agent**. Updates verify the package and preserve identity and approval. They require a recent admin sign-in and local Windows CIM/WMI. Older agents use the same command-based update path.
- **Repair:** rerun the normal installation command.
- **Uninstall:** Windows **Settings → Apps → Installed apps → Zireael-RMM**, or **Remove the support app** on the public homepage.
- **Start fresh:** use the console's **clean replacement** command, approve the new identity, and revoke the old entry.

Agent certificates renew automatically. Devices offline beyond certificate expiry need clean replacement.

## Configuration

Use startup flags; no `.env` editing is required. **`./start.sh --help`** lists every option.

<details>
<summary>Ports, certificates and reverse proxies</summary>

Use HTTPS port 443:

```sh
./start.sh --domain support.example.com --port 443
```

Supply your own `fullchain.pem` and `privkey.pem`:

```sh
./start.sh --domain support.example.com --cert-dir /srv/zireael-certs
```

Certificate files must be readable by container UID **65532**. Mount the complete tree for symlinked certificates. Renewed files reload on new connections.

Existing Certbot and cached certificates are checked first. Cached certificates can allow startup without port 80; rerun with **`--http-port 80`** when built-in HTTP-01 renewal needs it. Public port 80 must reach the challenge listener. TLS-ALPN renewal requires public port 443 routed to the app. Supplied certificates need no ACME port.

Other options: **`--bind`** for the host address, **`--origin`** for the exact public HTTPS origin, and **`--acme-directory`** for another issuer. Reverse proxies must support WebSockets and long-running transfers.

</details>

The launcher prints its log command. Agent traffic uses an encrypted inner TLS channel through inspected HTTPS; the admin browser and initial installation command still require a trusted HTTPS path.

## License

Original code is **[CC0](LICENSE)**. Dependencies retain their permissive licenses; see **[third-party notices](THIRD_PARTY_NOTICES.md)**.
