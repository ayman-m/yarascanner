# CLAUDE.md

Project-specific notes for working in this repo. See `.claude/skills/` for the
XDR Action Center API automation skills (scan delivery, live testing).

## Lab tenant test VMs (GCP `cortex-gcp-labs`, zone `us-central1-f`)

The XDR test endpoints (`xdragent`, `xdragent2`, `xdr-agent`, `server2022`, `services`, etc.)
are GCE instances with no external IP — reachable only via IAP tunneling. Access differs
by OS and (for Windows) by which specific VM has been set up — see below, don't assume.

### Linux endpoints (`xdr-agent`, `aks-agentpool-*`) — SSH works directly

```bash
gcloud compute ssh xdr-agent --zone=us-central1-f --command="whoami"
```

No extra setup needed — SSH (port 22) is open and reachable via IAP tunnel out of the box.
Use this for anything needing real-time visibility the XDR public API can't give cleanly
(e.g. tailing `/opt/yara_scanner/logs/uploads_*.log` live while testing timing-sensitive
scanner behavior — round-tripping through XQL/Action Center to check the same thing has
several seconds of latency per check and is much harder to use for precise timing tests).

### Windows endpoints — per-VM status

Windows VMs need OpenSSH Server explicitly enabled; it is **not** on by default, and
WinRM (5985/5986) has never been successfully set up on any of them (a firewall rule
`allow-winrm-iap` exists project-wide, but no VM has WinRM itself configured — SSH is the
proven path, don't bother with WinRM unless something changes this).

- **`xdragent2` — SSH enabled and working (set up 2026-08-12).**
  ```bash
  gcloud compute ssh ayman@xdragent2 --zone=us-central1-f --command="whoami"
  ```
  **Username must be `ayman`, not your local machine username** — `gcloud compute ssh`
  defaults to your local OS username (e.g. `aymanmahmoud`), which doesn't exist as a
  Windows principal on these boxes and fails with a silent-looking `Permission denied
  (publickey,password,keyboard-interactive)`. `ayman` is the account on record from this
  project's GCE `windows-keys` metadata (used by `reset-windows-password`); it's a member
  of Administrators, which is what makes `administrators_authorized_keys` apply.
  Default shell over SSH is PowerShell — `--command="..."` runs PowerShell directly, no
  `cmd /c` wrapping needed.

- **`xdragent`, `server2022`, `services`, `IT-DL-DSK-234` — SSH not yet enabled.**
  Same blockers as xdragent2 had: missing the `allow-ssh-iap` network tag, and OpenSSH
  Server not installed/running. Same fix, if needed on one of these:
  1. `gcloud compute instances add-tags <name> --zone=us-central1-f --tags=<existing-tags>,allow-ssh-iap`
     (check existing tags first with `gcloud compute instances describe <name> --format="value(tags.items)"`
     — don't drop the VM's other tags, e.g. `allow-rdp-iap`).
  2. No existing remote-exec channel exists yet, so bootstrapping needs a **restart**: set
     `windows-startup-script-ps1` metadata to an OpenSSH-enable script (installs the
     OpenSSH.Server capability, starts+autostarts `sshd`, opens the local Windows Firewall
     port, sets PowerShell as `HKLM:\SOFTWARE\OpenSSH\DefaultShell`, writes your public key
     — `~/.ssh/google_compute_engine.pub` — to `C:\ProgramData\ssh\administrators_authorized_keys`
     with `icacls /inheritance:r` + `Administrators:F`/`SYSTEM:F` grants), then
     `gcloud compute instances reset <name> --zone=us-central1-f`. **This is a real reboot —
     drops any active RDP session and kills anything running on the box** — confirm with
     the user first, it's not a reflexive action.
  3. After confirming SSH works, clear the startup-script metadata
     (`gcloud compute instances remove-metadata <name> --zone=us-central1-f --keys=windows-startup-script-ps1`)
     so it doesn't needlessly re-run the setup on every future boot.
  4. RDP via `gcloud compute reset-windows-password <name> --zone=us-central1-f` remains
     available as a fallback / for the user's own manual access regardless.
