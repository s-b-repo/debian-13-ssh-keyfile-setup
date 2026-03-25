#!/usr/bin/env python3
"""
ssh_setup.py — SSH + Key Authentication Setup Tool for Debian 13
Run as root or with sudo: sudo python3 ssh_setup.py
"""

import os
import sys
import subprocess
import pwd
import grp
import stat
from pathlib import Path


# ── Colours ──────────────────────────────────────────────────────────────────
R  = "\033[0m"
G  = "\033[32m"
Y  = "\033[33m"
B  = "\033[34m"
C  = "\033[36m"
W  = "\033[97m"
DIM = "\033[2m"
BOLD = "\033[1m"

def ok(msg):    print(f"  {G}✔{R}  {msg}")
def info(msg):  print(f"  {C}→{R}  {msg}")
def warn(msg):  print(f"  {Y}⚠{R}  {msg}")
def err(msg):   print(f"  \033[31m✘{R}  {msg}")
def header(msg):print(f"\n{BOLD}{W}{msg}{R}\n  {'─' * (len(msg))}")
def ask(prompt, default=""):
    val = input(f"  {B}?{R}  {prompt} [{DIM}{default}{R}]: ").strip()
    return val if val else default


# ── Helpers ───────────────────────────────────────────────────────────────────
def run(cmd, check=True, capture=False):
    return subprocess.run(
        cmd, shell=True, check=check,
        capture_output=capture, text=True
    )

def run_ok(cmd):
    result = run(cmd, check=False, capture=True)
    return result.returncode == 0

def require_root():
    if os.geteuid() != 0:
        err("This script must be run as root (use sudo).")
        sys.exit(1)

def user_exists(username):
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False

def confirm(prompt):
    return input(f"  {Y}?{R}  {prompt} (y/N): ").strip().lower() == "y"


# ── Steps ─────────────────────────────────────────────────────────────────────
def install_openssh():
    header("Step 1 — Install OpenSSH Server")
    if run_ok("systemctl is-active --quiet ssh"):
        ok("OpenSSH is already installed and running.")
        return
    info("Installing openssh-server via apt …")
    run("apt-get update -qq")
    run("apt-get install -y openssh-server")
    run("systemctl enable --now ssh")
    ok("OpenSSH installed and started.")


def configure_sshd(port, permit_root, password_auth):
    header("Step 2 — Harden /etc/ssh/sshd_config")
    sshd_config = Path("/etc/ssh/sshd_config")
    backup = Path("/etc/ssh/sshd_config.bak")

    if not backup.exists():
        import shutil
        shutil.copy2(sshd_config, backup)
        ok(f"Backup saved to {backup}")

    settings = {
        "Port":                    str(port),
        "PermitRootLogin":         "yes" if permit_root else "no",
        "PubkeyAuthentication":    "yes",
        "AuthorizedKeysFile":      ".ssh/authorized_keys",
        "PasswordAuthentication":  "yes" if password_auth else "no",
        "ChallengeResponseAuthentication": "no",
        "UsePAM":                  "yes",
        "X11Forwarding":           "no",
        "PrintMotd":               "no",
        "AcceptEnv":               "LANG LC_*",
        "Subsystem":               "sftp /usr/lib/openssh/sftp-server",
        "MaxAuthTries":            "4",
        "LoginGraceTime":          "30",
        "ClientAliveInterval":     "300",
        "ClientAliveCountMax":     "2",
    }

    original = sshd_config.read_text()
    lines = original.splitlines()
    applied = set()

    new_lines = []
    for line in lines:
        stripped = line.strip()
        matched = False
        for key, val in settings.items():
            if stripped.lower().startswith(key.lower()) or \
               stripped.lower().startswith(f"#{key.lower()}"):
                if key not in applied:
                    new_lines.append(f"{key} {val}")
                    applied.add(key)
                    matched = True
                    break
                else:
                    matched = True  # skip duplicate
                    break
        if not matched:
            new_lines.append(line)

    # append any settings not already present
    for key, val in settings.items():
        if key not in applied:
            new_lines.append(f"{key} {val}")

    sshd_config.write_text("\n".join(new_lines) + "\n")

    # validate
    result = run("sshd -t", check=False, capture=True)
    if result.returncode != 0:
        err("sshd config validation failed — restoring backup.")
        import shutil
        shutil.copy2(backup, sshd_config)
        print(result.stderr)
        sys.exit(1)

    ok(f"sshd_config written  (port={port}, root={'yes' if permit_root else 'no'}, "
       f"password={'yes' if password_auth else 'no'})")


def setup_user_ssh_dir(username):
    header("Step 3 — Prepare ~/.ssh for user")
    pw = pwd.getpwnam(username)
    home = Path(pw.pw_dir)
    ssh_dir = home / ".ssh"
    auth_keys = ssh_dir / "authorized_keys"

    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    if not auth_keys.exists():
        auth_keys.touch(mode=0o600)

    # fix ownership
    uid, gid = pw.pw_uid, pw.pw_gid
    os.chown(ssh_dir, uid, gid)
    os.chown(auth_keys, uid, gid)
    os.chmod(ssh_dir, stat.S_IRWXU)
    os.chmod(auth_keys, stat.S_IRUSR | stat.S_IWUSR)

    ok(f"~/.ssh/ and authorized_keys ready for '{username}'")
    return auth_keys


def generate_keypair(username, key_type, key_bits, key_comment):
    header("Step 4 — Generate SSH Key Pair")
    pw = pwd.getpwnam(username)
    home = Path(pw.pw_dir)
    key_dir = home / ".ssh"
    key_path = key_dir / f"id_{key_type}"

    if key_path.exists():
        warn(f"Key already exists at {key_path}")
        if not confirm("Overwrite existing key?"):
            info("Skipping key generation — using existing key.")
            return key_path
        key_path.unlink()
        Path(str(key_path) + ".pub").unlink(missing_ok=True)

    bits_flag = f"-b {key_bits}" if key_type in ("rsa", "dsa") else ""
    cmd = (
        f'sudo -u {username} ssh-keygen -t {key_type} {bits_flag} '
        f'-C "{key_comment}" -f {key_path} -N ""'
    )
    run(cmd)
    ok(f"Key pair generated: {key_path} / {key_path}.pub")
    return key_path


def install_public_key(auth_keys_path, pub_key_path, username):
    header("Step 5 — Install Public Key")
    pub_key = Path(pub_key_path).read_text().strip()

    current = auth_keys_path.read_text()
    if pub_key in current:
        ok("Public key is already in authorized_keys.")
        return

    with open(auth_keys_path, "a") as f:
        f.write(pub_key + "\n")

    pw = pwd.getpwnam(username)
    os.chown(auth_keys_path, pw.pw_uid, pw.pw_gid)
    ok(f"Public key added to {auth_keys_path}")


def configure_firewall(port):
    header("Step 6 — Firewall (ufw)")
    if not run_ok("which ufw"):
        info("ufw not found — skipping firewall step.")
        return
    if not run_ok("ufw status | grep -q active"):
        warn("ufw is installed but not active. Skipping rule (enable ufw manually).")
        return

    # remove old SSH rule if port changed
    run(f"ufw delete allow OpenSSH", check=False)
    run(f"ufw allow {port}/tcp comment 'SSH'")
    ok(f"ufw rule added for port {port}/tcp")


def restart_sshd():
    header("Step 7 — Restart SSH Service")
    run("systemctl restart ssh")
    if run_ok("systemctl is-active --quiet ssh"):
        ok("sshd restarted successfully.")
    else:
        err("sshd failed to restart — check: journalctl -xe -u ssh")
        sys.exit(1)


def print_summary(username, port, key_path, server_ip):
    pub = Path(str(key_path) + ".pub").read_text().strip()
    priv = key_path

    print(f"""
{BOLD}{G}══════════════════════════════════════════════════════{R}
{BOLD}{W}  ✔  SSH Setup Complete{R}
{G}══════════════════════════════════════════════════════{R}

  {C}User:{R}          {username}
  {C}Port:{R}          {port}
  {C}Private key:{R}   {priv}
  {C}Public key:{R}    {priv}.pub

  {BOLD}Connect from your local machine:{R}
  {DIM}(copy the private key off this server first){R}

    {G}ssh -i /path/to/{priv.name} -p {port} {username}@{server_ip}{R}

  {BOLD}Copy private key to local machine:{R}

    {G}scp -P {port} {username}@{server_ip}:{priv} ~/.ssh/{priv.name}{R}
    {G}chmod 600 ~/.ssh/{priv.name}{R}

  {BOLD}Add to ~/.ssh/config (local machine):{R}

    {DIM}Host myserver{R}
    {DIM}    HostName     {server_ip}{R}
    {DIM}    User         {username}{R}
    {DIM}    Port         {port}{R}
    {DIM}    IdentityFile ~/.ssh/{priv.name}{R}

{Y}  ⚠  If you disabled password auth, make sure you can{R}
{Y}     log in with your key BEFORE closing this session!{R}

{G}══════════════════════════════════════════════════════{R}
""")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"""
{BOLD}{G}  ╔══════════════════════════════════════════╗
  ║   SSH Key Setup Tool  —  Debian 13      ║
  ╚══════════════════════════════════════════╝{R}
""")

    require_root()

    # ── Gather config ──────────────────────────────────────────────────────
    header("Configuration")

    username = ask("Linux user to configure SSH for", "root")
    if not user_exists(username) and username != "root":
        err(f"User '{username}' does not exist.")
        if confirm(f"Create user '{username}'?"):
            run(f"adduser --disabled-password --gecos '' {username}")
            ok(f"User '{username}' created.")
        else:
            sys.exit(1)

    port         = ask("SSH port", "22")
    key_type     = ask("Key type  (rsa / ed25519 / ecdsa)", "ed25519")
    key_bits     = ask("Key bits  (ignored for ed25519)", "4096")
    key_comment  = ask("Key comment", f"{username}@debian13")
    server_ip    = ask("Server IP / hostname (for summary)", "YOUR_SERVER_IP")
    permit_root  = confirm("Allow root login?")
    password_auth = confirm("Keep password authentication enabled? (disable after testing keys)")

    print()
    info(f"User:           {username}")
    info(f"Port:           {port}")
    info(f"Key type:       {key_type}")
    info(f"Root login:     {'yes' if permit_root else 'no'}")
    info(f"Password auth:  {'yes' if password_auth else 'no'}")
    print()

    if not confirm("Proceed with these settings?"):
        print("  Aborted.")
        sys.exit(0)

    # ── Run steps ──────────────────────────────────────────────────────────
    install_openssh()
    configure_sshd(port, permit_root, password_auth)
    auth_keys = setup_user_ssh_dir(username)
    key_path  = generate_keypair(username, key_type, key_bits, key_comment)
    install_public_key(auth_keys, Path(str(key_path) + ".pub"), username)
    configure_firewall(port)
    restart_sshd()
    print_summary(username, port, key_path, server_ip)


if __name__ == "__main__":
    main()
