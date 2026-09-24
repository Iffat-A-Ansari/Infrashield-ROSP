import subprocess
import os


def check_ssh_service():
    """
    Checks SSH service status and basic SSH hardening settings.
    Works both on Linux and inside Docker.
    """

    systemctl_path = "/usr/bin/systemctl"
    status = ""

    if os.path.exists(systemctl_path):
        result = subprocess.run(
            ["systemctl", "is-active", "ssh"],
            capture_output=True,
            text=True
        )
        status = result.stdout.strip()
    else:
        sshd_running = subprocess.run(
            ["pgrep", "-x", "sshd"],
            capture_output=True,
            text=True
        ).returncode == 0
        status = "active" if sshd_running else "inactive"

    if status == "":
        return {
            "name": "SSH Service Hardening",
            "status": "PASS",
            "details": "SSH service is not installed or running"
        }

    if status == "inactive":
        return {
            "name": "SSH Service Hardening",
            "status": "PASS",
            "details": "SSH service is inactive"
        }

    config_file = "/etc/ssh/sshd_config"

    if not os.path.exists(config_file):
        return {
            "name": "SSH Service Hardening",
            "status": "WARNING",
            "details": "SSH is active but configuration file was not found"
        }

    with open(config_file, "r", errors="ignore") as file:
        config = file.read()

    issues = []

    if "PermitRootLogin no" not in config:
        issues.append("root login policy should be reviewed")

    if "PasswordAuthentication no" not in config:
        issues.append("password authentication policy should be reviewed")

    if issues:
        return {
            "name": "SSH Service Hardening",
            "status": "WARNING",
            "details": "; ".join(issues)
        }

    return {
        "name": "SSH Service Hardening",
        "status": "PASS",
        "details": "SSH configuration follows basic hardening policies"
    }