import subprocess
import shutil


def check_packages():
    if not shutil.which("apt"):
        return {
            "name": "System Packages",
            "status": "WARNING",
            "details": "apt is not available on this host"
        }

    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            timeout=25
        )
    except Exception as error:
        return {
            "name": "System Packages",
            "status": "WARNING",
            "details": str(error)
        }

    lines = [
        line for line in result.stdout.strip().split("\n")
        if line and not line.lower().startswith("listing")
    ]

    if not lines:
        return {
            "name": "System Packages",
            "status": "PASS",
            "details": "No outdated packages detected"
        }

    return {
        "name": "System Packages",
        "status": "WARNING",
        "details": f"{len(lines)} package(s) can be updated"
    }