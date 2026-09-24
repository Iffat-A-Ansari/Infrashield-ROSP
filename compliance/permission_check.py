import os


def check_passwd_permissions():
    file_path = "/etc/passwd"

    permissions = oct(os.stat(file_path).st_mode & 0o777)

    if permissions == "0o644":
        return {
            "name": "/etc/passwd permissions",
            "status": "PASS",
            "details": f"Permissions are {permissions}"
        }
    else:
        return {
            "name": "/etc/passwd permissions",
            "status": "FAIL",
            "details": f"Permissions are {permissions}"
        }


def check_shadow_permissions():
    file_path = "/etc/shadow"

    permissions = oct(os.stat(file_path).st_mode & 0o777)

    if permissions in ["0o600", "0o640"]:
        return {
            "name": "/etc/shadow permissions",
            "status": "PASS",
            "details": f"Permissions are {permissions}"
        }
    else:
        return {
            "name": "/etc/shadow permissions",
            "status": "FAIL",
            "details": f"Permissions are {permissions}"
        }