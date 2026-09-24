import platform
try:
    import psutil
except Exception:
    class _MockPsutil:
        CONN_LISTEN = "LISTEN"
        @staticmethod
        def net_connections(kind="inet"):
            return []
        class Process:
            def __init__(self, pid):
                self.pid = pid
            def name(self):
                return "Unknown"
        class NoSuchProcess(Exception):
            pass
        class AccessDenied(Exception):
            pass
    psutil = _MockPsutil()
import subprocess
import re
import shutil


# ============================================================
# CONFIGURATION
# ============================================================

ALLOWED_PORTS = {80, 443, 22}

HIGH_RISK_PORTS = {
    21, 23, 135, 139, 445,
    3306, 5432, 3389
}


# ============================================================
# COMMAND HELPERS
# ============================================================

def command_exists(command):
    """Check whether a command exists on the system."""
    return shutil.which(command) is not None


def run_command(command, privileged=False):
    """
    Run a system command.

    On Linux:
    1. Try normal execution.
    2. If permission fails, retry using sudo -n.
       -n prevents the scanner from hanging for a password prompt.

    Returns:
        subprocess.CompletedProcess or None
    """

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

    except (subprocess.CalledProcessError, PermissionError):

        if platform.system() == "Linux" and privileged:

            try:
                return subprocess.run(
                    ["sudo", "-n"] + command,
                    capture_output=True,
                    text=True,
                    check=True
                )

            except (subprocess.CalledProcessError, PermissionError):
                return None

        return None


# ============================================================
# ACTIVE CONNECTIONS
# ============================================================

def get_active_connections():
    """Get active network connections."""

    connections = []

    try:
        for conn in psutil.net_connections(kind="inet"):

            local_ip = ""
            local_port = ""
            remote_ip = ""
            remote_port = ""

            if conn.laddr:
                local_ip = conn.laddr.ip
                local_port = conn.laddr.port

            if conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

            process_name = "Unknown"

            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):
                    process_name = "Unknown"

            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": conn.status,
                "pid": conn.pid,
                "process": process_name
            })

    except Exception as e:
        print(f"Active connection scan error: {e}")

    return connections


# ============================================================
# LISTENING PORTS
# ============================================================

def get_listening_ports():
    """Get all listening TCP/UDP ports."""

    listening = []
    seen_ports = set()

    try:
        for conn in psutil.net_connections(kind="inet"):

            if conn.status != psutil.CONN_LISTEN:
                continue

            if not conn.laddr:
                continue

            ip = conn.laddr.ip
            port = conn.laddr.port

            if port in seen_ports:
                continue

            seen_ports.add(port)

            process_name = "Unknown"

            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):
                    process_name = "Unknown"

            listening.append({
                "ip": ip,
                "port": port,
                "pid": conn.pid,
                "process": process_name
            })

    except Exception as e:
        print(f"Listening port scan error: {e}")

    return listening


# ============================================================
# WINDOWS FIREWALL
# ============================================================

def get_windows_firewall_status():
    """Get Windows Firewall status."""

    firewall = {
        "type": "Windows Firewall",
        "available": False,
        "enabled": False,
        "profiles": []
    }

    command = [
        "powershell",
        "-Command",
        "Get-NetFirewallProfile | "
        "Select-Object Name,Enabled | "
        "ConvertTo-Csv -NoTypeInformation"
    ]

    result = run_command(command)

    if result is None:
        return firewall

    firewall["available"] = True

    lines = result.stdout.strip().splitlines()

    for line in lines[1:]:

        parts = line.strip().strip('"').split('","')

        if len(parts) >= 2:

            profile_name = parts[0].replace('"', '')
            enabled_value = parts[1].replace('"', '').lower()

            enabled = enabled_value == "true"

            firewall["profiles"].append({
                "name": profile_name,
                "enabled": enabled
            })

    if firewall["profiles"]:
        firewall["enabled"] = all(
            profile["enabled"]
            for profile in firewall["profiles"]
        )

    return firewall


def get_windows_firewall_rules():
    """Get Windows Firewall inbound rules."""

    rules = []

    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        "name=all"
    ]

    result = run_command(command)

    if result is None:
        return rules

    current_rule = {}

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("Rule Name:"):

            if current_rule:
                rules.append(current_rule)

            current_rule = {
                "name": line.split(":", 1)[1].strip(),
                "direction": "",
                "protocol": "",
                "local_port": "",
                "action": ""
            }

        elif line.startswith("Direction:"):

            current_rule["direction"] = (
                line.split(":", 1)[1].strip()
            )

        elif line.startswith("Protocol:"):

            current_rule["protocol"] = (
                line.split(":", 1)[1].strip()
            )

        elif line.startswith("LocalPort:"):

            current_rule["local_port"] = (
                line.split(":", 1)[1].strip()
            )

        elif line.startswith("Action:"):

            current_rule["action"] = (
                line.split(":", 1)[1].strip()
            )

    if current_rule:
        rules.append(current_rule)

    return rules


# ============================================================
# LINUX FIREWALL STATUS
# ============================================================

def get_linux_firewall_status():
    """
    Detect Linux firewall.

    Priority:
    UFW -> firewalld -> nftables -> iptables
    """

    firewall = {
        "type": "Linux Firewall",
        "available": False,
        "enabled": False,
        "profiles": []
    }

    # --------------------------------------------------------
    # UFW
    # --------------------------------------------------------

    if command_exists("ufw"):

        result = run_command(
            ["ufw", "status"],
            privileged=True
        )

        if result is not None:

            output = result.stdout.lower()

            if "status: active" in output:

                firewall["type"] = "UFW"
                firewall["available"] = True
                firewall["enabled"] = True

                return firewall

            elif "status: inactive" in output:

                firewall["type"] = "UFW"
                firewall["available"] = True
                firewall["enabled"] = False

                return firewall

    # --------------------------------------------------------
    # firewalld
    # --------------------------------------------------------

    if command_exists("firewall-cmd"):

        result = run_command(
            ["firewall-cmd", "--state"],
            privileged=True
        )

        if result is not None:

            output = result.stdout.strip().lower()

            firewall["type"] = "firewalld"
            firewall["available"] = True
            firewall["enabled"] = output == "running"

            return firewall

    # --------------------------------------------------------
    # nftables
    # --------------------------------------------------------

    if command_exists("nft"):

        result = run_command(
            ["nft", "list", "ruleset"],
            privileged=True
        )

        if result is not None:

            firewall["type"] = "nftables"
            firewall["available"] = True
            firewall["enabled"] = bool(
                result.stdout.strip()
            )

            return firewall

    # --------------------------------------------------------
    # iptables
    # --------------------------------------------------------

    if command_exists("iptables"):

        result = run_command(
            ["iptables", "-L", "-n"],
            privileged=True
        )

        if result is not None:

            firewall["type"] = "iptables"
            firewall["available"] = True

            output = result.stdout

            input_policy = re.search(
                r"Chain INPUT \(policy (\w+)",
                output
            )

            if input_policy:

                firewall["enabled"] = (
                    input_policy.group(1).upper()
                    != "ACCEPT"
                )

            else:

                firewall["enabled"] = bool(
                    output.strip()
                )

            return firewall

    return firewall


# ============================================================
# UFW RULES
# ============================================================

def get_ufw_rules():
    """Get UFW firewall rules."""

    rules = []

    result = run_command(
        ["ufw", "status"],
        privileged=True
    )

    if result is None:
        return rules

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("Status:"):
            continue

        if line.startswith("---"):
            continue

        # Example:
        # 22/tcp ALLOW IN Anywhere

        match = re.match(
            r"(.+?)\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)\s+(.*)",
            line,
            re.IGNORECASE
        )

        if not match:
            continue

        port_info = match.group(1).strip()
        action = match.group(2).upper()
        direction = match.group(3).upper()

        protocol = "ANY"
        local_port = port_info

        if "/" in port_info:

            port_part, protocol_part = port_info.split(
                "/",
                1
            )

            local_port = port_part
            protocol = protocol_part.upper()

        rules.append({
            "name": "UFW",
            "direction": direction,
            "protocol": protocol,
            "local_port": local_port,
            "action": action
        })

    return rules


# ============================================================
# FIREWALLD RULES
# ============================================================

def get_firewalld_rules():
    """Get firewalld allowed ports."""

    rules = []

    result = run_command(
        [
            "firewall-cmd",
            "--get-active-zones"
        ],
        privileged=True
    )

    if result is None:
        return rules

    zones = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if (
            line
            and not line.startswith("interfaces:")
            and not line.startswith("sources:")
            and not line.startswith("services:")
            and not line.startswith("ports:")
        ):
            zones.append(line)

    for zone in zones:

        result = run_command(
            [
                "firewall-cmd",
                "--zone",
                zone,
                "--list-ports"
            ],
            privileged=True
        )

        if result is None:
            continue

        for port_entry in result.stdout.split():

            if "/" not in port_entry:
                continue

            port, protocol = port_entry.split(
                "/",
                1
            )

            rules.append({
                "name": f"firewalld:{zone}",
                "direction": "IN",
                "protocol": protocol.upper(),
                "local_port": port,
                "action": "ALLOW"
            })

    return rules


# ============================================================
# NFTABLES RULES
# ============================================================

def get_nftables_rules():
    """Extract basic TCP/UDP accept rules from nftables."""

    rules = []

    result = run_command(
        ["nft", "list", "ruleset"],
        privileged=True
    )

    if result is None:
        return rules

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        if "accept" not in line.lower():
            continue

        match = re.search(
            r"(tcp|udp)\s+(?:dport|sport)\s+(\d+)",
            line,
            re.IGNORECASE
        )

        if match:

            protocol = match.group(1).upper()
            port = match.group(2)

            rules.append({
                "name": "nftables",
                "direction": "IN",
                "protocol": protocol,
                "local_port": port,
                "action": "ACCEPT"
            })

    return rules


# ============================================================
# IPTABLES RULES
# ============================================================

def get_iptables_rules():
    """Get basic INPUT ACCEPT rules from iptables."""

    rules = []

    result = run_command(
        [
            "iptables",
            "-S",
            "INPUT"
        ],
        privileged=True
    )

    if result is None:
        return rules

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        if "-j ACCEPT" not in line:
            continue

        direction = "IN"
        protocol = "ANY"
        local_port = "Any"

        protocol_match = re.search(
            r"-p\s+(\w+)",
            line
        )

        if protocol_match:
            protocol = protocol_match.group(1).upper()

        port_match = re.search(
            r"--dport\s+(\d+)",
            line
        )

        if port_match:
            local_port = port_match.group(1)

        rules.append({
            "name": "iptables",
            "direction": direction,
            "protocol": protocol,
            "local_port": local_port,
            "action": "ACCEPT"
        })

    return rules


# ============================================================
# LINUX FIREWALL RULE DISPATCHER
# ============================================================

def get_linux_firewall_rules(firewall_type):
    """Return rules according to detected firewall."""

    firewall_type = firewall_type.lower()

    if firewall_type == "ufw":
        return get_ufw_rules()

    if firewall_type == "firewalld":
        return get_firewalld_rules()

    if firewall_type == "nftables":
        return get_nftables_rules()

    if firewall_type == "iptables":
        return get_iptables_rules()

    return []


# ============================================================
# PORT MATCHING
# ============================================================

def port_matches_rule(port, rule):
    """Check whether a port matches a firewall rule."""

    rule_port = str(
        rule.get("local_port", "")
    ).strip()

    if not rule_port:
        return False

    if rule_port.lower() in {
        "any",
        "all",
        "any port",
        "any ports"
    }:
        return True

    # Remove protocol suffix if present
    if "/" in rule_port:
        rule_port = rule_port.split("/", 1)[0]

    # Multiple ports
    for item in rule_port.split(","):

        item = item.strip()

        if not item:
            continue

        # Port range
        if "-" in item:

            try:

                start, end = item.split("-", 1)

                if int(start) <= port <= int(end):
                    return True

            except ValueError:
                continue

        # Single port
        else:

            try:

                if int(item) == port:
                    return True

            except ValueError:
                continue

    return False


# ============================================================
# FIREWALL POLICY CHECK
# ============================================================

def is_port_allowed_by_firewall(port, rules):
    """Check whether inbound port is explicitly allowed."""

    for rule in rules:

        direction = str(
            rule.get("direction", "")
        ).upper()

        action = str(
            rule.get("action", "")
        ).upper()

        if direction not in {
            "IN",
            "INBOUND",
            "INPUT"
        }:
            continue

        if action not in {
            "ALLOW",
            "ACCEPT"
        }:
            continue

        if port_matches_rule(port, rule):
            return True

    return False


# ============================================================
# POLICY EVALUATION
# ============================================================

def evaluate_network_policy(
    listening_ports,
    firewall_rules
):
    """Evaluate every listening port."""

    results = []

    for item in listening_ports:

        port = item["port"]

        process = item.get(
            "process",
            "Unknown"
        )

        firewall_allowed = (
            is_port_allowed_by_firewall(
                port,
                firewall_rules
            )
        )

        if port in HIGH_RISK_PORTS:
            risk = "HIGH"

        elif port in ALLOWED_PORTS:
            risk = "LOW"

        else:
            risk = "MEDIUM"

        if firewall_allowed:
            status = "AUTHORIZED"

        else:
            status = "UNAUTHORIZED"

        if (
            port in HIGH_RISK_PORTS
            and firewall_allowed
        ):
            status = "REVIEW"

        results.append({
            "port": port,
            "process": process,
            "risk": risk,
            "status": status,
            "firewall_allowed": firewall_allowed
        })

    return results


# ============================================================
# SECURITY SCORE
# ============================================================

def calculate_network_score(
    policy_results,
    firewall_enabled
):
    """Calculate network security score."""

    score = 100

    for result in policy_results:

        status = result["status"]
        risk = result["risk"]

        if status == "UNAUTHORIZED":

            if risk == "HIGH":
                score -= 20

            elif risk == "MEDIUM":
                score -= 10

            elif risk == "LOW":
                score -= 5

        elif status == "REVIEW":

            score -= 5

    if not firewall_enabled:
        score -= 30

    score = max(
        0,
        min(100, score)
    )

    return score


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 80:
        return "LOW"

    elif score >= 60:
        return "MEDIUM"

    elif score >= 40:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# RECOMMENDATIONS
# ============================================================

def generate_recommendations(
    policy_results,
    firewall_enabled,
    operating_system="Unknown"
):
    """Generate security recommendations."""

    recommendations = []

    # --------------------------------------------------------
    # FIREWALL RECOMMENDATION
    # --------------------------------------------------------

    if not firewall_enabled:

        if operating_system == "Linux":

            recommendations.append({
                "severity": "CRITICAL",
                "message": (
                    "Enable a Linux firewall such as UFW, "
                    "firewalld, nftables or iptables."
                )
            })

        elif operating_system == "Windows":

            recommendations.append({
                "severity": "CRITICAL",
                "message": (
                    "Enable Windows Firewall to protect "
                    "the system from unauthorized network access."
                )
            })

        else:

            recommendations.append({
                "severity": "CRITICAL",
                "message": (
                    "Enable a firewall to protect the system."
                )
            })

    # --------------------------------------------------------
    # PORT RECOMMENDATIONS
    # --------------------------------------------------------

    unauthorized_found = False

    for result in policy_results:

        port = result["port"]
        risk = result["risk"]
        status = result["status"]

        if risk == "HIGH":

            if status == "REVIEW":

                recommendations.append({
                    "severity": "HIGH",
                    "message": (
                        f"Review high-risk port {port}. "
                        "Ensure the service is required and "
                        "properly restricted."
                    )
                })

            elif status == "UNAUTHORIZED":

                recommendations.append({
                    "severity": "CRITICAL",
                    "message": (
                        f"Block unauthorized high-risk port {port} "
                        "unless the service is explicitly required."
                    )
                })

        if status == "UNAUTHORIZED":
            unauthorized_found = True

    # --------------------------------------------------------
    # GENERAL UNAUTHORIZED PORT RECOMMENDATION
    # --------------------------------------------------------

    if unauthorized_found:

        recommendations.append({
            "severity": "HIGH",
            "message": (
                "Review unauthorized listening ports and allow "
                "only required services."
            )
        })

    # --------------------------------------------------------
    # NO ISSUES
    # --------------------------------------------------------

    if not recommendations:

        recommendations.append({
            "severity": "INFO",
            "message": (
                "No major network security issues detected."
            )
        })

    return recommendations


# ============================================================
# MAIN NETWORK POLICY SCAN
# ============================================================

def run_network_policy_scan():
    """Run complete network policy scan."""

    operating_system = platform.system()

    # --------------------------------------------------------
    # ACTIVE CONNECTIONS
    # --------------------------------------------------------

    active_connections = get_active_connections()

    # --------------------------------------------------------
    # LISTENING PORTS
    # --------------------------------------------------------

    listening_ports = get_listening_ports()

    # --------------------------------------------------------
    # FIREWALL DETECTION
    # --------------------------------------------------------

    firewall_rules = []

    if operating_system == "Windows":

        firewall = get_windows_firewall_status()

        if firewall["available"]:

            firewall_rules = (
                get_windows_firewall_rules()
            )

    elif operating_system == "Linux":

        firewall = get_linux_firewall_status()

        if firewall["available"]:

            firewall_rules = (
                get_linux_firewall_rules(
                    firewall["type"]
                )
            )

    else:

        firewall = {
            "type": "Unknown",
            "available": False,
            "enabled": False,
            "profiles": []
        }

    # --------------------------------------------------------
    # POLICY EVALUATION
    # --------------------------------------------------------

    policy_results = evaluate_network_policy(
        listening_ports,
        firewall_rules
    )

    # --------------------------------------------------------
    # SECURITY SCORE
    # --------------------------------------------------------

    network_score = calculate_network_score(
        policy_results,
        firewall["enabled"]
    )

    risk_level = get_risk_level(
        network_score
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    unauthorized_ports = sum(
        1
        for result in policy_results
        if result["status"] == "UNAUTHORIZED"
    )

    high_risk_ports = sum(
        1
        for result in policy_results
        if result["risk"] == "HIGH"
    )

    review_ports = sum(
        1
        for result in policy_results
        if result["status"] == "REVIEW"
    )

    authorized_ports = sum(
        1
        for result in policy_results
        if result["status"] == "AUTHORIZED"
    )

    summary = {
        "active_connections": len(
            active_connections
        ),
        "listening_ports": len(
            listening_ports
        ),
        "unauthorized_ports": unauthorized_ports,
        "high_risk_ports": high_risk_ports,
        "review_ports": review_ports,
        "authorized_ports": authorized_ports,
        "network_score": network_score,
        "risk_level": risk_level
    }

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    recommendations = generate_recommendations(
        policy_results,
        firewall["enabled"],
        operating_system
    )

    # --------------------------------------------------------
    # FIREWALL INFORMATION
    # --------------------------------------------------------

    firewall["rules_count"] = len(
        firewall_rules
    )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {
        "operating_system": operating_system,
        "summary": summary,
        "firewall": firewall,
        "active_connections": active_connections,
        "listening_ports": listening_ports,
        "policy": policy_results,
        "recommendations": recommendations
    }


# ============================================================
# COMMAND LINE OUTPUT
# ============================================================

if __name__ == "__main__":

    result = run_network_policy_scan()

    print("\nOperating System:")
    print(result["operating_system"])

    print("\nSUMMARY:")

    for key, value in result["summary"].items():
        print(f"{key}: {value}")

    print("\nFIREWALL:")

    firewall = result["firewall"]

    print(
        f"Type: {firewall['type']}"
    )

    print(
        f"Available: {firewall['available']}"
    )

    print(
        f"Enabled: {firewall['enabled']}"
    )

    print(
        f"Firewall Rules Found: "
        f"{firewall.get('rules_count', 0)}"
    )

    print("\nPOLICY:")

    for item in result["policy"]:

        print(
            f"{item['port']} "
            f"{item['status']} "
            f"{item['risk']} "
            f"{item['process']} "
            f"Firewall Allow: "
            f"{item['firewall_allowed']}"
        )

    print("\nRECOMMENDATIONS:")

    for recommendation in result["recommendations"]:

        print(
            f"[{recommendation['severity']}] "
            f"{recommendation['message']}"
        )