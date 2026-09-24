import platform
import psutil
import subprocess
import re


# =========================================================
# INFRASHIELD NETWORK POLICY SCANNER
# =========================================================

# Ports that are normally expected for common web services
ALLOWED_PORTS = {80, 443, 22}

# Ports that can be security-sensitive
HIGH_RISK_PORTS = {
    21,      # FTP
    23,      # Telnet
    135,     # RPC
    139,     # NetBIOS
    445,     # SMB
    3306,    # MySQL
    5432,    # PostgreSQL
    3389     # RDP
}


# =========================================================
# HELPER - COMMAND CHECK
# =========================================================

def command_exists(command):
    """
    Check whether a command is available on the system.
    Works on Linux and Windows.
    """

    try:
        result = subprocess.run(
            ["which", command],
            capture_output=True,
            text=True,
            timeout=5
        )

        return result.returncode == 0

    except Exception:
        return False


# =========================================================
# ACTIVE CONNECTIONS
# =========================================================

def get_active_connections():

    connections = []

    try:

        for conn in psutil.net_connections(kind="inet"):

            if conn.laddr:

                local_ip = conn.laddr.ip
                local_port = conn.laddr.port

                remote_ip = ""
                remote_port = ""

                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                status = conn.status
                process_name = "Unknown"

                if conn.pid:

                    try:

                        process = psutil.Process(conn.pid)
                        process_name = process.name()

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
                    "status": status,
                    "pid": conn.pid,
                    "process": process_name
                })

    except Exception as e:

        print("Error reading connections:", e)

    return connections


# =========================================================
# LISTENING PORTS
# =========================================================

def get_listening_ports():

    ports = []

    try:

        for conn in psutil.net_connections(kind="inet"):

            if conn.status == psutil.CONN_LISTEN and conn.laddr:

                port = conn.laddr.port
                process_name = "Unknown"

                if conn.pid:

                    try:

                        process_name = psutil.Process(
                            conn.pid
                        ).name()

                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied
                    ):
                        process_name = "Unknown"

                ports.append({
                    "ip": conn.laddr.ip,
                    "port": port,
                    "pid": conn.pid,
                    "process": process_name
                })

    except Exception as e:

        print("Error reading listening ports:", e)

    # Remove duplicate ports
    unique_ports = {}

    for item in ports:

        port = item["port"]

        if port not in unique_ports:
            unique_ports[port] = item

    return list(unique_ports.values())


# =========================================================
# WINDOWS FIREWALL STATUS
# =========================================================

def get_windows_firewall_status():

    result = {
        "type": "Windows Firewall",
        "available": False,
        "enabled": False,
        "profiles": []
    }

    try:

        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetFirewallProfile | "
            "Select-Object Name,Enabled | "
            "ConvertTo-Csv -NoTypeInformation"
        ]

        output = subprocess.check_output(
            command,
            text=True,
            timeout=10
        )

        lines = output.strip().splitlines()

        if len(lines) > 1:

            result["available"] = True

            for line in lines[1:]:

                parts = line.split(",")

                if len(parts) >= 2:

                    name = (
                        parts[0]
                        .strip()
                        .strip('"')
                    )

                    enabled_value = (
                        parts[1]
                        .strip()
                        .strip('"')
                    )

                    enabled = (
                        enabled_value.lower() == "true"
                    )

                    result["profiles"].append({
                        "name": name,
                        "enabled": enabled
                    })

            if result["profiles"]:

                result["enabled"] = all(
                    profile["enabled"]
                    for profile in result["profiles"]
                )

    except Exception as e:

        print("Windows firewall status error:", e)

    return result


# =========================================================
# WINDOWS FIREWALL RULES
# =========================================================

def get_windows_firewall_rules():

    rules = []

    try:

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all"
        ]

        output = subprocess.check_output(
            command,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=30
        )

        lines = output.splitlines()
        current_rule = {}

        for line in lines:

            line = line.strip()

            # Rule Name
            if line.lower().startswith("rule name:"):

                if current_rule:
                    rules.append(current_rule)

                current_rule = {
                    "name": line.split(
                        ":",
                        1
                    )[1].strip()
                }

            # Direction
            elif line.lower().startswith("direction:"):

                current_rule["direction"] = (
                    line.split(
                        ":",
                        1
                    )[1].strip()
                )

            # Protocol
            elif line.lower().startswith("protocol:"):

                current_rule["protocol"] = (
                    line.split(
                        ":",
                        1
                    )[1].strip()
                )

            # Local Port
            elif line.lower().startswith("localport:"):

                current_rule["local_port"] = (
                    line.split(
                        ":",
                        1
                    )[1].strip()
                )

            # Action
            elif line.lower().startswith("action:"):

                current_rule["action"] = (
                    line.split(
                        ":",
                        1
                    )[1].strip()
                )

        # Add final rule
        if current_rule:
            rules.append(current_rule)

    except subprocess.TimeoutExpired:

        print(
            "Windows Firewall rule scan timed out."
        )

    except Exception as e:

        print(
            "Windows firewall rule error:",
            e
        )

    return rules


# =========================================================
# LINUX FIREWALL STATUS
# =========================================================

def get_linux_firewall_status():

    result = {
        "type": "Linux Firewall",
        "available": False,
        "enabled": False,
        "profiles": []
    }

    # -----------------------------------------------------
    # UFW
    # -----------------------------------------------------

    try:

        if command_exists("ufw"):

            output = subprocess.check_output(
                ["ufw", "status"],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=10
            )

            result["available"] = True
            result["type"] = "UFW"

            if re.search(
                r"Status:\s*active",
                output,
                re.IGNORECASE
            ):
                result["enabled"] = True

            result["profiles"].append({
                "name": "UFW",
                "enabled": result["enabled"]
            })

            return result

    except Exception as e:

        print("UFW status error:", e)


    # -----------------------------------------------------
    # firewalld
    # -----------------------------------------------------

    try:

        if command_exists("firewall-cmd"):

            output = subprocess.check_output(
                ["firewall-cmd", "--state"],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=10
            ).strip()

            result["available"] = True
            result["type"] = "firewalld"
            result["enabled"] = (
                output.lower() == "running"
            )

            result["profiles"].append({
                "name": "firewalld",
                "enabled": result["enabled"]
            })

            return result

    except Exception as e:

        print("firewalld status error:", e)


    # -----------------------------------------------------
    # nftables
    # -----------------------------------------------------

    try:

        if command_exists("nft"):

            output = subprocess.check_output(
                ["nft", "list", "ruleset"],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=15
            )

            result["available"] = True
            result["type"] = "nftables"

            # nft command exists, but we only consider it
            # enabled when an actual ruleset exists.
            if output.strip():

                result["enabled"] = True

            result["profiles"].append({
                "name": "nftables",
                "enabled": result["enabled"]
            })

            return result

    except Exception as e:

        print("nftables status error:", e)


    # -----------------------------------------------------
    # iptables
    # -----------------------------------------------------

    try:

        if command_exists("iptables"):

            output = subprocess.check_output(
                ["iptables", "-L", "-n"],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=15
            )

            result["available"] = True
            result["type"] = "iptables"

            # iptables is considered active when it has
            # usable chains/rules output.
            if output.strip():

                result["enabled"] = True

            result["profiles"].append({
                "name": "iptables",
                "enabled": result["enabled"]
            })

            return result

    except Exception as e:

        print("iptables status error:", e)


    return result


# =========================================================
# LINUX FIREWALL RULES - UFW
# =========================================================

def get_ufw_rules():

    rules = []

    try:

        output = subprocess.check_output(
            ["ufw", "status"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=15
        )

        lines = output.splitlines()

        for line in lines:

            line = line.strip()

            if not line:
                continue

            if line.startswith("Status:"):
                continue

            if line.startswith("To"):
                continue

            if line.startswith("--"):
                continue

            # Example:
            # 22/tcp ALLOW IN Anywhere
            # 80/tcp ALLOW IN Anywhere
            # 443/tcp ALLOW IN Anywhere

            match = re.match(
                r"^(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)?\s*(.*)$",
                line,
                re.IGNORECASE
            )

            if not match:
                continue

            port_protocol = match.group(1).strip()
            action = match.group(2).strip().upper()
            direction = (
                match.group(3).strip().upper()
                if match.group(3)
                else "IN"
            )

            protocol = "ANY"
            local_port = port_protocol

            # Handle 22/tcp
            if "/" in port_protocol:

                port_part, protocol_part = (
                    port_protocol.rsplit("/", 1)
                )

                local_port = port_part.strip()
                protocol = protocol_part.strip().upper()

            rules.append({
                "name": "UFW",
                "direction": direction,
                "protocol": protocol,
                "local_port": local_port,
                "action": action
            })

    except Exception as e:

        print("UFW rule error:", e)

    return rules


# =========================================================
# LINUX FIREWALL RULES - FIREWALLD
# =========================================================

def get_firewalld_rules():

    rules = []

    try:

        zones_output = subprocess.check_output(
            [
                "firewall-cmd",
                "--get-active-zones"
            ],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=10
        )

        zones = []

        for line in zones_output.splitlines():

            line = line.strip()

            if line and not line.startswith("interfaces:"):

                zones.append(line)

        if not zones:

            zones = ["public"]

        for zone in zones:

            try:

                output = subprocess.check_output(
                    [
                        "firewall-cmd",
                        "--zone",
                        zone,
                        "--list-ports"
                    ],
                    text=True,
                    stderr=subprocess.STDOUT,
                    timeout=10
                )

                for entry in output.split():

                    entry = entry.strip()

                    if not entry:
                        continue

                    protocol = "ANY"
                    local_port = entry

                    if "/" in entry:

                        port_part, protocol_part = (
                            entry.rsplit("/", 1)
                        )

                        local_port = port_part.strip()
                        protocol = protocol_part.upper()

                    rules.append({
                        "name": f"firewalld:{zone}",
                        "direction": "IN",
                        "protocol": protocol,
                        "local_port": local_port,
                        "action": "ALLOW"
                    })

            except Exception:
                continue

    except Exception as e:

        print("firewalld rule error:", e)

    return rules


# =========================================================
# LINUX FIREWALL RULES - NFTABLES
# =========================================================

def get_nftables_rules():

    rules = []

    try:

        output = subprocess.check_output(
            ["nft", "list", "ruleset"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=20
        )

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            # Look for tcp/udp destination ports.
            port_matches = re.findall(
                r"(?:tcp|udp)\s+dport\s+([0-9,\-]+)",
                line,
                re.IGNORECASE
            )

            # Check whether rule allows traffic.
            allow_match = re.search(
                r"\baccept\b",
                line,
                re.IGNORECASE
            )

            if not allow_match:
                continue

            for port_value in port_matches:

                protocol_match = re.search(
                    r"\b(tcp|udp)\s+dport\b",
                    line,
                    re.IGNORECASE
                )

                protocol = (
                    protocol_match.group(1).upper()
                    if protocol_match
                    else "ANY"
                )

                rules.append({
                    "name": "nftables",
                    "direction": "IN",
                    "protocol": protocol,
                    "local_port": port_value,
                    "action": "ALLOW"
                })

    except Exception as e:

        print("nftables rule error:", e)

    return rules


# =========================================================
# LINUX FIREWALL RULES - IPTABLES
# =========================================================

def get_iptables_rules():

    rules = []

    try:

        output = subprocess.check_output(
            [
                "iptables",
                "-S",
                "INPUT"
            ],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=20
        )

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            # We only need ACCEPT rules.
            if not re.search(
                r"-j\s+ACCEPT\b",
                line,
                re.IGNORECASE
            ):
                continue

            protocol_match = re.search(
                r"-p\s+(tcp|udp)",
                line,
                re.IGNORECASE
            )

            protocol = (
                protocol_match.group(1).upper()
                if protocol_match
                else "ANY"
            )

            # --dport 22
            port_match = re.search(
                r"--dport\s+([0-9,\-]+)",
                line,
                re.IGNORECASE
            )

            if not port_match:
                continue

            local_port = port_match.group(1)

            rules.append({
                "name": "iptables",
                "direction": "IN",
                "protocol": protocol,
                "local_port": local_port,
                "action": "ALLOW"
            })

    except Exception as e:

        print("iptables rule error:", e)

    return rules


# =========================================================
# LINUX FIREWALL RULES
# =========================================================

def get_linux_firewall_rules(firewall_type):

    if firewall_type == "UFW":

        return get_ufw_rules()

    elif firewall_type == "firewalld":

        return get_firewalld_rules()

    elif firewall_type == "nftables":

        return get_nftables_rules()

    elif firewall_type == "iptables":

        return get_iptables_rules()

    return []


# =========================================================
# PORT MATCHING
# =========================================================

def port_matches_rule(port, rule):

    local_port = rule.get(
        "local_port",
        ""
    ).strip()

    if not local_port:

        return False

    # Any port
    if local_port.lower() in {
        "any",
        "all"
    }:

        return True

    # Single numeric port
    if local_port.isdigit():

        return int(local_port) == port

    # Comma-separated ports
    if "," in local_port:

        parts = local_port.split(",")

        for part in parts:

            part = part.strip()

            if part.isdigit():

                if int(part) == port:

                    return True

            # Handle comma separated ranges
            if "-" in part:

                range_parts = part.split("-")

                if len(range_parts) == 2:

                    try:

                        start = int(range_parts[0])
                        end = int(range_parts[1])

                        if start <= port <= end:

                            return True

                    except ValueError:
                        pass

    # Port ranges
    if "-" in local_port:

        parts = local_port.split("-")

        if len(parts) == 2:

            try:

                start = int(parts[0])
                end = int(parts[1])

                if start <= port <= end:

                    return True

            except ValueError:

                pass

    return False


# =========================================================
# FIREWALL PORT CHECK
# =========================================================

def is_port_allowed_by_firewall(
    port,
    rules
):

    for rule in rules:

        action = rule.get(
            "action",
            ""
        ).lower()

        direction = rule.get(
            "direction",
            ""
        ).lower()

        # Only Allow rules
        if action not in {
            "allow",
            "accept"
        }:

            continue

        # Only inbound rules
        if direction and "in" not in direction:

            continue

        if port_matches_rule(
            port,
            rule
        ):

            return True

    return False


# =========================================================
# NETWORK POLICY EVALUATION
# =========================================================

def evaluate_network_policy(
    listening_ports,
    firewall_rules
):

    policy_results = []

    for item in listening_ports:

        port = item["port"]
        process = item["process"]

        firewall_allowed = (
            is_port_allowed_by_firewall(
                port,
                firewall_rules
            )
        )

        # -------------------------------------------------
        # Risk classification
        # -------------------------------------------------

        if port in HIGH_RISK_PORTS:

            risk = "HIGH"

        elif port in ALLOWED_PORTS:

            risk = "LOW"

        else:

            risk = "MEDIUM"

        # -------------------------------------------------
        # Policy decision
        # -------------------------------------------------

        if firewall_allowed:

            status = "AUTHORIZED"

        else:

            status = "UNAUTHORIZED"

        # High-risk ports allowed by firewall
        # should still be reviewed
        if (
            port in HIGH_RISK_PORTS
            and firewall_allowed
        ):

            status = "REVIEW"

        policy_results.append({

            "port": port,

            "process": process,

            "status": status,

            "risk": risk,

            "firewall_allowed":
                firewall_allowed

        })

    return policy_results


# =========================================================
# SECURITY SCORE
# =========================================================

def calculate_network_score(
    policy_results,
    firewall_enabled
):

    score = 100

    for item in policy_results:

        # Unauthorized ports
        if item["status"] == "UNAUTHORIZED":

            if item["risk"] == "HIGH":

                score -= 20

            elif item["risk"] == "MEDIUM":

                score -= 10

            else:

                score -= 5

        # Review ports
        elif item["status"] == "REVIEW":

            score -= 5

    # Firewall disabled
    if not firewall_enabled:

        score -= 30

    # Keep score between 0 and 100
    score = max(
        0,
        min(
            100,
            score
        )
    )

    return score


# =========================================================
# RISK LEVEL
# =========================================================

def get_risk_level(score):

    if score >= 80:

        return "LOW"

    elif score >= 60:

        return "MEDIUM"

    elif score >= 40:

        return "HIGH"

    else:

        return "CRITICAL"


# =========================================================
# SECURITY RECOMMENDATIONS
# =========================================================

def generate_recommendations(
    policy_results,
    firewall,
    operating_system="Unknown"
):

    recommendations = []

    firewall_type = firewall.get(
        "type",
        "Firewall"
    )

    # -----------------------------------------------------
    # Firewall recommendation
    # -----------------------------------------------------

    if not firewall["enabled"]:

        if operating_system == "Windows":

            firewall_title = (
                "Enable Windows Firewall"
            )

            firewall_description = (
                "Windows Firewall is disabled. "
                "Enable it to protect inbound "
                "network connections."
            )

        elif operating_system == "Linux":

            firewall_title = (
                f"Enable {firewall_type}"
            )

            firewall_description = (
                f"{firewall_type} is disabled or "
                "not active. Enable the firewall "
                "to protect inbound network "
                "connections."
            )

        else:

            firewall_title = (
                "Enable Firewall"
            )

            firewall_description = (
                "The firewall is disabled. "
                "Enable it to protect inbound "
                "network connections."
            )

        recommendations.append({
            "severity": "CRITICAL",
            "title": firewall_title,
            "description": firewall_description
        })

    # -----------------------------------------------------
    # High-risk ports
    # -----------------------------------------------------

    for item in policy_results:

        if item["risk"] == "HIGH":

            if item["status"] == "REVIEW":

                recommendations.append({

                    "severity": "HIGH",

                    "title":
                        f"Review high-risk port "
                        f"{item['port']}",

                    "description":
                        f"Port {item['port']} is "
                        f"used by "
                        f"{item['process']} and "
                        f"is allowed by the "
                        f"firewall. Verify that "
                        f"this service is required."

                })

            elif item["status"] == "UNAUTHORIZED":

                recommendations.append({

                    "severity": "CRITICAL",

                    "title":
                        f"Block unauthorized "
                        f"port {item['port']}",

                    "description":
                        f"Port {item['port']} is "
                        f"open without a matching "
                        f"firewall allow rule."

                })

    # -----------------------------------------------------
    # Unauthorized ports
    # -----------------------------------------------------

    unauthorized = [

        item

        for item in policy_results

        if item["status"] == "UNAUTHORIZED"

    ]

    if unauthorized:

        recommendations.append({

            "severity": "HIGH",

            "title":
                "Review unauthorized ports",

            "description":
                f"{len(unauthorized)} "
                f"unauthorized listening "
                f"port(s) were detected."

        })

    # -----------------------------------------------------
    # No issues
    # -----------------------------------------------------

    if not recommendations:

        recommendations.append({

            "severity": "INFO",

            "title":
                "Network policy looks healthy",

            "description":
                "No immediate network policy "
                "issues were detected."

        })

    return recommendations


# =========================================================
# MAIN NETWORK POLICY SCAN
# =========================================================

def run_network_policy_scan():

    print("=" * 60)

    print(
        "       INFRASHIELD NETWORK POLICY SCANNER"
    )

    print("=" * 60)

    # -----------------------------------------------------
    # Operating System
    # -----------------------------------------------------

    operating_system = platform.system()

    print("\nOperating System:")
    print(operating_system)

    # -----------------------------------------------------
    # Active Connections
    # -----------------------------------------------------

    active_connections = (
        get_active_connections()
    )

    # -----------------------------------------------------
    # Listening Ports
    # -----------------------------------------------------

    listening_ports = (
        get_listening_ports()
    )

    # -----------------------------------------------------
    # Firewall
    # -----------------------------------------------------

    firewall = {

        "type": "Unknown",

        "available": False,

        "enabled": False,

        "profiles": []

    }

    firewall_rules = []

    # -----------------------------------------------------
    # Windows
    # -----------------------------------------------------

    if operating_system == "Windows":

        firewall = (
            get_windows_firewall_status()
        )

        firewall_rules = (
            get_windows_firewall_rules()
        )

    # -----------------------------------------------------
    # Linux
    # -----------------------------------------------------

    elif operating_system == "Linux":

        firewall = (
            get_linux_firewall_status()
        )

        if firewall["available"]:

            firewall_rules = (
                get_linux_firewall_rules(
                    firewall["type"]
                )
            )

    # -----------------------------------------------------
    # Unsupported OS
    # -----------------------------------------------------

    else:

        print(
            f"Firewall scanning is not implemented "
            f"for {operating_system}."
        )

    # -----------------------------------------------------
    # Policy Evaluation
    # -----------------------------------------------------

    policy_results = (
        evaluate_network_policy(
            listening_ports,
            firewall_rules
        )
    )

    # -----------------------------------------------------
    # Unauthorized Ports
    # -----------------------------------------------------

    unauthorized_ports = [

        item

        for item in policy_results

        if item["status"] == "UNAUTHORIZED"

    ]

    # -----------------------------------------------------
    # High Risk Ports
    # -----------------------------------------------------

    high_risk_ports = [

        item

        for item in policy_results

        if item["risk"] == "HIGH"

    ]

    # -----------------------------------------------------
    # Review Ports
    # -----------------------------------------------------

    review_ports = [

        item

        for item in policy_results

        if item["status"] == "REVIEW"

    ]

    # -----------------------------------------------------
    # Authorized Ports
    # -----------------------------------------------------

    authorized_ports = [

        item

        for item in policy_results

        if item["status"] == "AUTHORIZED"

    ]

    # -----------------------------------------------------
    # Security Score
    # -----------------------------------------------------

    network_score = (
        calculate_network_score(
            policy_results,
            firewall["enabled"]
        )
    )

    # -----------------------------------------------------
    # Risk Level
    # -----------------------------------------------------

    risk_level = (
        get_risk_level(
            network_score
        )
    )

    # -----------------------------------------------------
    # Recommendations
    # -----------------------------------------------------

    recommendations = (
        generate_recommendations(
            policy_results,
            firewall,
            operating_system
        )
    )

    # =====================================================
    # TERMINAL OUTPUT
    # =====================================================

    print("\nSUMMARY:")

    print(
        "active_connections:",
        len(active_connections)
    )

    print(
        "listening_ports:",
        len(listening_ports)
    )

    print(
        "unauthorized_ports:",
        len(unauthorized_ports)
    )

    print(
        "high_risk_ports:",
        len(high_risk_ports)
    )

    print(
        "review_ports:",
        len(review_ports)
    )

    print(
        "authorized_ports:",
        len(authorized_ports)
    )

    print(
        "network_score:",
        network_score
    )

    print(
        "risk_level:",
        risk_level
    )

    # -----------------------------------------------------
    # Firewall
    # -----------------------------------------------------

    print("\nFIREWALL:")

    print(
        "Type:",
        firewall["type"]
    )

    print(
        "Available:",
        firewall["available"]
    )

    print(
        "Enabled:",
        firewall["enabled"]
    )

    print(
        "Firewall Rules Found:",
        len(firewall_rules)
    )

    # -----------------------------------------------------
    # Policy
    # -----------------------------------------------------

    print("\nPOLICY:")

    for item in policy_results:

        print(

            item["port"],

            item["status"],

            item["risk"],

            item["process"],

            "Firewall Allow:",

            item["firewall_allowed"]

        )

    print(
        "\n" + "=" * 60
    )

    print("SCAN COMPLETE")

    print(
        "=" * 60
    )

    # =====================================================
    # STRUCTURED RESULT FOR FLASK / FRONTEND
    # =====================================================

    return {

        "operating_system":
            operating_system,

        "summary": {

            "active_connections":
                len(active_connections),

            "listening_ports":
                len(listening_ports),

            "unauthorized_ports":
                len(unauthorized_ports),

            "high_risk_ports":
                len(high_risk_ports),

            "review_ports":
                len(review_ports),

            "authorized_ports":
                len(authorized_ports),

            "network_score":
                network_score,

            "risk_level":
                risk_level

        },

        "firewall": {

            "type":
                firewall["type"],

            "available":
                firewall["available"],

            "enabled":
                firewall["enabled"],

            "profiles":
                firewall["profiles"],

            "rules_found":
                len(firewall_rules)

        },

        "active_connections":
            active_connections,

        "listening_ports":
            listening_ports,

        "policy":
            policy_results,

        "recommendations":
            recommendations

    }


# =========================================================
# DIRECT EXECUTION
# =========================================================

if __name__ == "__main__":

    run_network_policy_scan()