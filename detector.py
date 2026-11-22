import pandas as pd

HIGH_RISK_PORTS = {
    21: "FTP (Unencrypted File Transfer)",
    22: "SSH (Remote Access)",
    23: "Telnet (Insecure Remote Shell)",
    445: "SMB (Lateral Movement / Ransomware Vector)",
    3389: "RDP (Remote Desktop Exposure)",
    4444: "Default Reverse Shell / Metasploit Port"
}


def load_traffic_data(csv_path="traffic_logs.csv"):
    """Load traffic CSV and ensure backward compatibility with older schemas."""
    df = pd.read_csv(csv_path)

    defaults = {
        "Source Port": 0,
        "Destination Port": 0,
        "Direction": "Unknown",
        "Size": 0,
        "Info": "N/A"
    }
    for col, default_val in defaults.items():
        if col not in df.columns:
            df[col] = default_val

    df["Size"] = pd.to_numeric(df["Size"], errors="coerce").fillna(0).astype(int)
    df["Source Port"] = pd.to_numeric(df["Source Port"], errors="coerce").fillna(0).astype(int)
    df["Destination Port"] = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0).astype(int)
    return df


def compute_traffic_summary(df):
    """Calculate Module 2 traffic & bandwidth statistics."""
    total_packets = len(df)
    total_bytes = int(df["Size"].sum())
    avg_packet_size = round(df["Size"].mean(), 2) if total_packets > 0 else 0

    incoming_count = len(df[df["Direction"] == "Incoming"])
    outgoing_count = len(df[df["Direction"] == "Outgoing"])

    protocol_counts = df["Protocol"].value_counts().to_dict()

    active_connections = (
        df.groupby(["Source IP", "Destination IP", "Protocol"])
        .agg(Packets=("Size", "count"), Total_Bytes=("Size", "sum"))
        .reset_index()
        .sort_values(by="Packets", ascending=False)
    )

    valid_ports = df[df["Destination Port"] > 0]
    top_ports = (
        valid_ports["Destination Port"]
        .value_counts()
        .head(5)
        .reset_index()
    )
    top_ports.columns = ["Destination Port", "Count"]

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_kb": round(total_bytes / 1024, 2),
        "avg_packet_size": avg_packet_size,
        "incoming_count": incoming_count,
        "outgoing_count": outgoing_count,
        "protocol_counts": protocol_counts,
        "active_connections": active_connections,
        "top_ports": top_ports
    }


def detect_suspicious_activity(df):
    """
    Module 3: Rule-based Suspicious Activity Detection.
    Returns a list of structured alert dictionaries.
    """
    alerts = []
    if df.empty:
        return alerts

    total_packets = len(df)
    # Exclude normal local outbound packets from external flood false-positives
    external_df = df[df["Direction"] != "Outgoing"] if "Outgoing" in df["Direction"].values else df

    # Rule 1: High Traffic Spike from a Single Source IP
    spike_threshold = max(15, int(total_packets * 0.25))
    src_counts = external_df["Source IP"].value_counts()
    for ip, count in src_counts.items():
        if count >= spike_threshold:
            alerts.append({
                "Severity": "HIGH",
                "Category": "High Traffic Spike / Potential Flood",
                "Source IP": ip,
                "Details": f"Sent {count} packets ({round((count / total_packets) * 100, 1)}% of captured traffic).",
                "Recommendation": "Inspect traffic rate and consider rate-limiting or blocking IP if unauthorized."
            })

    # Rule 2: Port Scanning / Reconnaissance (1 Source IP hitting >= 5 distinct Destination Ports)
    port_df = df[df["Destination Port"] > 0]
    if not port_df.empty:
        unique_ports_per_ip = port_df.groupby("Source IP")["Destination Port"].nunique()
        for ip, unique_port_count in unique_ports_per_ip.items():
            if unique_port_count >= 5:
                ports_list = sorted(port_df[port_df["Source IP"] == ip]["Destination Port"].unique().tolist())[:10]
                alerts.append({
                    "Severity": "HIGH",
                    "Category": "Port Scan / Reconnaissance Activity",
                    "Source IP": ip,
                    "Details": f"Probed {unique_port_count} distinct destination ports (e.g., {ports_list}).",
                    "Recommendation": "Verify if internal vulnerability scan; otherwise block source IP at firewall."
                })

    # Rule 3: Repeated SYN / Connection Attempts (Potential SYN Flood or Brute Force)
    syn_df = df[df["Info"].astype(str).str.contains(r"\bSYN\b", regex=True, na=False)]
    if not syn_df.empty:
        syn_counts = syn_df.groupby(["Source IP", "Destination Port"]).size()
        for (ip, port), count in syn_counts.items():
            if count >= 5:
                alerts.append({
                    "Severity": "MEDIUM",
                    "Category": "Repeated Connection Attempts (SYN Burst)",
                    "Source IP": ip,
                    "Details": f"{count} repeated SYN connection requests targeting port {port}.",
                    "Recommendation": "Check for half-open connections or brute-force attempts on the target service."
                })

    # Rule 4: Traffic on High-Risk / Sensitive Ports
    for port, desc in HIGH_RISK_PORTS.items():
        risky_hits = df[df["Destination Port"] == port]
        if not risky_hits.empty:
            sources = ", ".join(risky_hits["Source IP"].unique()[:3])
            alerts.append({
                "Severity": "MEDIUM",
                "Category": f"Sensitive Port Activity (Port {port})",
                "Source IP": sources,
                "Details": f"{len(risky_hits)} packet(s) detected on {desc}.",
                "Recommendation": "Ensure port access is restricted to trusted administrative hosts."
            })

    # Rule 5: Unusual Bandwidth Transfer (> 50 KB from a single external IP)
    ip_bandwidth = external_df.groupby("Source IP")["Size"].sum()
    for ip, byte_total in ip_bandwidth.items():
        if byte_total > 51200:  # 50 KB
            alerts.append({
                "Severity": "LOW",
                "Category": "High Bandwidth Consumption",
                "Source IP": ip,
                "Details": f"Transferred {round(byte_total / 1024, 2)} KB during capture session.",
                "Recommendation": "Verify whether large data transfer corresponds to legitimate media/updates."
            })

    return alerts