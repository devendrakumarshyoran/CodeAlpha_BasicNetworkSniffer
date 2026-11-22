from datetime import datetime
from detector import load_traffic_data, compute_traffic_summary, detect_suspicious_activity

REPORT_FILENAME = "security_report.txt"


def generate_security_report(csv_path="traffic_logs.csv", output_path=REPORT_FILENAME):
    df = load_traffic_data(csv_path)
    summary = compute_traffic_summary(df)
    alerts = detect_suspicious_activity(df)

    capture_start = df["Timestamp"].min() if not df.empty else "N/A"
    capture_end = df["Timestamp"].max() if not df.empty else "N/A"

    lines = [
        "====================================================================",
        "               NETWORK TRAFFIC & SECURITY ANALYSIS REPORT           ",
        "====================================================================",
        f"Report Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Capture Window   : {capture_start}  to  {capture_end}",
        "",
        "1. EXECUTIVE TRAFFIC SUMMARY",
        "--------------------------------------------------------------------",
        f"Total Packets Captured : {summary['total_packets']}",
        f"Total Bandwidth Usage  : {summary['total_kb']} KB ({summary['total_bytes']} Bytes)",
        f"Average Packet Size    : {summary['avg_packet_size']} Bytes",
        f"Incoming Packets       : {summary['incoming_count']}",
        f"Outgoing Packets       : {summary['outgoing_count']}",
        "",
        "2. PROTOCOL DISTRIBUTION",
        "--------------------------------------------------------------------",
    ]

    for proto, count in summary["protocol_counts"].items():
        pct = round((count / summary["total_packets"]) * 100, 1) if summary["total_packets"] else 0
        lines.append(f"- {proto:<8}: {count} packets ({pct}%)")

    lines.extend([
        "",
        "3. TOP ACTIVE CONNECTIONS (BY PACKET VOLUME)",
        "--------------------------------------------------------------------",
    ])
    for _, row in summary["active_connections"].head(5).iterrows():
        lines.append(
            f"- {row['Source IP']} -> {row['Destination IP']} "
            f"[{row['Protocol']}] : {row['Packets']} packets ({row['Total_Bytes']} Bytes)"
        )

    lines.extend([
        "",
        "4. SUSPICIOUS ACTIVITY & THREAT DETECTION LOGS",
        "--------------------------------------------------------------------",
    ])

    if alerts:
        for idx, alert in enumerate(alerts, 1):
            lines.append(f"[{idx}] SEVERITY: {alert['Severity']} | {alert['Category']}")
            lines.append(f"    Source IP      : {alert['Source IP']}")
            lines.append(f"    Evidence       : {alert['Details']}")
            lines.append(f"    Recommendation : {alert['Recommendation']}\n")
    else:
        lines.append("STATUS: NORMAL - No suspicious traffic patterns or anomalies detected.\n")

    lines.extend([
        "====================================================================",
        "End of Automated Security Report",
        "====================================================================",
    ])

    report_text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return report_text


if __name__ == "__main__":
    print("[*] Generating Security Analysis Report...")
    try:
        generate_security_report()
        print(f"[*] Report successfully saved to '{REPORT_FILENAME}'.")
    except FileNotFoundError:
        print("[!] Error: 'traffic_logs.csv' not found. Run 'sniffer.py' first.")