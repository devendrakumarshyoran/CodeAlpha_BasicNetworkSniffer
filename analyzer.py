from detector import load_traffic_data, compute_traffic_summary, detect_suspicious_activity

print("==========================================================")
print("          NETWORK TRAFFIC ANALYZER - CLI SUMMARY          ")
print("==========================================================")

try:
    df = load_traffic_data("traffic_logs.csv")
    summary = compute_traffic_summary(df)
    alerts = detect_suspicious_activity(df)

    print(f"\n[+] Total Packets Captured : {summary['total_packets']}")
    print(f"[+] Total Bandwidth Used   : {summary['total_kb']} KB ({summary['total_bytes']} Bytes)")
    print(f"[+] Average Packet Size    : {summary['avg_packet_size']} Bytes")
    print(f"[+] Incoming vs Outgoing   : {summary['incoming_count']} Incoming | {summary['outgoing_count']} Outgoing")

    print("\n--- Protocol Distribution ---")
    for proto, count in summary["protocol_counts"].items():
        print(f"  * {proto:<6}: {count} packets")

    print("\n--- Top 5 Active Connections ---")
    print(summary["active_connections"].head(5).to_string(index=False))

    print("\n--- Top Targeted Destination Ports ---")
    if not summary["top_ports"].empty:
        print(summary["top_ports"].to_string(index=False))
    else:
        print("  No port data recorded.")

    print("\n--- Suspicious Activity Alerts ---")
    if alerts:
        for idx, alert in enumerate(alerts, 1):
            print(f"  [{idx}] [{alert['Severity']}] {alert['Category']} | Source: {alert['Source IP']}")
            print(f"      -> {alert['Details']}")
    else:
        print("  [OK] No suspicious anomalies detected in this capture session.")

except FileNotFoundError:
    print("[!] Error: 'traffic_logs.csv' not found. Run 'sniffer.py' first.")