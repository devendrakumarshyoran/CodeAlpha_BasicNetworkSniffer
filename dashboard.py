import streamlit as st
import pandas as pd
import plotly.express as px
from detector import load_traffic_data, compute_traffic_summary, detect_suspicious_activity
from report_generator import generate_security_report

st.set_page_config(
    page_title="Network Traffic Analyzer | SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Traffic Analyzer — Security Monitoring Dashboard")
st.caption("Real-time packet telemetry, bandwidth analysis, active connections, and automated threat detection.")

try:
    raw_df = load_traffic_data("traffic_logs.csv")

    # Sidebar Filters & Actions
    st.sidebar.header("⚙️ Controls & Filters")
    if st.sidebar.button("🔄 Refresh Traffic Data", use_container_width=True):
        st.rerun()

    available_protocols = sorted(raw_df["Protocol"].dropna().unique().tolist())
    selected_protocols = st.sidebar.multiselect(
        "Filter by Protocol",
        options=available_protocols,
        default=available_protocols
    )

    available_directions = ["All"] + sorted(raw_df["Direction"].dropna().unique().tolist())
    selected_direction = st.sidebar.selectbox("Filter by Traffic Direction", available_directions)

    ip_search = st.sidebar.text_input("Search Source / Destination IP", placeholder="e.g. 142.250 or 10.191")

    # Apply Filters
    df = raw_df[raw_df["Protocol"].isin(selected_protocols)]
    if selected_direction != "All":
        df = df[df["Direction"] == selected_direction]
    if ip_search.strip():
        q = ip_search.strip()
        df = df[
            df["Source IP"].astype(str).str.contains(q, na=False) |
            df["Destination IP"].astype(str).str.contains(q, na=False)
        ]

    summary = compute_traffic_summary(df)
    alerts = detect_suspicious_activity(df)

    # Sidebar Report Download
    st.sidebar.divider()
    st.sidebar.subheader("📄 Security Reporting")
    report_content = generate_security_report("traffic_logs.csv")
    st.sidebar.download_button(
        label="⬇️ Download Security Report (.txt)",
        data=report_content,
        file_name="security_report.txt",
        mime="text/plain",
        use_container_width=True
    )

    # Top KPI Cards
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Total Packets", summary["total_packets"])
    k2.metric("Total Bandwidth", f"{summary['total_kb']} KB")
    k3.metric("Incoming Packets", summary["incoming_count"])
    k4.metric("Outgoing Packets", summary["outgoing_count"])
    k5.metric("Security Alerts", len(alerts))

    st.divider()

    # Suspicious Activity Alerts Panel (Module 3)
    st.subheader("🚨 Suspicious Activity & Threat Alerts")
    if alerts:
        for alert in alerts:
            msg = (
                f"**[{alert['Severity']}] {alert['Category']}** — "
                f"Source IP: `{alert['Source IP']}` | {alert['Details']} "
                f"*(Action: {alert['Recommendation']})*"
            )
            if alert["Severity"] == "HIGH":
                st.error(msg)
            elif alert["Severity"] == "MEDIUM":
                st.warning(msg)
            else:
                st.info(msg)
    else:
        st.success("✅ No suspicious anomalies, port scans, or abnormal traffic spikes detected.")

    st.divider()

    # Charts Row 1: Timeline & Protocol Distribution
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("📈 Traffic Volume Over Time")
        if not df.empty:
            timeline = (
                df.groupby("Timestamp")
                .agg(Packets=("Size", "count"), Bytes=("Size", "sum"))
                .reset_index()
            )
            fig_time = px.area(
                timeline,
                x="Timestamp",
                y="Packets",
                markers=True,
                title="Packets Captured per Second"
            )
            st.plotly_chart(fig_time, use_container_width=True)

    with c2:
        st.subheader("🥧 Protocol Distribution")
        if not df.empty:
            fig_proto = px.pie(
                df,
                names="Protocol",
                hole=0.45,
                title="Share of Captured Protocols"
            )
            st.plotly_chart(fig_proto, use_container_width=True)

    # Charts Row 2: Top Source IPs & Targeted Destination Ports
    c3, c4 = st.columns(2)
    with c3:
        st.subheader("🌐 Top Active Source IPs")
        if not df.empty:
            top_src = df["Source IP"].value_counts().head(6).reset_index()
            top_src.columns = ["Source IP", "Packets"]
            fig_src = px.bar(
                top_src,
                x="Source IP",
                y="Packets",
                color="Packets",
                title="Highest Packet-Generating Hosts"
            )
            st.plotly_chart(fig_src, use_container_width=True)

    with c4:
        st.subheader("🎯 Top Targeted Destination Ports")
        if not summary["top_ports"].empty:
            port_df = summary["top_ports"].copy()
            port_df["Destination Port"] = port_df["Destination Port"].astype(str)
            fig_ports = px.bar(
                port_df,
                x="Destination Port",
                y="Count",
                color="Count",
                title="Most Accessed Service Ports"
            )
            st.plotly_chart(fig_ports, use_container_width=True)
        else:
            st.info("No TCP/UDP port numbers recorded in filtered traffic.")

    st.divider()

    # Active Connections & Raw Packet Logs
    tab1, tab2 = st.tabs(["🔗 Active Connections Summary", "📋 Raw Packet Capture Logs"])
    with tab1:
        st.dataframe(summary["active_connections"], use_container_width=True, hide_index=True)
    with tab2:
        st.dataframe(df, use_container_width=True, hide_index=True)

except FileNotFoundError:
    st.error("No traffic data found (`traffic_logs.csv`). Run `python sniffer.py` first to capture packets.")