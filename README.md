# Network Traffic Analyzer

A Python-based Security Operations Center (SOC) inspired network monitoring and threat detection tool built using **Scapy**, **Pandas**, **Plotly**, and **Streamlit**.

## Key Features
- **Network Packet Capture (`sniffer.py`):** Captures live IPv4 packets with automatic local IP detection, traffic direction (`Incoming` / `Outgoing` / `Local`), source and destination ports, protocol classification (`TCP`, `UDP`, `DNS`, `ICMP`), TCP flags, and packet size.
- **Traffic & Bandwidth Monitoring (`analyzer.py`):** Computes total packet volume, bandwidth usage (Bytes/KB), average packet size, protocol share, active host connections, and top targeted ports.
- **Suspicious Activity Detection (`detector.py`):** Rule-based anomaly detection for high traffic spikes, multi-port scanning/reconnaissance, repeated `SYN` connection bursts, sensitive/high-risk port activity (`FTP`, `Telnet`, `SSH`, `SMB`, `RDP`), and unusual bandwidth transfers.
- **Interactive SOC Dashboard (`dashboard.py`):** Real-time Streamlit + Plotly web interface with protocol/direction/IP filtering, severity-coded alert banners, traffic timeline graphs, and one-click security report downloads.
- **Automated Security Reporting (`report_generator.py`):** Generates a structured `security_report.txt` summarizing traffic metrics, active connections, threat alerts, and remediation recommendations.

## Project Structure

    Network_Traffic_Analyzer/
    ├── sniffer.py            # Live packet capture module (Scapy)
    ├── detector.py           # Traffic analytics & rule-based threat detection engine
    ├── analyzer.py           # CLI summary & anomaly checker
    ├── dashboard.py          # Interactive Streamlit + Plotly web dashboard
    ├── report_generator.py   # Automated security_report.txt generator
    ├── traffic_logs.csv      # Captured packet dataset
    ├── security_report.txt   # Generated security audit report
    ├── requirements.txt      # Python dependencies
    └── README.md

## Setup & Usage
1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: On Windows, ensure **Npcap** is installed and run your terminal as Administrator for raw packet sniffing. On Linux, run `sniffer.py` with `sudo`.)*

2. **Capture Live Network Traffic:**
   ```bash
   python sniffer.py
   ```
   Enter the desired packet count (e.g., `100` or `200`) and browse a few websites or run an `nmap` scan against a local lab target to generate traffic.

3. **View CLI Analysis & Generate Security Report:**
   ```bash
   python analyzer.py
   python report_generator.py
   ```

4. **Launch the Interactive Dashboard:**
   ```bash
   streamlit run dashboard.py
   ```