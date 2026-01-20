# Network Traffic Analyzer for Home Security

## Overview

The **Network Traffic Analyzer for Home Security** is a real-time network monitoring and security analysis system designed for home and small networks.  
It continuously observes network traffic, identifies connected devices, detects insecure or suspicious behavior, and presents insights through an interactive web dashboard.

The primary goal of this project is to **increase visibility into home network activity** and **alert users to potential security risks**, such as insecure protocols, compromised devices, or abnormal communication patterns.

---

## Key Capabilities

This system combines packet-level inspection, behavioral analysis, and visualization to provide layered network security monitoring.

### 🔍1. Real-Time Packet Capture
- Captures live network packets using the `scapy` library from one or more network interfaces (e.g., home Wi-Fi, mobile hotspot).
- Packet capture acts as the foundational data source for all further analysis.


### 🖥️2. Device Discovery & Fingerprinting
- Identifies devices using:
  - MAC addresses
  - OUI-based manufacturer lookup
  - Hostnames extracted from DHCP traffic
- Helps distinguish between trusted devices, unknown devices, and IoT endpoints.


### 🔐3. Insecure Protocol Detection (**CRITICAL Alerts**)
- Detects use of insecure and unencrypted protocols such as:
  - Telnet
  - FTP
  - rlogin / rsh
  - Unencrypted MQTT
- These protocols expose credentials and data in plaintext and represent serious security risks.


### ⚠️4. Suspicious Port Activity Detection (**HIGH Alerts**)
- Flags outbound connections to ports commonly associated with:
  - Remote access services (SSH, RDP)
  - Malware command-and-control channels
  - Backdoors or lateral movement
- Helps identify potentially compromised devices.


### 📈5. Connection Baselining (**NORMAL Alerts**)
- Builds a behavioral baseline for each device by tracking unique connections:
  - Destination IP
  - Destination port
  - Protocol
- New or previously unseen connections are logged to highlight behavioral changes.


### 🌐6. DNS Monitoring & Threat Intelligence (**CRITICAL Alerts**)
- Monitors DNS queries in real time.
- Compares queried domains against a configurable malicious-domain blocklist.
- Effective at detecting malware that relies on domain-based communication.


### 📊7. Interactive Web Dashboard
Built using **Plotly Dash**, the dashboard provides:

- **Network Map:** Visual graph of device communication, color-coded by severity
- **Security Alerts:** Filterable alerts (CRITICAL, HIGH, NORMAL)
- **Discovered Devices:** Inventory of detected devices with metadata
- **DNS Logs:** Live DNS query feed
- **Live Traffic:** Raw packet-level traffic log

---

## System Architecture

1. **Packet Sensors (`sensor_*.py`)**
   - Capture packets from multiple network interfaces
   - Perform initial protocol parsing (DHCP, DNS, TCP, UDP)

2. **Analysis & Storage (SQLite)**
   - Analyze traffic patterns
   - Update device profiles
   - Store alerts and DNS logs in `sentinel.db`

3. **Dashboard (`dashboard_*.py`)**
   - Periodically queries the database
   - Updates tables and visualizations in real time

---

## **Setup & Running**

1. **Prerequisites:** Python 3, pip.  
2. **Install Dependencies:**  
   pip install scapy mac-vendor-lookup dash pandas dash-cytoscape  
   \# On Windows, install Npcap (with WinPcap compatibility)  
   \# On Linux/macOS, ensure libpcap-dev (or equivalent) is installed

3. **Configure Sensors:** Edit both sensor\_main\_wifi.py and sensor\_hotspot.py:  
   * Set YOUR\_SUBNET\_PREFIX correctly for each network they monitor.  
   * Set the correct iface name in the sniff() command at the bottom of each file.  
4. **Run:**  
   * Open **Terminal 1 (Admin):** python sensor\_main\_wifi.py  
   * Open **Terminal 2 (Admin):** python sensor\_hotspot.py  
   * Open **Terminal 3 (Normal):** python dashboard\_vX\_Y.py (use your latest dashboard file)  
5. **Access Dashboard:** Open http://127.0.0.1:8050 in your web browser.

---

## 📸 Dashboard Screenshots

The following screenshots showcase the real-time monitoring, alerting, and visualization
capabilities of the **Network Traffic Analyzer**.

---

### 🚨 Security Alerts – Critical Events

Detects insecure protocols and high-risk behavior in real time.

![Critical Security Alerts](screenshots/critical_security_alerts.png)

---

### ⚠️ Security Alerts – High Severity

Flags suspicious outbound connections and abnormal service usage.

![High Security Alerts](screenshots/high_security_alerts.png)

---

### 📋 All Security Alerts (Filtered & Sorted)

Unified alert view with severity-based filtering and newest-first ordering.

![Security Alerts](screenshots/security_alerts.png)

---

### 🧠 Discovered Network Devices

Automatically identifies devices using MAC address, hostname, and manufacturer lookup.

![Discovered Devices](screenshots/discovered_devices.png)

---

### 🗺️ Live Device Communication Map

Interactive graph visualizing device-to-destination communication,
color-coded by alert severity.

![Live Device Communication Map](screenshots/live_device_com_map.png)

---

### 🌐 Live DNS Query Log

Monitors DNS requests in real time to detect communication with suspicious or malicious domains.

![Live DNS Query Log](screenshots/live_dns_query_log.png)

---

### 📡 Real-Time Network Traffic Log

Low-level packet visibility including protocol, source, destination, and ports.

![Live Network Traffic](screenshots/live_traffic.png)

---

## **Future Improvements**

* **HTTP User-Agent Fingerprinting:** Extract User-Agent strings from HTTP traffic to identify specific applications or device models.  
* **Traffic Volume Baselining:** Monitor the *amount* of data transferred per connection to detect anomalies like data exfiltration or DDoS participation.  
* **Encrypted Traffic Analysis (Advanced):** Analyze patterns in encrypted traffic (TLS handshake details, connection timing) for potential threats (requires more advanced techniques).  
* **Configuration File:** Move settings like subnet, cooldowns, and blocklists into a separate config file instead of hardcoding.
