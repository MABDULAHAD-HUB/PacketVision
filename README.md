<h1 align="center">🔍 Packet Vision</h1>

<p align="center">
  <b>Advanced Network Packet Capturing & Anomaly Detection Tool</b><br>
  Real-time traffic analysis powered by Python, Scapy, PyQt5, and Matplotlib.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Built%20with-Python%203.6+-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/GUI-PyQt5-brightgreen?style=for-the-badge&logo=qt">
  <img src="https://img.shields.io/badge/Capture-Scapy-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
</p>

---

## 🎬 Quick Demo
![Packet Vision Demo](screenshots/demo.gif)
*See Packet Vision in action - from capture to analysis in real-time*

---

## 📌 About the Project

**Packet Vision** is a Python-powered desktop tool that captures, filters, and visualizes live network packets. Designed with a sleek PyQt5 GUI, it supports real-time traffic inspection, anomaly detection using statistical thresholds, and seamless PCAP export for advanced analysis in tools like Wireshark.

Whether you're a cybersecurity student, network engineer, or penetration tester, this tool offers an efficient and accessible way to peek inside your network traffic.

## ✨ Key Features

- 📡 **Live Packet Capture** with Scapy and BPF filtering
- 🎛️ **Modern GUI** built using PyQt5 with intuitive controls
- 🧠 **Statistical Anomaly Detection** with real-time visualization
- 🔍 **Detailed Packet Analysis**: Multi-layer protocol inspection
- 🎨 **Color-Coded Protocols**: Easy visual identification of traffic types
- 🗂️ **PCAP Export**: Save captured data for use with Wireshark
- 📊 **Graphical Representation**: Real-time anomaly graph plotting
- 🧭 **Navigation Controls**: Browse packets with First/Previous/Next/Last
- 🛡️ **Security Assessment**: Automatic protocol security evaluation
- 📚 **Built-in Help System**: Complete user guide and shortcuts

## 🧰 Tech Stack

| Component      | Tool/Library  | Purpose |
|----------------|---------------|---------|
| Language       | Python 3.6+   | Core development |
| GUI Framework  | PyQt5         | User interface |
| Packet Capture | Scapy         | Network packet processing |
| Stats/Analysis | NumPy         | Statistical computations |
| Visualization  | Matplotlib    | Real-time graphs |
| Export Format  | PCAP          | Wireshark compatibility |


## ⚠️ Important: Install Packet Capture Dependencies

**Before installing Packet Vision, you MUST install the following system dependencies:**

### Windows Users:
- **Download and Install Npcap**: https://npcap.com/#download
- This is required for Scapy to capture network packets on Windows

### Linux Users:
```bash
sudo apt-get install tcpdump
```

> **Note**: Without these dependencies, packet capture will not work and you'll get import errors.

## 🛠️ Installation Guide

### Step 1: Clone the Repository
```bash
https://github.com/MABDULAHAD-HUB/PacketVision.git
cd PacketVision
```

### Step 2: Create Virtual Environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install PyQt5 scapy matplotlib numpy
```

### Step 4: Run the Application
```bash
python CODE.py
```

## 📘 User Guide

### 🚀 Getting Started

1. **Launch the Application**
   - Run `python CODE.py` from the terminal
   - The main window will open with all controls visible

2. **Start Packet Capture**
   - Click the ▶️ **START** button to begin capturing packets
   - Packets will appear in real-time in the main table

3. **Stop Packet Capture**
   - Click the ⏹️ **STOP** button to halt packet capture
   - Use **RESTART** to clear all data and start fresh

### 🔍 Filtering Packets

#### Basic Filtering:
- **Protocol Filter**: Select from dropdown (All, TCP, UDP, ICMP)
- **Port Filter**: Enter specific port numbers (e.g., "80", "443")
- **Custom Filter**: Advanced BPF filters (e.g., "host 8.8.8.8")

#### Apply Filters:
1. Set your desired filters before starting capture, OR
2. Use **Filter Table** button to filter already captured packets

#### Filter Examples:
```
Protocol: TCP + Port: 443 = Capture only HTTPS traffic
Custom: "host google.com" = Capture traffic to/from Google
Custom: "port 53" = Capture all DNS traffic
```

### 📊 Understanding the Interface

#### Main Packet Table Columns:
- **Time**: When the packet was captured
- **Protocol**: Network protocol (TCP/HTTP, UDP/DNS, etc.)
- **Flags**: TCP flags (SYN, ACK, FIN, etc.)
- **TTL**: Time to Live (helps identify OS)
- **Direction**: Traffic flow (LOCAL, IN, OUT, EXT)
- **Source**: Origin IP address
- **Destination**: Target IP address
- **Ports**: Source → Destination ports
- **Length**: Packet size in bytes
- **Info**: Detailed protocol information

#### Color Coding System:
- 🟢 **Green (TCP)**: General TCP traffic
- 🔵 **Blue (UDP)**: General UDP traffic  
- 🟠 **Orange (ICMP)**: Ping and network control
- 🟣 **Purple (HTTP)**: Unencrypted web traffic ⚠️
- 🟡 **Yellow (HTTPS)**: Encrypted web traffic ✅
- 🔷 **Cyan (DNS)**: Domain name lookups
- ⚫ **Gray (Others)**: Unknown protocols
- 🔴 **Red (Anomalous)**: Suspicious traffic patterns

### 🔍 Packet Analysis

#### View Packet Details:
1. Click on any packet in the main table
2. **Details Panel** shows structured analysis:
   - 🕒 Timing information
   - 🌐 Network layer (IP)
   - 🔗 Transport layer (TCP/UDP/ICMP)
   - 📱 Application layer services
   - 🔒 Security assessment

3. **Bytes Panel** shows raw packet data in hexadecimal

#### Navigation:
- ⏮️ **First**: Jump to first packet
- ⏪ **Previous**: Go to previous packet
- ⏩ **Next**: Go to next packet
- ⏭️ **Last**: Jump to last packet

### 🚨 Anomaly Detection

#### Start Anomaly Detection:
1. Capture some packets first
2. Go to **Anomaly Detection** → **Detect Anomalies**
3. Real-time graph window opens showing traffic patterns

#### Understanding the Graph:
- 🔵 **Blue Bars**: Normal traffic (below threshold)
- 🔴 **Red Bars**: Anomalous traffic (above threshold)
- 📍 **Red Dashed Line**: DDoS threshold (50 packets)
- 📝 **Letters (A, B, C...)**: Anonymized IP addresses
- 📋 **Gray Box**: IP mapping legend on right side

#### Anomaly Controls:
- **Stop Real-time Detection**: Pause the live updates
- **Clear Graph**: Reset the anomaly visualization

### 💾 Saving Your Work

#### Export to PCAP:
1. Go to **File** → **Save PCAP**
2. Choose location and filename
3. File can be opened in Wireshark for advanced analysis

### 📚 Help System

Access built-in help through the **Help** menu:
- **User Guide**: Complete feature overview
- **Keyboard Shortcuts**: Quick reference
- **About Packet Vision**: Version and developer info



## 🎯 Use Cases

### For Students:
- Learn network protocols (TCP, UDP, ICMP)
- Understand packet structure and flow
- Practice network security concepts

### For Network Engineers:
- Monitor real-time network traffic
- Troubleshoot connectivity issues
- Analyze protocol distributions

### For Security Professionals:
- Detect suspicious traffic patterns
- Identify potential DDoS attacks
- Perform basic network forensics


## 🔒 Privacy & Security

- ✅ All analysis performed locally on your machine
- ✅ No data transmitted to external servers
- ✅ IP addresses anonymized in anomaly graphs
- ✅ Captured data stays on your system
- ⚠️ Use responsibly and only on networks you own/have permission to monitor

## 👨‍💻 Author

**M ABDUL AHAD**  
🔐 *Cybersecurity Enthusiast & Network Security Specialist*
- 💼 LinkedIn: [@m-abdul-ahad](https://www.linkedin.com/in/m-abdul-ahad-91800b2a7)
- 🐙 GitHub: [@MABDULAHAD-HUB](https://github.com/MABDULAHAD-HUB)

## ⭐ Show Your Support

If this project helped you, please consider giving it a ⭐ on GitHub!

---

<p align="center">
  <b>© 2025 M ABDUL AHAD - Packet Vision</b><br>
  <i>Making network analysis accessible to everyone</i>
</p>
