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

<p align="center">
  <img src="screenshots/start_gui.png" alt="Packet Vision UI" width="80%">
</p>

---

## 📌 About the Project

**Packet Vision** is a Python-powered desktop tool that captures, filters, and visualizes live network packets. Designed with a sleek PyQt5 GUI, it supports real-time traffic inspection, anomaly detection using statistical thresholds, and seamless PCAP export for advanced analysis in tools like Wireshark.

Whether you're a cybersecurity student, network engineer, or penetration tester, this tool offers an efficient and accessible way to peek inside your traffic.



## ✨ Key Features

- 📡 **Live Packet Capture** with Scapy and BPF filtering
- 🎛️ **Modern GUI** built using PyQt5
- 🧠 **Statistical Anomaly Detection** with visualization
- 🧾 **Detailed Packet Info**: source, destination, ports, bytes
- 🗂️ **PCAP Export**: Save captured data for use with Wireshark
- 📊 **Graphical Representation**: Real-time anomaly graph plotting
- 🧭 **Navigation Controls**: First, Last, Next, Previous packet browsing



## 🖼️ Screenshots

| Start GUI | Capturing Packets |
|-----------|-------------------|
| ![Start](screenshots/start_gui.png) | ![Capture](screenshots/capturing_packets.png) |

| Anomaly Detection Graph | Packet Detail View |
|-------------------------|--------------------|
| ![Anomaly](screenshots/anomaly_graph.png) | ![Detail](screenshots/packet_detail.png) |



## 🧰 Tech Stack

| Component      | Tool/Library  |
|----------------|---------------|
| Language       | Python 3.6+   |
| GUI Framework  | PyQt5         |
| Packet Capture | Scapy         |
| Stats/Analysis | NumPy         |
| Graphing       | Matplotlib    |
| Export Format  | PCAP          |



## 🛠️ Setup Instructions

### 📁 Clone the Repository

```bash
git clone https://github.com/yourusername/PacketVision.git
cd PacketVision
``` 
### 🧪 Create and Activate a Virtual Environment

#### 🔹 On Windows
```bash
python -m venv venv
venv\Scripts\activate
```
#### 🔹 On Linux/macOS
```bash
python3 -m venv venv
source venv/bin/activate
```
### 📦 Install Dependencies

```bash
pip install -r requirements.txt

```
### ▶️ Run the Application
```bash
python CODE.py
```

## 📘 Usage Instructions

- Use the **filter box** (e.g., `tcp`, `udp`, `icmp`) to apply protocol filters.
- Click the ▶️ **Start** button to begin capturing packets.
- Select any packet in the table to view:
  - 📝 Detailed header and payload data
  - 🔍 Hex byte view of the raw packet
- Navigate using the ⏮ ⏪ ⏩ ⏭ buttons.
- Use **Anomaly Detection → Detect Anomalies** to plot suspicious traffic patterns.
- Save all captured traffic with **File → Save PCAP** for offline analysis (e.g., in Wireshark).



## 👨‍💻 Author

<p align="left">
  <img src="screenshots/author_logo.png" alt="M Abdul Ahad Logo" width="160">
</p>
GitHub: [@abdulahad00](https://github.com/abdulahad00)

