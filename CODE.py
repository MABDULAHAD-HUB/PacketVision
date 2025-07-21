import sys
import threading
from collections import defaultdict
import time
import datetime
from PyQt5.QtCore import QSize, QTimer
from PyQt5.QtGui import QIcon, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHBoxLayout, QLineEdit, QLabel, QTextEdit, QGroupBox,
    QFileDialog, QSizePolicy, QAction, QComboBox, QFrame
)
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.utils import wrpcap
import matplotlib.pyplot as plt
import numpy as np

class NetworkCaptureApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Packet Vision')
        self.setGeometry(100, 100, 1200, 700)  # Minimized window size

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        self.layout = QVBoxLayout(central_widget)

        self.create_menu_bar()
        self.create_filter_section()
        self.create_color_legend()
        self.create_packet_table()
        self.create_detail_views()
        self.initialize_variables()
        self.setup_graph()

    def create_menu_bar(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("File")
        anomaly_menu = menu_bar.addMenu("Anomaly Detection")
        help_menu = menu_bar.addMenu("Help")

        save_action = QAction("Save PCAP", self)
        save_action.triggered.connect(self.save_pcap)
        file_menu.addAction(save_action)

        detect_action = QAction("Detect Anomalies", self)
        detect_action.triggered.connect(self.start_anomaly_detection)
        anomaly_menu.addAction(detect_action)

        clear_action = QAction("Clear Graph", self)
        clear_action.triggered.connect(self.clear_graph)
        anomaly_menu.addAction(clear_action)
        
        stop_detection_action = QAction("Stop Real-time Detection", self)
        stop_detection_action.triggered.connect(self.stop_anomaly_detection)
        anomaly_menu.addAction(stop_detection_action)

        # Help menu actions
        user_guide_action = QAction("User Guide", self)
        user_guide_action.triggered.connect(self.show_user_guide)
        help_menu.addAction(user_guide_action)

        shortcuts_action = QAction("Keyboard Shortcuts", self)
        shortcuts_action.triggered.connect(self.show_shortcuts)
        help_menu.addAction(shortcuts_action)

        about_action = QAction("About Packet Vision", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_filter_section(self):
        filter_group = QGroupBox("Filter & Controls")
        filter_layout = QHBoxLayout()

        # Protocol filter dropdown
        self.protocol_combo = QComboBox(self)
        self.protocol_combo.addItems(["All", "TCP", "UDP", "ICMP"])
        self.protocol_combo.setStyleSheet("padding: 5px; font-weight: bold;")
        
        # Custom filter input (for advanced filters like host, port ranges, etc.)
        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText("Custom filter (e.g., 'host 8.8.8.8', 'port 80')")
        
        # Port filter input
        self.port_filter = QLineEdit(self)
        self.port_filter.setPlaceholderText("Port (e.g., '80', '443')")
        self.port_filter.setFixedWidth(100)
        
        # Filter captured packets button
        self.filter_table_button = self.create_text_button("Filter Table", self.filter_captured_packets)
        self.filter_table_button.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:pressed {
                background-color: #E65100;
            }
        """)

        # Control buttons
        self.start_button = self.create_icon_button("start_icon.jpg", self.start_capture)
        self.stop_button = self.create_icon_button("end_icon.jpg", self.stop_capture, enabled=False)
        self.restart_button = self.create_text_button("Restart", self.restart_capture, enabled=False)

        # Navigation buttons
        self.go_first_button = self.create_icon_button("up_icon.jpg", self.go_to_first)
        self.go_last_button = self.create_icon_button("down_icon.png", self.go_to_last)
        self.go_previous_button = self.create_icon_button("previous_icon.jpg", self.go_previous)
        self.go_next_button = self.create_icon_button("next_icon.jpg", self.go_next)

        # Add widgets to layout with separators
        widgets = [
            QLabel("Protocol:"), self.protocol_combo,
            QLabel("Port:"), self.port_filter,
            QLabel("Custom:"), self.filter_input,
            self.filter_table_button,
            QLabel("|"),  # Separator
            self.start_button, self.stop_button, self.restart_button,
            QLabel("|"),  # Separator
            self.go_first_button, self.go_previous_button, self.go_next_button, self.go_last_button
        ]
        
        for widget in widgets:
            filter_layout.addWidget(widget)

        filter_group.setLayout(filter_layout)
        self.layout.addWidget(filter_group)

    def create_color_legend(self):
        """Create a color legend showing protocol colors"""
        legend_group = QGroupBox("Protocol Color Reference")
        legend_group.setStyleSheet("""
            QGroupBox {
                margin: 0px;
                padding: 2px;
                border: 1px solid #ccc;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        legend_layout = QHBoxLayout()
        
        protocols = [
            ("TCP", "#4CAF50"),    # Green
            ("UDP", "#2196F3"),    # Blue  
            ("ICMP", "#FF9800"),   # Orange
            ("HTTP", "#9C27B0"),   # Purple
            ("HTTPS", "#FFEB3B"),  # Light Yellow (changed to light yellow)
            ("DNS", "#00BCD4"),    # Cyan
            ("Others", "#9E9E9E"),  # Gray
            ("Anomalous", "#F44336")  # Red for anomalies
        ]
        
        for protocol, color in protocols:
            # Create colored frame
            color_frame = QFrame()
            color_frame.setStyleSheet(f"background-color: {color}; border: 1px solid black;")
            color_frame.setFixedSize(20, 20)
            
            # Create label
            label = QLabel(protocol)
            label.setStyleSheet("font-weight: bold; margin-left: 5px; margin-right: 15px;")
            
            legend_layout.addWidget(color_frame)
            legend_layout.addWidget(label)
        
        legend_layout.addStretch()  # Push everything to the left
        legend_group.setLayout(legend_layout)
        self.layout.addWidget(legend_group)

    def create_icon_button(self, icon_path, callback, enabled=True):
        button = QPushButton(self)
        button.setIcon(QIcon(icon_path))
        button.setIconSize(QSize(40, 40))
        button.setEnabled(enabled)
        button.clicked.connect(callback)
        return button

    def create_text_button(self, text, callback, enabled=True):
        button = QPushButton(text, self)
        button.setEnabled(enabled)
        button.clicked.connect(callback)
        button.setFixedHeight(40)  # Match the height of icon buttons
        button.setStyleSheet("""
            QPushButton {
                background-color: #607D8B;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #546E7A;
            }
            QPushButton:pressed {
                background-color: #455A64;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        return button

    def create_packet_table(self):
        packet_group = QGroupBox("Packet List")
        self.packet_table = QTableWidget(0, 10, self)  # 10 columns
        self.packet_table.setHorizontalHeaderLabels(['Time', 'Protocol', 'Flags', 'TTL', 'Direction', 'Source', 'Destination', 'Ports', 'Length', 'Info'])
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.cellClicked.connect(self.display_packet_details)

        # Set the table to automatically resize columns to fit the available space
        header = self.packet_table.horizontalHeader()
        header.setStretchLastSection(True)  # Last column (Info) stretches to fill remaining space
        
        # Set resize modes for each column to distribute space proportionally
        from PyQt5.QtWidgets import QHeaderView
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Time
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Protocol
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Flags
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # TTL
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Direction
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # Source
        header.setSectionResizeMode(6, QHeaderView.Interactive)  # Destination
        header.setSectionResizeMode(7, QHeaderView.Interactive)  # Ports
        header.setSectionResizeMode(8, QHeaderView.Interactive)  # Length
        header.setSectionResizeMode(9, QHeaderView.Stretch)     # Info - stretches to fill remaining space

        # Set initial minimum column widths for readability
        self.packet_table.setColumnWidth(0, 90)   # Time
        self.packet_table.setColumnWidth(1, 80)   # Protocol
        self.packet_table.setColumnWidth(2, 80)   # Flags
        self.packet_table.setColumnWidth(3, 40)   # TTL
        self.packet_table.setColumnWidth(4, 75)   # Direction
        self.packet_table.setColumnWidth(5, 100)  # Source
        self.packet_table.setColumnWidth(6, 100)  # Destination
        self.packet_table.setColumnWidth(7, 75)   # Ports
        self.packet_table.setColumnWidth(8, 55)   # Length
        # Info column will auto-stretch to fill remaining space

        table_layout = QVBoxLayout()
        table_layout.addWidget(self.packet_table)
        packet_group.setLayout(table_layout)
        self.layout.addWidget(packet_group)

    def create_detail_views(self):
        detail_group = QGroupBox("Packet Details")
        detail_layout = QHBoxLayout()

        self.packet_detail_view = self.create_read_only_textedit(350)  # Reduced width
        self.packet_bytes_view = self.create_read_only_textedit(350)   # Reduced width

        detail_layout.addWidget(QLabel("Details:"))
        detail_layout.addWidget(self.packet_detail_view)
        detail_layout.addWidget(QLabel("Bytes:"))
        detail_layout.addWidget(self.packet_bytes_view)

        detail_group.setLayout(detail_layout)
        self.layout.addWidget(detail_group)

    def create_read_only_textedit(self, width):
        text_edit = QTextEdit(self)
        text_edit.setReadOnly(True)
        text_edit.setFixedWidth(width)
        return text_edit

    def initialize_variables(self):
        self.captured_packets = []
        self.all_captured_packets = []  # Store all packets for filtering
        self.packet_lengths = []
        self.ip_packet_count = defaultdict(int)
        self.anomalous_ips = set()
        self.current_packet_index = 0
        self.capture_running = False

    def setup_graph(self):
        self.fig, self.ax = plt.subplots()
        plt.ion()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)

    def start_capture(self):
        self.capture_running = True
        self.toggle_buttons(start=False)
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()
        # Removed automatic timer start - graph will only show when manually triggered
        print("Packet capture started...")

    def stop_capture(self):
        self.capture_running = False
        self.toggle_buttons(start=True)
        self.timer.stop()  # Stop timer if it's running
        print("Packet capture stopped.")

    def restart_capture(self):
        """Restart packet capture - clears all data and starts fresh"""
        print("Restarting packet capture...")
        self.stop_capture()
        
        # Clear all captured data
        self.captured_packets.clear()
        self.all_captured_packets.clear()  # Clear all stored packets too
        self.packet_lengths.clear()
        self.ip_packet_count.clear()
        self.anomalous_ips.clear()
        self.current_packet_index = 0
        
        # Clear the packet table
        self.packet_table.setRowCount(0)
        
        # Clear packet detail views
        self.packet_detail_view.clear()
        self.packet_bytes_view.clear()
        
        # Clear the graph if it exists
        if hasattr(self, 'ax'):
            self.ax.clear()
            plt.draw()
        
        # Wait a moment then restart capture
        QTimer.singleShot(500, self.start_capture)  # Start after 500ms delay

    def filter_captured_packets(self):
        """Filter already captured packets based on current filter settings"""
        if not self.all_captured_packets:
            print("No captured packets to filter")
            return
            
        print("Filtering captured packets...")
        
        # Get current filter settings
        protocol_filter = self.protocol_combo.currentText().lower()
        port_filter = self.port_filter.text().strip()
        custom_filter = self.filter_input.text().strip().lower()
        
        # Clear current display
        self.packet_table.setRowCount(0)
        self.captured_packets.clear()
        self.packet_lengths.clear()
        self.ip_packet_count.clear()
        self.anomalous_ips.clear()
        
        filtered_count = 0
        for packet in self.all_captured_packets:
            if self.packet_matches_filter(packet, protocol_filter, port_filter, custom_filter):
                self.captured_packets.append(packet)
                self.packet_lengths.append(len(packet))
                self.ip_packet_count[packet[IP].src] += 1
                self.add_packet_to_table(packet)
                filtered_count += 1
        
        print(f"Filtered: {filtered_count} packets match current filters")
        
        # Clear packet details if no packets match
        if filtered_count == 0:
            self.packet_detail_view.clear()
            self.packet_bytes_view.clear()

    def packet_matches_filter(self, packet, protocol_filter, port_filter, custom_filter):
        """Check if packet matches the specified filters"""
        
        # Protocol filter
        if protocol_filter != "all":
            if protocol_filter == "tcp" and TCP not in packet:
                return False
            elif protocol_filter == "udp" and UDP not in packet:
                return False
            elif protocol_filter == "icmp" and ICMP not in packet:
                return False
        
        # Port filter
        if port_filter:
            try:
                target_port = int(port_filter)
                packet_ports = []
                
                if TCP in packet:
                    packet_ports.extend([packet[TCP].sport, packet[TCP].dport])
                elif UDP in packet:
                    packet_ports.extend([packet[UDP].sport, packet[UDP].dport])
                
                if target_port not in packet_ports:
                    return False
            except ValueError:
                # Invalid port number, ignore port filter
                pass
        
        # Custom filter (simple text matching in packet summary and IPs)
        if custom_filter:
            packet_summary = packet.summary().lower()
            packet_src = packet[IP].src.lower() if IP in packet else ""
            packet_dst = packet[IP].dst.lower() if IP in packet else ""
            
            # Check if custom filter text appears in summary or IP addresses
            if not any(custom_filter in field for field in [packet_summary, packet_src, packet_dst]):
                return False
        
        return True

    def toggle_buttons(self, start):
        self.start_button.setEnabled(start)
        self.stop_button.setEnabled(not start)
        # Restart button enabled only when stopped AND we have captured some packets
        has_packets = len(self.all_captured_packets) > 0 or self.packet_table.rowCount() > 0
        self.restart_button.setEnabled(start and has_packets)

    def sniff_packets(self):
        """Enhanced packet sniffing with multiple filter options"""
        try:
            # Build filter from dropdown and inputs
            protocol_filter = self.protocol_combo.currentText().lower()
            custom_filter = self.filter_input.text().strip()
            port_filter = self.port_filter.text().strip()
            
            # Construct the complete filter
            filter_parts = []
            
            # Add protocol filter
            if protocol_filter != "all":
                filter_parts.append(protocol_filter)
            
            # Add port filter
            if port_filter:
                filter_parts.append(f"port {port_filter}")
            
            # Add custom filter
            if custom_filter:
                filter_parts.append(custom_filter)
            
            # Combine filters with 'and'
            filter_text = " and ".join(filter_parts) if filter_parts else None
            
            print(f"Using filter: {filter_text if filter_text else 'No filter (capturing all packets)'}")
            
            sniff(prn=self.process_packet, store=0, filter=filter_text,
                  stop_filter=lambda _: not self.capture_running)
                  
        except Exception as e:
            print(f"Packet capture error: {e}")
            print("Make sure you have proper permissions and network interface access")

    def process_packet(self, packet):
        if IP in packet:
            self.captured_packets.append(packet)
            self.all_captured_packets.append(packet)  # Store all packets for filtering
            self.packet_lengths.append(len(packet))
            self.ip_packet_count[packet[IP].src] += 1
            self.add_packet_to_table(packet)

    def get_protocol_color(self, packet):
        """Return color based on packet protocol"""
        if TCP in packet:
            # Check for specific applications
            if hasattr(packet[TCP], 'dport') or hasattr(packet[TCP], 'sport'):
                dport = getattr(packet[TCP], 'dport', 0)
                sport = getattr(packet[TCP], 'sport', 0)
                
                if dport == 80 or sport == 80:
                    return "#9C27B0"  # Purple for HTTP
                elif dport == 443 or sport == 443:
                    return "#FFEB3B"  # Light Yellow for HTTPS
                else:
                    return "#4CAF50"  # Green for TCP
            return "#4CAF50"  # Green for TCP
        elif UDP in packet:
            # Check for DNS
            if hasattr(packet[UDP], 'dport') or hasattr(packet[UDP], 'sport'):
                dport = getattr(packet[UDP], 'dport', 0)
                sport = getattr(packet[UDP], 'sport', 0)
                
                if dport == 53 or sport == 53:
                    return "#00BCD4"  # Cyan for DNS
                else:
                    return "#2196F3"  # Blue for UDP
            return "#2196F3"  # Blue for UDP
        elif ICMP in packet:
            return "#FF9800"  # Orange for ICMP
        else:
            return "#9E9E9E"  # Gray for other protocols

    def get_tcp_flags(self, packet):
        """Get TCP flags as readable flag names"""
        if TCP not in packet:
            return "N/A"
        
        flags = []
        tcp_layer = packet[TCP]
        
        if tcp_layer.flags & 0x02:  # SYN
            flags.append("SYN")
        if tcp_layer.flags & 0x10:  # ACK
            flags.append("ACK")
        if tcp_layer.flags & 0x01:  # FIN
            flags.append("FIN")
        if tcp_layer.flags & 0x04:  # RST
            flags.append("RST")
        if tcp_layer.flags & 0x08:  # PSH
            flags.append("PSH")
        if tcp_layer.flags & 0x20:  # URG
            flags.append("URG")
        
        return "+".join(flags) if flags else "-"

    def get_ttl(self, packet):
        """Get TTL value"""
        if IP in packet:
            return str(packet[IP].ttl)
        return "N/A"

    def get_direction(self, packet):
        """Determine packet direction with enhanced logic"""
        if IP not in packet:
            return "?"
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check if source is private network
        src_private = src_ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                                        '127.')) or src_ip == '0.0.0.0'
        
        # Check if destination is private network  
        dst_private = dst_ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                                        '127.')) or dst_ip == '0.0.0.0'
        
        # Determine direction based on private/public IPs
        if src_private and dst_private:
            return "LOCAL"  # Both private - local network traffic
        elif src_private and not dst_private:
            return "OUT"    # Private to public - outbound
        elif not src_private and dst_private:
            return "IN"     # Public to private - inbound
        else:
            return "EXT"    # Both public - external traffic

    def get_protocol_info(self, packet):
        """Get detailed protocol-specific information"""
        if IP not in packet:
            return "No IP layer"
        
        info_parts = []
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            
            # Add sequence and acknowledgment numbers
            info_parts.append(f"Seq={tcp_layer.seq}")
            if tcp_layer.flags & 0x10:  # ACK flag
                info_parts.append(f"Ack={tcp_layer.ack}")
            
            # Add window size
            info_parts.append(f"Win={tcp_layer.window}")
            
            # Add specific service info
            dport = getattr(tcp_layer, 'dport', 0)
            sport = getattr(tcp_layer, 'sport', 0)
            
            if dport == 80 or sport == 80:
                info_parts.append("HTTP")
            elif dport == 443 or sport == 443:
                info_parts.append("HTTPS/TLS")
            elif dport == 22 or sport == 22:
                info_parts.append("SSH")
            elif dport == 21 or sport == 21:
                info_parts.append("FTP")
            elif dport == 25 or sport == 25:
                info_parts.append("SMTP")
            elif dport == 53 or sport == 53:
                info_parts.append("DNS over TCP")
                
        elif UDP in packet:
            udp_layer = packet[UDP]
            dport = getattr(udp_layer, 'dport', 0)
            sport = getattr(udp_layer, 'sport', 0)
            
            info_parts.append(f"Len={len(udp_layer)}")
            
            if dport == 53 or sport == 53:
                info_parts.append("DNS Query/Response")
            elif dport == 67 or sport == 67:
                info_parts.append("DHCP Server")
            elif dport == 68 or sport == 68:
                info_parts.append("DHCP Client")
            elif dport == 123 or sport == 123:
                info_parts.append("NTP Time Sync")
            elif dport == 161 or sport == 161:
                info_parts.append("SNMP")
            elif dport == 514 or sport == 514:
                info_parts.append("Syslog")
                
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            
            if icmp_type == 0:
                info_parts.append("Echo Reply (Ping Response)")
            elif icmp_type == 8:
                info_parts.append("Echo Request (Ping)")
            elif icmp_type == 3:
                if icmp_code == 0:
                    info_parts.append("Destination Network Unreachable")
                elif icmp_code == 1:
                    info_parts.append("Destination Host Unreachable")
                elif icmp_code == 3:
                    info_parts.append("Destination Port Unreachable")
                else:
                    info_parts.append(f"Destination Unreachable (Code {icmp_code})")
            elif icmp_type == 11:
                info_parts.append("Time Exceeded (TTL=0)")
            else:
                info_parts.append(f"ICMP Type={icmp_type} Code={icmp_code}")
        
        # Add IP-level info
        ip_layer = packet[IP]
        if hasattr(ip_layer, 'frag') and ip_layer.frag != 0:
            info_parts.append(f"Fragment offset={ip_layer.frag}")
        
        if hasattr(ip_layer, 'flags') and ip_layer.flags & 0x2:  # Don't Fragment flag
            info_parts.append("DF")
        
        return " | ".join(info_parts) if info_parts else "Standard packet"

    def add_packet_to_table(self, packet):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        # Format timestamp properly
        current_time = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]  # Show milliseconds
        
        values = [
            current_time,  # Use current time instead of packet.time
            self.get_protocol(packet),
            self.get_tcp_flags(packet),
            self.get_ttl(packet),
            self.get_direction(packet),
            packet[IP].src,
            packet[IP].dst,
            self.get_ports(packet),
            str(len(packet)),
            self.get_protocol_info(packet)  # New Info column
        ]

        for col, val in enumerate(values):
            self.packet_table.setItem(row, col, QTableWidgetItem(val))

        if self.is_anomalous(packet):
            self.color_row(row, "#F44336")  # Red for anomalies
            self.anomalous_ips.add(packet[IP].src)
        else:
            protocol_color = self.get_protocol_color(packet)
            self.color_row(row, protocol_color)

    def get_protocol(self, packet):
        if TCP in packet:
            # Check for specific applications on TCP
            if hasattr(packet[TCP], 'dport') or hasattr(packet[TCP], 'sport'):
                dport = getattr(packet[TCP], 'dport', 0)
                sport = getattr(packet[TCP], 'sport', 0)
                
                if dport == 80 or sport == 80:
                    return 'TCP/HTTP'
                elif dport == 443 or sport == 443:
                    return 'TCP/HTTPS'
                elif dport == 22 or sport == 22:
                    return 'TCP/SSH'
                elif dport == 21 or sport == 21:
                    return 'TCP/FTP'
                elif dport == 23 or sport == 23:
                    return 'TCP/TELNET'
                elif dport == 25 or sport == 25:
                    return 'TCP/SMTP'
                elif dport == 110 or sport == 110:
                    return 'TCP/POP3'
                elif dport == 143 or sport == 143:
                    return 'TCP/IMAP'
                elif dport == 993 or sport == 993:
                    return 'TCP/IMAPS'
                elif dport == 995 or sport == 995:
                    return 'TCP/POP3S'
                else:
                    return 'TCP'
            return 'TCP'
        elif UDP in packet:
            # Check for specific applications on UDP
            if hasattr(packet[UDP], 'dport') or hasattr(packet[UDP], 'sport'):
                dport = getattr(packet[UDP], 'dport', 0)
                sport = getattr(packet[UDP], 'sport', 0)
                
                if dport == 53 or sport == 53:
                    return 'UDP/DNS'
                elif dport == 67 or sport == 67 or dport == 68 or sport == 68:
                    return 'UDP/DHCP'
                elif dport == 123 or sport == 123:
                    return 'UDP/NTP'
                elif dport == 161 or sport == 161:
                    return 'UDP/SNMP'
                elif dport == 514 or sport == 514:
                    return 'UDP/SYSLOG'
                else:
                    return 'UDP'
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        return 'IP' if IP in packet else 'Unknown'

    def get_ports(self, packet):
        if TCP in packet or UDP in packet:
            proto = TCP if TCP in packet else UDP
            return f"{packet[proto].sport} -> {packet[proto].dport}"
        return 'N/A'

    def is_anomalous(self, packet):
        ddos_threshold = 50
        length_mean, length_std = np.mean(self.packet_lengths), np.std(self.packet_lengths)
        return self.ip_packet_count[packet[IP].src] > ddos_threshold or abs(len(packet) - length_mean) > 2 * length_std

    def color_row(self, row, color):
        for col in range(self.packet_table.columnCount()):
            item = self.packet_table.item(row, col)
            if item:
                item.setBackground(QColor(color))

    def display_packet_details(self, row, _):
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            
            # Format structured packet details
            formatted_details = self.format_packet_details(packet, row)
            self.packet_detail_view.setPlainText(formatted_details)
            
            # Format bytes view with better spacing
            hex_bytes = " ".join(f"{b:02x}" for b in bytes(packet))
            self.packet_bytes_view.setPlainText(hex_bytes)
            
            self.current_packet_index = row

    def format_packet_details(self, packet, packet_num):
        """Format packet details in a structured, readable format"""
        details = []
        
        # Header
        protocol = self.get_protocol(packet)
        details.append("═" * 50)
        details.append(f"         PACKET #{packet_num + 1} ANALYSIS")
        details.append("═" * 50)
        details.append("")
        
        # Timing Information
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        details.append("🕒 TIMING INFO")
        details.append(f"   Time: {current_time}")
        details.append(f"   Frame: #{packet_num + 1}")
        details.append("")
        
        # Network Layer (IP)
        if IP in packet:
            ip_layer = packet[IP]
            direction = self.get_direction(packet)
            details.append("🌐 NETWORK LAYER (IP)")
            details.append(f"   Source: {ip_layer.src}")
            details.append(f"   Destination: {ip_layer.dst}")
            details.append(f"   Protocol: {protocol}")
            details.append(f"   TTL: {ip_layer.ttl} hops")
            details.append(f"   Size: {len(packet)} bytes")
            details.append(f"   Direction: {direction}")
            details.append("")
        
        # Transport Layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            flags = self.get_tcp_flags(packet)
            details.append("🔗 TRANSPORT LAYER (TCP)")
            details.append(f"   Source Port: {tcp_layer.sport}")
            details.append(f"   Dest Port: {tcp_layer.dport}")
            details.append(f"   Flags: {flags}")
            details.append(f"   Seq: {tcp_layer.seq}")
            details.append(f"   Ack: {tcp_layer.ack}")
            details.append(f"   Window: {tcp_layer.window} bytes")
            details.append("")
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            details.append("🔗 TRANSPORT LAYER (UDP)")
            details.append(f"   Source Port: {udp_layer.sport}")
            details.append(f"   Dest Port: {udp_layer.dport}")
            details.append(f"   Length: {udp_layer.len} bytes")
            details.append("   No connection state (UDP)")
            details.append("")
            
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            details.append("🔗 TRANSPORT LAYER (ICMP)")
            details.append(f"   Type: {icmp_layer.type}")
            details.append(f"   Code: {icmp_layer.code}")
            details.append("")
        
        # Application Layer
        app_info = self.get_application_layer_info(packet)
        details.append("📱 APPLICATION LAYER")
        details.extend(app_info)
        details.append("")
        
        # Security Information
        security_info = self.get_security_info(packet)
        if security_info:
            details.append("🔒 SECURITY INFO")
            details.extend(security_info)
            details.append("")
        
        # Anomaly check
        if self.is_anomalous(packet):
            details.append("⚠️ ANOMALY DETECTED")
            details.append("   This packet shows unusual patterns")
            details.append("")
        
        return "\n".join(details)
    
    def get_application_layer_info(self, packet):
        """Get application layer specific information"""
        info = []
        
        if TCP in packet:
            dport = getattr(packet[TCP], 'dport', 0)
            sport = getattr(packet[TCP], 'sport', 0)
            
            if dport == 80 or sport == 80:
                info.append("   Service: HTTP (Web)")
                info.append("   Security: Unencrypted")
                info.append("   ⚠️ Plain text web traffic")
            elif dport == 443 or sport == 443:
                info.append("   Service: HTTPS (Secure Web)")
                info.append("   Security: TLS Encrypted")
                info.append("   Content: Encrypted web data")
            elif dport == 22 or sport == 22:
                info.append("   Service: SSH (Secure Shell)")
                info.append("   Security: Encrypted terminal")
            elif dport == 21 or sport == 21:
                info.append("   Service: FTP (File Transfer)")
                info.append("   Security: Plain text")
                info.append("   ⚠️ Unencrypted file transfer")
            elif dport == 25 or sport == 25:
                info.append("   Service: SMTP (Email)")
                info.append("   Security: Usually unencrypted")
                info.append("   ⚠️ Email in plain text")
            elif dport == 53 or sport == 53:
                info.append("   Service: DNS over TCP")
                info.append("   Content: Large DNS query/response")
            else:
                info.append(f"   Service: TCP Port {dport}")
                info.append("   Type: Custom application")
                
        elif UDP in packet:
            dport = getattr(packet[UDP], 'dport', 0)
            sport = getattr(packet[UDP], 'sport', 0)
            
            if dport == 53 or sport == 53:
                info.append("   Service: DNS Query/Response")
                info.append("   Type: Domain name lookup")
                info.append("   Security: Plain text")
            elif dport == 67 or sport == 67:
                info.append("   Service: DHCP Server")
                info.append("   Type: IP address assignment")
            elif dport == 68 or sport == 68:
                info.append("   Service: DHCP Client")
                info.append("   Type: Requesting IP address")
            elif dport == 123 or sport == 123:
                info.append("   Service: NTP (Time Sync)")
                info.append("   Type: Clock synchronization")
            elif dport == 161 or sport == 161:
                info.append("   Service: SNMP")
                info.append("   Type: Network management")
            else:
                info.append(f"   Service: UDP Port {dport}")
                info.append("   Type: Custom application")
                
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            if icmp_type == 8:
                info.append("   Service: Ping Request")
                info.append("   Type: Network connectivity test")
            elif icmp_type == 0:
                info.append("   Service: Ping Reply")
                info.append("   Type: Network response")
            elif icmp_type == 3:
                info.append("   Service: Destination Unreachable")
                info.append("   Type: Network error message")
            elif icmp_type == 11:
                info.append("   Service: Time Exceeded")
                info.append("   Type: TTL expired")
            else:
                info.append(f"   Service: ICMP Type {icmp_type}")
                info.append("   Type: Network control message")
        else:
            info.append("   Service: Unknown/Other")
            info.append("   Type: Non-standard protocol")
        
        return info
    
    def get_security_info(self, packet):
        """Get security-related information"""
        security = []
        
        if TCP in packet:
            dport = getattr(packet[TCP], 'dport', 0)
            sport = getattr(packet[TCP], 'sport', 0)
            
            if dport == 443 or sport == 443:
                security.append("   Status: ✅ SECURE (HTTPS/TLS)")
                security.append("   Encryption: Strong")
            elif dport == 80 or sport == 80:
                security.append("   Status: ⚠️ UNSECURE (HTTP)")
                security.append("   Risk: Data visible in plain text")
            elif dport == 22 or sport == 22:
                security.append("   Status: ✅ SECURE (SSH)")
                security.append("   Encryption: Strong")
            elif dport in [21, 23, 25]:  # FTP, Telnet, SMTP
                security.append("   Status: ⚠️ UNSECURE")
                security.append("   Risk: Credentials/data in plain text")
        
        # Check for private/public IP communication
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            src_private = src_ip.startswith(('192.168.', '10.', '172.'))
            dst_private = dst_ip.startswith(('192.168.', '10.', '172.'))
            
            if not src_private and not dst_private:
                security.append("   External: Both IPs are public")
                security.append("   Monitor: Internet traffic")
        
        return security

    def show_user_guide(self):
        """Show user guide dialog"""
        from PyQt5.QtWidgets import QMessageBox
        
        guide_text = """
📖 PACKET VISION USER GUIDE

🚀 GETTING STARTED:
1. Click START button to begin packet capture
2. Select protocols from dropdown (TCP, UDP, ICMP)
3. Filter by port number or custom criteria
4. Click on any packet to view detailed analysis

🎯 FEATURES:
• Real-time packet capture and analysis
• Color-coded protocols for easy identification
• Structured packet details with security info
• Anomaly detection with visual graphs
• Export captured packets to PCAP files

🔍 FILTERING:
• Protocol Filter: Select specific protocols
• Port Filter: Enter port numbers (80, 443, etc.)
• Custom Filter: Use advanced filters like 'host 8.8.8.8'
• Filter Table: Apply filters to already captured packets

🛡️ SECURITY INDICATORS:
• ✅ Green: Secure protocols (HTTPS, SSH)
• ⚠️ Yellow: Unsecure protocols (HTTP, FTP)
• 🔴 Red: Anomalous traffic patterns

📊 ANOMALY DETECTION:
• Go to Anomaly Detection → Detect Anomalies
• View real-time graphs of packet patterns
• IPs are anonymized with letters for privacy

🎨 GRAPH COLOR REFERENCE:
• 🔵 Blue Bars: Normal traffic (below threshold)
• 🔴 Red Bars: Anomalous traffic (above threshold)
• 🔴 Red Dashed Line: DDoS threshold (50 packets)
• 📊 Letters (A, B, C...): Anonymized IP addresses
• 📋 Gray Box: IP mapping legend on right side
        """
        
        msg = QMessageBox()
        msg.setWindowTitle("Packet Vision - User Guide")
        msg.setText(guide_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()

    def show_shortcuts(self):
        """Show keyboard shortcuts dialog"""
        from PyQt5.QtWidgets import QMessageBox
        
        shortcuts_text = """
⌨️ KEYBOARD SHORTCUTS

🎮 NAVIGATION:
• First Packet: Use navigation buttons
• Previous Packet: ← navigation button
• Next Packet: → navigation button  
• Last Packet: ↓ navigation button

🔧 CONTROLS:
• Start Capture: Click START button
• Stop Capture: Click STOP button
• Restart: Click RESTART button
• Filter Table: Click FILTER TABLE button

💾 FILE OPERATIONS:
• Save PCAP: File → Save PCAP
• Export: Saves all captured packets

📊 ANALYSIS:
• Anomaly Detection: Anomaly Detection → Detect Anomalies
• Clear Graph: Anomaly Detection → Clear Graph
• Stop Detection: Anomaly Detection → Stop Real-time Detection

💡 TIPS:
• Double-click packets for quick details view
• Use color legend to identify protocol types
• Monitor the security status in packet details
        """
        
        msg = QMessageBox()
        msg.setWindowTitle("Packet Vision - Keyboard Shortcuts")
        msg.setText(shortcuts_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()

    def show_about(self):
        """Show about dialog"""
        from PyQt5.QtWidgets import QMessageBox
        
        about_text = """
🌟 PACKET VISION v1.0

🔬 Professional Network Packet Analyzer
Built with Python, PyQt5, and Scapy

✨ FEATURES:
• Real-time packet capture
• Protocol analysis (TCP, UDP, ICMP)
• Security assessment
• Anomaly detection
• PCAP export capability

🛠️ TECHNICAL STACK:
• Python 3.x
• PyQt5 (GUI Framework)
• Scapy (Packet Processing)
• Matplotlib (Visualization)
• NumPy (Data Analysis)

👨‍💻 DEVELOPED BY:
M ABDUL AHAD
Cybersecurity Enthusiast & Network Security

🎯 DEVELOPED FOR:
Network security professionals, students, and researchers
who need comprehensive packet analysis capabilities.

🔒 PRIVACY:
All analysis is performed locally on your machine.
No data is transmitted to external servers.

© 2025 Packet Vision - Developed by M ABDUL AHAD
        """
        
        msg = QMessageBox()
        msg.setWindowTitle("About Packet Vision")
        msg.setText(about_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()

    def go_to_first(self):
        self.navigate_to_packet(0)

    def go_previous(self):
        if self.current_packet_index > 0:
            self.navigate_to_packet(self.current_packet_index - 1)

    def go_next(self):
        if self.current_packet_index < len(self.captured_packets) - 1:
            self.navigate_to_packet(self.current_packet_index + 1)

    def go_to_last(self):
        self.navigate_to_packet(len(self.captured_packets) - 1)

    def navigate_to_packet(self, index):
        self.current_packet_index = index
        self.display_packet_details(index, 0)
        self.packet_table.selectRow(index)

    def plot_anomalies(self):
        """Enhanced anomaly detection with IP letter mapping"""
        if not self.ip_packet_count:
            print("No packets captured yet for anomaly detection")
            return
            
        self.ax.clear()
        
        # Create IP to letter mapping for privacy
        sorted_ips = sorted(self.ip_packet_count.keys())
        ip_to_letter = {}
        letter_labels = []
        
        for i, ip in enumerate(sorted_ips):
            letter = chr(65 + i)  # A, B, C, D, etc.
            ip_to_letter[ip] = letter
            letter_labels.append(letter)
        
        # Get counts in the same order as letters
        counts = [self.ip_packet_count[ip] for ip in sorted_ips]
        colors = ["red" if ip in self.anomalous_ips else "blue" for ip in sorted_ips]

        # Create the bar chart with letter labels
        bars = self.ax.bar(letter_labels, counts, color=colors)
        self.ax.set_xlabel("Source IP (Letters)")
        self.ax.set_ylabel("Packet Count")
        self.ax.set_title("Real-time Anomaly Detection")
        
        # Add threshold line
        ddos_threshold = 50
        self.ax.axhline(y=ddos_threshold, color='red', linestyle='--', alpha=0.7, label=f'Threshold: {ddos_threshold}')
        
        # Create IP mapping text for display on the side
        mapping_text = "IP Mapping:\n"
        for ip in sorted_ips:
            letter = ip_to_letter[ip]
            status = " (ANOMALY)" if ip in self.anomalous_ips else ""
            mapping_text += f"{letter} = {ip}{status}\n"
        
        # Add the mapping text to the right side of the plot
        self.ax.text(1.02, 0.98, mapping_text, transform=self.ax.transAxes, 
                     fontsize=9, verticalalignment='top', 
                     bbox=dict(boxstyle="round,pad=0.5", facecolor="lightgray", alpha=0.8))
        
        self.ax.legend()
        plt.tight_layout()  # Adjust layout to accommodate the text
        plt.draw()
        plt.pause(0.01)

    def start_anomaly_detection(self):
        """Start anomaly detection with real-time updates"""
        if not self.ip_packet_count:
            print("No packets captured yet. Please start packet capture first.")
            return
        
        print("Starting real-time anomaly detection...")
        self.plot_anomalies()  # Show initial plot
        self.timer.start(2000)  # Start real-time updates every 2 seconds
        
    def stop_anomaly_detection(self):
        """Stop real-time anomaly detection"""
        self.timer.stop()
        print("Real-time anomaly detection stopped.")

    def update_graph(self):
        if self.ip_packet_count:
            self.plot_anomalies()

    def clear_graph(self):
        """Clear the anomaly detection graph and stop real-time updates"""
        self.timer.stop()  # Stop real-time updates
        self.ax.clear()
        plt.draw()
        print("Graph cleared and real-time detection stopped.")

    def save_pcap(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", "", "PCAP Files (*.pcap)")
        if file_name:
            wrpcap(file_name if file_name.endswith('.pcap') else file_name + '.pcap', self.captured_packets)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NetworkCaptureApp()
    window.show()
    sys.exit(app.exec_())
