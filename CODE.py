import sys
import threading
from collections import defaultdict
from PyQt5.QtCore import QSize, QTimer
from PyQt5.QtGui import QIcon, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHBoxLayout, QLineEdit, QLabel, QTextEdit, QGroupBox,
    QFileDialog, QSizePolicy, QAction
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
        self.setWindowTitle('ADVANCED NETWORK CAPTURING TOOL')
        self.setGeometry(100, 100, 1200, 700)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        self.layout = QVBoxLayout(central_widget)

        self.create_menu_bar()
        self.create_filter_section()
        self.create_packet_table()
        self.create_detail_views()
        self.initialize_variables()
        self.setup_graph()

    def create_menu_bar(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("File")
        anomaly_menu = menu_bar.addMenu("Anomaly Detection")

        save_action = QAction("Save PCAP", self)
        save_action.triggered.connect(self.save_pcap)
        file_menu.addAction(save_action)

        detect_action = QAction("Detect Anomalies", self)
        detect_action.triggered.connect(self.plot_anomalies)
        anomaly_menu.addAction(detect_action)

        clear_action = QAction("Clear Graph", self)
        clear_action.triggered.connect(self.clear_graph)
        anomaly_menu.addAction(clear_action)

    def create_filter_section(self):
        filter_group = QGroupBox("Filter")
        filter_layout = QHBoxLayout()

        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter filter (e.g., 'tcp')")

        self.start_button = self.create_icon_button("start.jpg", self.start_capture)
        self.stop_button = self.create_icon_button("end1.jpg", self.stop_capture, enabled=False)

        self.go_first_button = self.create_icon_button("up.jpg", self.go_to_first)
        self.go_last_button = self.create_icon_button("down.png", self.go_to_last)
        self.go_previous_button = self.create_icon_button("prenew.jpg", self.go_previous)
        self.go_next_button = self.create_icon_button("nex.jpg", self.go_next)
        

        for widget in [QLabel("Filter:"), self.filter_input, self.start_button, self.stop_button,
                       self.go_first_button,self.go_last_button, self.go_previous_button, self.go_next_button]:
            filter_layout.addWidget(widget)

        filter_group.setLayout(filter_layout)
        self.layout.addWidget(filter_group)

    def create_icon_button(self, icon_path, callback, enabled=True):
        button = QPushButton(self)
        button.setIcon(QIcon(icon_path))
        button.setIconSize(QSize(40, 40))
        button.setEnabled(enabled)
        button.clicked.connect(callback)
        return button

    def create_packet_table(self):
        packet_group = QGroupBox("Packet List")
        self.packet_table = QTableWidget(0, 7, self)
        self.packet_table.setHorizontalHeaderLabels(['Time', 'Protocol', 'Length', 'Source', 'Destination', 'Ports', 'Info'])
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.cellClicked.connect(self.display_packet_details)

        table_layout = QVBoxLayout()
        table_layout.addWidget(self.packet_table)
        packet_group.setLayout(table_layout)
        self.layout.addWidget(packet_group)

    def create_detail_views(self):
        detail_group = QGroupBox("Packet Details")
        detail_layout = QHBoxLayout()

        self.packet_detail_view = self.create_read_only_textedit(400)
        self.packet_bytes_view = self.create_read_only_textedit(400)

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
        self.timer.start(2000)

    def stop_capture(self):
        self.capture_running = False
        self.toggle_buttons(start=True)
        self.timer.stop()

    def toggle_buttons(self, start):
        self.start_button.setEnabled(start)
        self.stop_button.setEnabled(not start)

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=0, filter=self.filter_input.text(),
              stop_filter=lambda _: not self.capture_running)

    def process_packet(self, packet):
        if IP in packet:
            self.captured_packets.append(packet)
            self.packet_lengths.append(len(packet))
            self.ip_packet_count[packet[IP].src] += 1
            self.add_packet_to_table(packet)

    def add_packet_to_table(self, packet):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        values = [
            str(packet.time),
            self.get_protocol(packet),
            str(len(packet)),
            packet[IP].src,
            packet[IP].dst,
            self.get_ports(packet),
            packet.summary()
        ]

        for col, val in enumerate(values):
            self.packet_table.setItem(row, col, QTableWidgetItem(val))

        if self.is_anomalous(packet):
            self.color_row(row, "red")
            self.anomalous_ips.add(packet[IP].src)
        else:
            self.color_row(row, "lightblue")

    def get_protocol(self, packet):
        if TCP in packet: return 'TCP'
        if UDP in packet: return 'UDP'
        if ICMP in packet: return 'ICMP'
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
            self.packet_detail_view.setPlainText(packet.show(dump=True))
            self.packet_bytes_view.setPlainText(" ".join(f"{b:02x}" for b in bytes(packet)))
            self.current_packet_index = row

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
        self.ax.clear()
        ips, counts = zip(*self.ip_packet_count.items())
        colors = ["red" if ip in self.anomalous_ips else "blue" for ip in ips]

        self.ax.bar(ips, counts, color=colors)
        self.ax.set_xlabel("Source IP")
        self.ax.set_ylabel("Packet Count")
        self.ax.set_title("Anomaly Detection")
        self.ax.tick_params(axis='x', rotation=45)
        plt.draw()
        plt.pause(0.01)

    def update_graph(self):
        if self.ip_packet_count:
            self.plot_anomalies()

    def clear_graph(self):
        self.ax.clear()
        plt.draw()

    def save_pcap(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", "", "PCAP Files (*.pcap)")
        if file_name:
            wrpcap(file_name if file_name.endswith('.pcap') else file_name + '.pcap', self.captured_packets)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NetworkCaptureApp()
    window.show()
    sys.exit(app.exec_())
