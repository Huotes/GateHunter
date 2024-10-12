import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
    QVBoxLayout, QHBoxLayout, QRadioButton, QGroupBox, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt
from modules.scanner import PortScanner
from modules.network_scanner import NetworkScanner

class GateHunterGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('GateHunter')
        self.init_ui()

    def init_ui(self):
        # Criação dos widgets
        self.option1 = QRadioButton("Escanear um único IP ou DNS")
        self.option2 = QRadioButton("Descobrir e escanear todos os hosts ativos em uma rede")
        self.option3 = QRadioButton("Descobrir automaticamente a rede local e escanear todos os hosts")

        self.option1.setChecked(True)  # Opção padrão

        self.target_label = QLabel('Alvo (IP/DNS):')
        self.target_input = QLineEdit()

        self.network_label = QLabel('Rede (ex: 192.168.1.0/24):')
        self.network_input = QLineEdit()
        self.network_input.setDisabled(True)  # Desabilitado por padrão

        self.use_common_ports = QRadioButton("Usar portas comuns")
        self.custom_ports = QRadioButton("Especificar portas")
        self.use_common_ports.setChecked(True)

        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Ex: 22,80,443")
        self.ports_input.setDisabled(True)

        self.scan_button = QPushButton('Iniciar Escaneamento')
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)

        # Layouts
        main_layout = QVBoxLayout()

        # Opções de escaneamento
        option_layout = QHBoxLayout()
        option_group = QGroupBox("Escolha uma opção:")
        option_layout.addWidget(self.option1)
        option_layout.addWidget(self.option2)
        option_layout.addWidget(self.option3)
        option_group.setLayout(option_layout)

        # Campos de entrada
        target_layout = QHBoxLayout()
        target_layout.addWidget(self.target_label)
        target_layout.addWidget(self.target_input)

        network_layout = QHBoxLayout()
        network_layout.addWidget(self.network_label)
        network_layout.addWidget(self.network_input)

        # Opções de portas
        ports_layout = QHBoxLayout()
        ports_group = QGroupBox("Portas para escanear:")
        ports_layout.addWidget(self.use_common_ports)
        ports_layout.addWidget(self.custom_ports)
        ports_layout.addWidget(self.ports_input)
        ports_group.setLayout(ports_layout)

        # Adicionar widgets ao layout principal
        main_layout.addWidget(option_group)
        main_layout.addLayout(target_layout)
        main_layout.addLayout(network_layout)
        main_layout.addWidget(ports_group)
        main_layout.addWidget(self.scan_button)
        main_layout.addWidget(self.result_area)

        self.setLayout(main_layout)

        # Conectar sinais e slots
        self.option1.toggled.connect(self.toggle_inputs)
        self.option2.toggled.connect(self.toggle_inputs)
        self.option3.toggled.connect(self.toggle_inputs)
        self.custom_ports.toggled.connect(self.toggle_ports_input)
        self.scan_button.clicked.connect(self.start_scan)

    def toggle_inputs(self):
        if self.option1.isChecked():
            self.target_input.setEnabled(True)
            self.network_input.setDisabled(True)
        elif self.option2.isChecked():
            self.target_input.setDisabled(True)
            self.network_input.setEnabled(True)
        elif self.option3.isChecked():
            self.target_input.setDisabled(True)
            self.network_input.setDisabled(True)

    def toggle_ports_input(self):
        if self.custom_ports.isChecked():
            self.ports_input.setEnabled(True)
        else:
            self.ports_input.setDisabled(True)

    def start_scan(self):
        if self.option1.isChecked():
            target = self.target_input.text()
            if not target:
                QMessageBox.warning(self, "Erro", "Por favor, insira um alvo (IP/DNS).")
                return

            if self.use_common_ports.isChecked():
                ports = None  # Será tratado no scanner
            else:
                ports_text = self.ports_input.text()
                if not ports_text:
                    QMessageBox.warning(self, "Erro", "Por favor, insira as portas.")
                    return
                ports = list(map(int, ports_text.split(',')))

            self.result_area.append(f"Iniciando escaneamento do alvo: {target}")
            scanner = PortScanner(target)
            results = scanner.scan_ports(ports)
            self.display_results(results, target)

        elif self.option2.isChecked():
            network = self.network_input.text()
            if not network:
                QMessageBox.warning(self, "Erro", "Por favor, insira uma rede.")
                return

            if self.use_common_ports.isChecked():
                ports = None
            else:
                ports_text = self.ports_input.text()
                if not ports_text:
                    QMessageBox.warning(self, "Erro", "Por favor, insira as portas.")
                    return
                ports = list(map(int, ports_text.split(',')))

            self.result_area.append(f"Iniciando escaneamento da rede: {network}")
            net_scanner = NetworkScanner(network)
            hosts = net_scanner.discover_hosts()
            for host in hosts:
                self.result_area.append(f"\nEscaneando host: {host}")
                scanner = PortScanner(host)
                results = scanner.scan_ports(ports)
                self.display_results(results, host)

        elif self.option3.isChecked():
            # Obter a rede local automaticamente
            network = self.get_local_network()
            self.result_area.append(f"Rede local detectada: {network}")

            if self.use_common_ports.isChecked():
                ports = None
            else:
                ports_text = self.ports_input.text()
                if not ports_text:
                    QMessageBox.warning(self, "Erro", "Por favor, insira as portas.")
                    return
                ports = list(map(int, ports_text.split(',')))

            net_scanner = NetworkScanner(network)
            hosts = net_scanner.discover_hosts()
            for host in hosts:
                self.result_area.append(f"\nEscaneando host: {host}")
                scanner = PortScanner(host)
                results = scanner.scan_ports(ports)
                self.display_results(results, host)

    def display_results(self, results, target):
        self.result_area.append(f"\nResultados para {target}:")
        for port, info in results.items():
            self.result_area.append(f"Porta {port}: {info}")

    def get_local_network(self):
        import socket
        import netifaces
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info['addr']
                    netmask = addr_info.get('netmask', '255.255.255.0')
                    network = f"{ip}/{netmask}"
                    return network
        return None

def main():
    app = QApplication(sys.argv)
    gui = GateHunterGUI()
    gui.show()
    sys.exit(app.exec_())
