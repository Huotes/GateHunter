import socket
from concurrent.futures import ThreadPoolExecutor
from common.common_ports import COMMON_PORTS

class PortScanner:
    def __init__(self, target, max_threads=100):
        self.target = target
        self.max_threads = max_threads

    def parse_http_banner(self, banner):
        """Filtra o banner HTTP para exibir informações importantes."""
        lines = banner.split("\r\n")
        filtered_info = {}
        for line in lines:
            if line.startswith("Server:") or line.startswith("X-Jenkins:") or line.startswith("X-"):
                key, value = line.split(":", 1)
                filtered_info[key.strip()] = value.strip()
        return filtered_info

    def scan_port(self, port):
        """Escaneia uma única porta e faz o banner grabbing, com tratamento de exceção na decodificação."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.target, port))
        if result == 0:
            try:
                service = COMMON_PORTS.get(port, 'Unknown')
                # Tenta pegar o banner de serviço
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    banner = sock.recv(1024).decode('utf-8').strip()  # Tenta decodificar como UTF-8
                except UnicodeDecodeError:
                    # Se falhar, tenta com latin-1 ou trata como dados binários
                    banner = sock.recv(1024).decode('latin-1').strip()

                if banner:
                    if port == 8080:  # Porta comum para HTTP ou proxy
                        filtered_banner = self.parse_http_banner(banner)
                        print(f"Porta {port} aberta ({service}) - Banner filtrado: {filtered_banner}")
                        return port, filtered_banner
                    else:
                        print(f"Porta {port} aberta ({service}) - Banner: {banner}")
                        return port, banner
                else:
                    print(f"Porta {port} aberta ({service})")
                    return port, service
            except socket.error:
                print(f"Porta {port} aberta ({service}) - Nenhum banner detectado")
                return port, service
        sock.close()
        return None

    def scan_ports(self, ports=None):
        """Escaneia as portas fornecidas usando multithreading e tenta fazer banner grabbing."""
        if ports is None:
            ports = COMMON_PORTS.keys()  # Usa as portas comuns se nenhuma for fornecida

        open_ports = {}
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = executor.map(self.scan_port, ports)
            for result in results:
                if result:
                    open_ports[result[0]] = result[1]

        return open_ports