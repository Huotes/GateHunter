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
            if (
                line.startswith("Server:")
                or line.startswith("X-Jenkins:")
                or line.startswith("X-")
            ):
                key, value = line.split(":", 1)
                filtered_info[key.strip()] = value.strip()
        return filtered_info

    def extract_mysql_version(self, data):
        """Extrai a versão do servidor MySQL a partir do pacote de handshake."""
        try:
            # Ignora os primeiros 4 bytes (cabeçalho do pacote)
            payload = data[4:]

            # O primeiro byte do payload é a versão do protocolo
            protocol_version = payload[0]
            # A versão do servidor é uma string terminada em NUL que começa no byte 1 do payload
            nul_index = payload.find(b"\x00", 1)
            if nul_index == -1:
                return "Desconhecida"

            server_version = payload[1:nul_index].decode("ascii", errors="replace")
            return server_version
        except Exception as e:
            return "Desconhecida"

    def scan_port(self, port):
        """Escaneia uma única porta e faz o banner grabbing, com tratamento especial para alguns serviços."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")

                # Tentativa de banner grabbing específica para serviços conhecidos
                if port in [80, 8080]:
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode("utf-8").strip()
                        filtered_banner = self.parse_http_banner(banner)
                        server_info = filtered_banner.get("Server", "Desconhecido")
                        return port, f"HTTP ({server_info})"
                    except:
                        return port, "HTTP"

                elif port == 3306:
                    try:
                        banner = sock.recv(1024)
                        if banner:
                            server_version = self.extract_mysql_version(banner)
                            return port, f"MySQL {server_version}"
                        else:
                            return port, "MySQL"
                    except:
                        return port, "MySQL"

                elif port == 6379:
                    try:
                        sock.send(b"PING\r\n")
                        banner = sock.recv(1024).decode("utf-8").strip()
                        return port, f"Redis ({banner})"
                    except:
                        return port, "Redis"

                elif port == 5432:
                    return port, "PostgreSQL"

                elif port == 27017:
                    return port, "MongoDB"

                else:
                    return port, service
            else:
                return None
        except socket.error:
            return None
        finally:
            sock.close()

    def scan_ports(self, ports=None):
        """Escaneia as portas fornecidas usando multithreading e tenta fazer banner grabbing."""
        if ports is None:
            ports = COMMON_PORTS.keys()

        open_ports = {}
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                results = executor.map(self.scan_port, ports)
                for result in results:
                    if result:
                        open_ports[result[0]] = result[1]
        except KeyboardInterrupt:
            print("\nEscaneamento de portas cancelado pelo usuário.")
            executor.shutdown(wait=False)
        return open_ports
