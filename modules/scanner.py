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

    def sanitize_mysql_banner(self, banner):
        """Tenta limpar o banner do MySQL, removendo dados binários irrelevantes."""
        try:
            # Verifica se o banner tem conteúdo antes de sanitizar
            if not banner:
                return "MySQL - Nenhuma resposta detectada"

            # Extrair informações úteis, como versão e tipo de autenticação
            lines = banner.split("\n")
            clean_lines = [
                line for line in lines if line.isprintable() and len(line) > 0
            ]

            if clean_lines:
                return "\n".join(clean_lines).strip()
            else:
                return "MySQL - Nenhuma informação útil no banner"
        except Exception as e:
            print(f"Erro ao sanitizar banner MySQL: {e}")
            return "MySQL - Erro ao processar banner"

    def extract_mysql_version(self, data):
        """Extrai a versão do servidor MySQL a partir do pacote de handshake."""
        try:
            # O primeiro byte é a versão do protocolo (1 byte)
            protocol_version = data[0]
            # A versão do servidor é uma string NUL-terminada que começa no byte 1
            # Vamos encontrar o índice do byte NUL após o byte 1
            nul_index = data.find(b"\x00", 1)
            if nul_index == -1:
                return "Desconhecida"
            server_version = data[1:nul_index].decode("ascii", errors="replace")
            return server_version
        except Exception as e:
            print(f"Erro ao extrair versão do MySQL: {e}")
            return "Desconhecida"

    def scan_port(self, port):
        """Escaneia uma única porta e faz o banner grabbing, com tratamento especial para alguns serviços."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Aumenta o tempo limite para capturar serviços mais lentos
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")

                # Tentativa de banner grabbing específica para serviços conhecidos
                if port in [80, 8080]:  # Para portas HTTP/Proxy
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode("utf-8").strip()
                        filtered_banner = self.parse_http_banner(banner)
                        print(
                            f"Porta {port} aberta ({service}) - Banner filtrado: {filtered_banner}"
                        )
                        return port, filtered_banner
                    except (socket.timeout, socket.error) as e:
                        print(f"Erro ao capturar banner na porta {port}: {e}")
                        return port, service

                elif port == 3306:  # MySQL
                    try:
                        banner = sock.recv(1024)
                        # Agora, parse o pacote de handshake para obter a versão do servidor
                        if banner:
                            server_version = self.extract_mysql_version(banner)
                            print(
                                f"Porta {port} aberta (MySQL) - Versão do servidor: {server_version}"
                            )
                            return port, f"MySQL {server_version}"
                        else:
                            print(f"Porta {port} aberta (MySQL) - Nenhuma resposta")
                            return port, "MySQL - Nenhuma resposta do serviço"
                    except Exception as e:
                        print(f"Erro ao capturar banner MySQL: {e}")
                        return port, "MySQL - Erro ao capturar banner"

                elif port == 6379:  # Redis
                    try:
                        sock.send(b"PING\r\n")
                        banner = sock.recv(1024).decode("utf-8").strip()
                        print(f"Porta {port} aberta (Redis) - Banner: {banner}")
                        return port, banner
                    except Exception as e:
                        print(f"Erro ao capturar banner Redis: {e}")
                        return port, "Redis - Erro ao capturar banner"

                elif port == 5432:  # PostgreSQL
                    print(f"Porta {port} aberta (PostgreSQL)")
                    return port, "PostgreSQL"

                elif port == 27017:  # MongoDB
                    print(f"Porta {port} aberta (MongoDB)")
                    return port, "MongoDB"

                else:
                    print(f"Porta {port} aberta ({service})")
                    return port, service
            else:
                print(f"Porta {port} fechada ou filtrada.")
                return None
        except socket.error as e:
            print(f"Erro ao conectar à porta {port}: {e}")
            return None
        finally:
            sock.close()  # Garantir que o socket seja fechado em todos os casos

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
