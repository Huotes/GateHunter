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
            if line.startswith("Server:"):
                key, value = line.split(":", 1)
                filtered_info[key.strip()] = value.strip()
        return filtered_info

    def extract_mysql_version(self, data):
        """Extrai a versão do servidor MySQL a partir do pacote de handshake."""
        try:
            payload = data[4:]
            nul_index = payload.find(b"\x00", 1)
            if nul_index == -1:
                return "Desconhecida"
            server_version = payload[1:nul_index].decode("ascii", errors="replace")
            return server_version
        except Exception:
            return "Desconhecida"

    def extract_postgresql_version(self):
        """Extrai a versão do PostgreSQL usando o cliente psycopg2."""
        try:
            import psycopg2

            conn = psycopg2.connect(
                host=self.target,
                port=5432,
                user="postgres",
                password="",
                connect_timeout=2,
            )
            cur = conn.cursor()
            cur.execute("SELECT version();")
            version_info = cur.fetchone()
            conn.close()
            if version_info:
                version = version_info[0]
                version_number = version.split(" ")[1]  # Extrai o número da versão
                return version_number
            else:
                return "Desconhecida"
        except Exception as e:
            print(f"Erro ao extrair versão do PostgreSQL: {e}")
            return "Desconhecida"

    def extract_mongodb_version(self):
        """Extrai a versão do MongoDB usando o cliente pymongo."""
        try:
            from pymongo import MongoClient

            client = MongoClient(self.target, port=27017, serverSelectionTimeoutMS=2000)
            server_info = client.server_info()
            version = server_info.get("version", "Desconhecida")
            client.close()
            return version
        except Exception as e:
            print(f"Erro ao extrair versão do MongoDB: {e}")
            return "Desconhecida"

    def scan_port(self, port):
        """Escaneia uma única porta e faz o banner grabbing."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")

                # Tratamento específico para serviços conhecidos
                if port in [80, 8080]:
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = (
                            sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        )
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

                elif port == 5432:
                    version_info = self.extract_postgresql_version()
                    return port, f"PostgreSQL {version_info}"

                elif port == 27017:
                    version_info = self.extract_mongodb_version()
                    return port, f"MongoDB {version_info}"

                elif port == 6379:
                    try:
                        sock.send(b"INFO\r\n")
                        banner = sock.recv(1024).decode("utf-8", errors="ignore")
                        version_line = [
                            line
                            for line in banner.split("\n")
                            if "redis_version" in line
                        ]
                        if version_line:
                            version = version_line[0].split(":")[1].strip()
                            return port, f"Redis {version}"
                        else:
                            return port, "Redis"
                    except:
                        return port, "Redis"

                else:
                    # Tentar banner grabbing genérico
                    try:
                        sock.send(b"\r\n")
                        banner = (
                            sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        )
                        if banner:
                            return port, f"{service} ({banner})"
                        else:
                            return port, service
                    except:
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
        return open_ports
