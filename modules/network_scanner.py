import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ICMP, IP, sr1

# Ajusta o nível de log do Scapy para suprimir avisos
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


class NetworkScanner:
    """Classe para escanear a rede e descobrir hosts ativos."""

    def __init__(self, network, timeout=1):
        """Inicializa o scanner com a rede fornecida."""
        self.network = network
        self.timeout = timeout

    def ping_host(self, ip):
        """Envia um pacote ICMP (ping) para verificar se o host está ativo."""
        try:
            icmp_packet = IP(dst=ip) / ICMP()
            response = sr1(icmp_packet, timeout=self.timeout, verbose=0)
            if response is not None and response.haslayer(ICMP):
                return True
            return False
        except PermissionError as e:
            logging.error(f"Permissão negada ao tentar pingar {ip}: {e}")
            return False
        except Exception as e:
            logging.error(f"Erro ao pingar {ip}: {e}")
            return False

    def discover_hosts(self):
        """Descobre todos os hosts ativos na rede."""
        active_hosts = []
        try:
            network = ipaddress.ip_network(self.network, strict=False)
            ips = [str(ip) for ip in network.hosts()]

            with ThreadPoolExecutor(max_workers=100) as executor:
                results = executor.map(self.ping_host, ips)
                for ip, is_active in zip(ips, results):
                    if is_active:
                        active_hosts.append(ip)
                        logging.info(f"Host ativo encontrado: {ip}")

            return active_hosts
        except ValueError as e:
            logging.error(f"Rede inválida: {e}")
            return []
        except Exception as e:
            logging.error(f"Erro ao descobrir hosts na rede {self.network}: {e}")
            return []
