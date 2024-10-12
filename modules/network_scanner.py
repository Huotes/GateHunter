import logging
import netifaces
import ipaddress

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1

# Ajusta o nível de log do Scapy para suprimir avisos
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_default_interface():
    """Obtém a interface de rede padrão."""
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default', {})
    if netifaces.AF_INET in default_gateway:
        return default_gateway[netifaces.AF_INET][1]
    else:
        return None

class NetworkScanner:
    """Classe para escanear a rede e descobrir hosts ativos."""
    
    def __init__(self, network, iface=None):
        """Inicializa o scanner com a rede fornecida."""
        self.network = network
        self.iface = iface or get_default_interface()

    def resolve_mac(self, ip):
        """Resolve o endereço MAC do IP fornecido usando ARP."""
        arp_request = ARP(pdst=ip)
        arp_response = sr1(arp_request, timeout=1, verbose=0, iface=self.iface)
        if arp_response:
            return arp_response.hwsrc
        else:
            return None

    def ping_host(self, ip):
        """Envia um pacote ICMP (ping) para verificar se o host está ativo."""
        # Pré-resolve o endereço MAC para evitar avisos
        mac = self.resolve_mac(ip)
        if mac is None:
            # Não conseguiu resolver o MAC, host provavelmente inativo
            return False
        icmp_packet = IP(dst=ip) / ICMP()
        response = sr1(icmp_packet, timeout=1, verbose=0)
        if response is None:
            return False
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            if icmp_type == 0:
                return True
        return False

    def discover_hosts(self):
        """Descobre todos os hosts ativos na rede."""
        active_hosts = []
        network = ipaddress.ip_network(self.network, strict=False)

        try:
            for ip in network.hosts():
                if self.ping_host(str(ip)):
                    active_hosts.append(str(ip))
                    print(f"Host ativo encontrado: {ip}")
        except KeyboardInterrupt:
            print("\nDescoberta de hosts cancelada pelo usuário.")
        return active_hosts
