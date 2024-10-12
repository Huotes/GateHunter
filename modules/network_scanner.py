from scapy.all import sr1, IP, ICMP
import ipaddress


class NetworkScanner:
    def __init__(self, network):
        """Inicializa o scanner com a rede fornecida."""
        self.network = network

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

    def ping_host(self, ip):
        """Envia um pacote ICMP (ping) para verificar se o host está ativo."""
        icmp_packet = IP(dst=ip) / ICMP()
        response = sr1(icmp_packet, timeout=1, verbose=0)

        if response is None:
            return False
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            if icmp_type == 0:
                return True
        return False
