from scapy.all import sr1, IP, ICMP, ICMPv6DestUnreach
import ipaddress

class NetworkScanner:
    def __init__(self, network):
        """Inicializa o scanner com a rede fornecida."""
        self.network = network

    def discover_hosts(self):
        """Descobre todos os hosts ativos na rede."""
        active_hosts = []
        network = ipaddress.ip_network(self.network, strict=False)

        for ip in network.hosts():
            if self.ping_host(str(ip)):
                active_hosts.append(str(ip))
                print(f"Host ativo encontrado: {ip}")
        return active_hosts

    def ping_host(self, ip):
        """Envia um pacote ICMP (ping) para verificar se o host está ativo."""
        icmp_packet = IP(dst=ip) / ICMP()
        response = sr1(icmp_packet, timeout=2, verbose=0)

        if response is None:
            return False  # Sem resposta, host inativo ou filtrado
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            if icmp_type == 0:  # Tipo 0 é "Echo Reply", ou seja, ping bem-sucedido
                return True
            elif icmp_type in [3, 11]:  # ICMP Destination unreachable ou TTL exceeded
                print(f"Host {ip} respondeu, mas está inacessível (ICMP Type {icmp_type})")
                return False
        return False
