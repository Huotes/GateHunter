# Dicionário de portas conhecidas e seus serviços
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP-Proxy'
}

def get_common_ports():
    """Retorna uma lista das portas comuns que podem ser escaneadas."""
    return list(COMMON_PORTS.keys())
