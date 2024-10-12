# Dicionário de portas conhecidas e seus serviços
COMMON_PORTS = {
    21: 'FTP',                # File Transfer Protocol
    22: 'SSH',                # Secure Shell
    23: 'Telnet',             # Telnet protocol (inseguro)
    25: 'SMTP',               # Simple Mail Transfer Protocol
    53: 'DNS',                # Domain Name System
    80: 'HTTP',               # HyperText Transfer Protocol
    110: 'POP3',              # Post Office Protocol (v3)
    135: 'Microsoft RPC',     # Microsoft Remote Procedure Call
    139: 'NetBIOS',           # NetBIOS Session Service
    143: 'IMAP',              # Internet Message Access Protocol
    161: 'SNMP',              # Simple Network Management Protocol
    389: 'LDAP',              # Lightweight Directory Access Protocol
    443: 'HTTPS',             # HyperText Transfer Protocol Secure
    445: 'SMB',               # Server Message Block (Windows File Sharing)
    465: 'SMTPS',             # Secure SMTP
    587: 'SMTP-MSA',          # Mail Submission Agent
    993: 'IMAPS',             # IMAP over SSL
    995: 'POP3S',             # POP3 over SSL
    1025: 'Microsoft RPC',    # Microsoft Remote Procedure Call
    1080: 'SOCKS Proxy',      # SOCKS Proxy
    1433: 'MSSQL',            # Microsoft SQL Server
    1434: 'MSSQL Monitor',    # Microsoft SQL Server Monitor
    1521: 'Oracle DB',        # Oracle Database
    1723: 'PPTP',             # Point-to-Point Tunneling Protocol
    1883: 'MQTT',             # Message Queuing Telemetry Transport
    2049: 'NFS',              # Network File System
    2375: 'Docker (No TLS)',  # Docker Daemon (sem TLS)
    2376: 'Docker (TLS)',     # Docker Daemon (com TLS)
    2483: 'Oracle DB Listener',# Oracle DB Listener (TCP)
    2484: 'Oracle DB Listener',# Oracle DB Listener (SSL)
    3306: 'MySQL',            # MySQL Database
    3389: 'RDP',              # Remote Desktop Protocol (Windows)
    5432: 'PostgreSQL',       # PostgreSQL Database
    5900: 'VNC',              # Virtual Network Computing
    5984: 'CouchDB',          # CouchDB
    6379: 'Redis',            # Redis Database
    7001: 'WebLogic',         # WebLogic Server
    8080: 'HTTP-Proxy',       # HTTP Proxy/Alternative HTTP Port
    8086: 'InfluxDB',         # InfluxDB
    8443: 'HTTPS-Alt',        # Alternative HTTPS Port
    8888: 'HTTP',             # Alternative HTTP Port
    9200: 'Elasticsearch',    # Elasticsearch
    11211: 'Memcached',       # Memcached
    27017: 'MongoDB',         # MongoDB Database
    27018: 'MongoDB',         # MongoDB (sharded clusters)
    27019: 'MongoDB',         # MongoDB (config servers)
    50000: 'SAP',             # SAP (Systems, Applications, and Products in Data Processing)
    50070: 'Hadoop',          # Hadoop NameNode
    50090: 'Hadoop',          # Hadoop Secondary NameNode
}

def get_common_ports():
    """Retorna uma lista das portas comuns que podem ser escaneadas."""
    return list(COMMON_PORTS.keys())
