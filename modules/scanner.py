import logging
import nmap
import os
import sys

from common.common_ports import COMMON_PORTS
from plugins.vulnerability_scanner import VulnerabilityScanner

class PortScanner:
    def __init__(self, target, arguments='-sV -sC'):
        self.target = target
        self.scanner = nmap.PortScanner()
        self.arguments = arguments  # Parâmetros do Nmap
        api_key = os.environ.get('NVD_API_KEY')
        if not api_key:
            logging.error("Chave de API da NVD não definida. Defina a variável de ambiente NVD_API_KEY.")
            sys.exit(1)
        self.vuln_scanner = VulnerabilityScanner(api_key=api_key)

    def scan_ports(self, ports=None):
        """Escaneia as portas fornecidas usando o Nmap."""
        if ports is None:
            port_range = '1-65535'
        else:
            port_range = ','.join(map(str, ports))

        try:
            self.scanner.scan(self.target, port_range, arguments=self.arguments)
            scan_data = self.scanner[self.target]
            open_ports = {}

            for proto in scan_data.all_protocols():
                lport = scan_data[proto].keys()
                for port in lport:
                    service = scan_data[proto][port]
                    port_info = {
                        'protocol': proto,
                        'state': service['state'],
                        'name': service['name'],
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', ''),
                        'conf': service.get('conf', ''),
                        'cpe': service.get('cpe', ''),
                        'vulnerabilities': []
                    }

                    # Log do CPE extraído
                    logging.debug(f"CPE para a porta {port}: {port_info['cpe']}")

                    # Se houver CPE, buscar vulnerabilidades
                    if port_info['cpe']:
                        cpe_list = port_info['cpe']
                        if isinstance(cpe_list, str):
                            cpe_list = [cpe_list]
                        vulnerabilities = self.vuln_scanner.search_vulnerabilities(cpe_list)
                        port_info['vulnerabilities'] = vulnerabilities
                    else:
                        # Se não houver CPE, tentar busca alternativa com produto e versão
                        logging.warning(f"CPE não encontrado para a porta {port}. Tentando busca alternativa.")
                        product = port_info['product'] or port_info['name']
                        version = port_info['version']
                        if product:
                            logging.info(f"Tentando busca alternativa para produto: {product} versão {version}")
                            vulnerabilities = self.vuln_scanner.search_vulnerabilities([], product=product, version=version)
                            port_info['vulnerabilities'] = vulnerabilities
                        else:
                            logging.warning(f"Não foi possível identificar o produto para a porta {port}.")

                    open_ports[port] = port_info

            return open_ports

        except nmap.PortScannerError as e:
            logging.error(f"Erro ao escanear portas com Nmap: {e}")
            return {}
        except Exception as e:
            logging.error(f"Erro inesperado ao escanear portas: {e}")
            return {}
