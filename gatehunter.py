from modules.scanner import PortScanner
from modules.reporting import ReportGenerator
from modules.network_scanner import NetworkScanner
from common.common_ports import get_common_ports
import netifaces
import ipaddress
import os


def show_ascii_art():
    """Função para ler e exibir a arte ASCII a partir de um arquivo."""
    file_path = os.path.join(os.path.dirname(__file__), "ascii_art.txt")
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            ascii_art = file.read()
            print(ascii_art)
    except FileNotFoundError:
        print("Arquivo 'ascii_art.txt' não encontrado.")
    except Exception as e:
        print(f"Ocorreu um erro ao ler o arquivo 'ascii_art.txt': {e}")


def check_exit(input_value):
    """Verifica se o usuário quer sair."""
    if input_value.lower() in ["q", "sair"]:
        print("Encerrando o programa...")
        exit()


def get_local_network():
    """Descobre automaticamente a rede local utilizando o gateway e a máscara de sub-rede."""
    gateways = netifaces.gateways()
    default_gateway = gateways["default"][netifaces.AF_INET][1]
    addresses = netifaces.ifaddresses(default_gateway)
    ip_info = addresses[netifaces.AF_INET][0]
    ip_address = ip_info["addr"]
    netmask = ip_info["netmask"]
    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    return network


def scan_single_target(target, ports):
    """Escaneia portas em um único alvo e gera um relatório."""
    scanner = PortScanner(target)
    results = scanner.scan_ports(ports)

    # Geração de relatório
    report = ReportGenerator(results)
    report.generate_report(f"reports/report_{target}.json")


def scan_network(network, ports):
    """Descobre e escaneia todos os hosts ativos em uma rede."""
    print(f"Escaneando todos os hosts ativos na rede {network}...")
    network_scanner = NetworkScanner(str(network))
    active_hosts = network_scanner.discover_hosts()

    for host in active_hosts:
        print(f"Escaneando o host {host}...")
        scan_single_target(host, ports)


def main():
    """
    Função principal do GateHunter.

    Mostra o menu principal e permite ao usuário escolher entre três opções:
    1. Escanear um único IP ou DNS.
    2. Descobrir e escanear todos os hosts ativos em uma rede fornecida.
    3. Descobrir automaticamente a rede local e escanear todos os hosts ativos.

    O usuário pode digitar 'q' ou 'sair' para encerrar o programa a qualquer momento.
    """
    show_ascii_art()
    print("Gatehunter\n")

    while True:
        print("Escolha uma opção:")
        print("1. Escanear um único IP ou DNS")
        print("2. Descobrir e escanear todos os hosts ativos em uma rede")
        print("3. Descobrir automaticamente a rede local e escanear todos os hosts")
        print("Digite 'q' ou 'sair' para encerrar o programa.")

        choice = input("Digite sua escolha (1, 2 ou 3): ")
        check_exit(choice)

        if choice == "1":
            target = input("Digite o alvo (IP/DNS) ou 'q' para sair: ")
            check_exit(target)

            use_common_ports = input(
                "Deseja usar as portas comuns automaticamente? (s/n) ou 'q' para sair: "
            ).lower()
            check_exit(use_common_ports)

            if use_common_ports == "s":
                ports = get_common_ports()  # Usa as portas comuns
            else:
                ports_input = input(
                    "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'q' para sair: "
                )
                check_exit(ports_input)
                ports = list(map(int, ports_input.split(",")))

            scan_single_target(target, ports)

        elif choice == "2":
            network = input("Digite a rede (ex: 192.168.1.0/24) ou 'q' para sair: ")
            check_exit(network)

            use_common_ports = input(
                "Deseja usar as portas comuns automaticamente? (s/n) ou 'q' para sair: "
            ).lower()
            check_exit(use_common_ports)

            if use_common_ports == "s":
                ports = get_common_ports()
            else:
                ports_input = input(
                    "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'q' para sair: "
                )
                check_exit(ports_input)
                ports = list(map(int, ports_input.split(",")))

            scan_network(network, ports)

        elif choice == "3":
            print("Descobrindo automaticamente a rede local...")
            network = get_local_network()
            print(f"Rede detectada: {network}")

            use_common_ports = input(
                "Deseja usar as portas comuns automaticamente? (s/n) ou 'q' para sair: "
            ).lower()
            check_exit(use_common_ports)

            if use_common_ports == "s":
                ports = get_common_ports()
            else:
                ports_input = input(
                    "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'q' para sair: "
                )
                check_exit(ports_input)
                ports = list(map(int, ports_input.split(",")))

            scan_network(network, ports)

        else:
            print("Opção inválida. Por favor, escolha 1, 2 ou 3.")


if __name__ == "__main__":
    main()
