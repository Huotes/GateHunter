import sys
import os
import netifaces
import ipaddress

from modules.scanner import PortScanner
from modules.reporting import ReportGenerator
from modules.network_scanner import NetworkScanner
from common.common_ports import get_common_ports


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


def clear_console():
    """Limpa o console de acordo com o sistema operacional."""
    os.system("cls" if os.name == "nt" else "clear")


def check_exit(input_value):
    """Verifica se o usuário quer sair ou voltar."""
    if input_value.lower() in ["q", "sair"]:
        print("Encerrando o programa...")
        exit()
    elif input_value.lower() == "voltar":
        return "voltar"
    else:
        return None


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
    try:
        scanner = PortScanner(target)
        results = scanner.scan_ports(ports)
        # Geração de relatório
        report = ReportGenerator(results)
        report.generate_report(f"reports/report_{target}.json")

        # Exibir resultados no console
        print(f"\nResultados para {target}:")
        for port, info in results.items():
            print(f"Porta {port} aberta: {info}")
    except KeyboardInterrupt:
        print("\nEscaneamento cancelado pelo usuário.")


def scan_network(network, ports):
    """Descobre e escaneia todos os hosts ativos em uma rede."""
    try:
        print(f"Escaneando todos os hosts ativos na rede {network}...")
        network_scanner = NetworkScanner(str(network))
        active_hosts = network_scanner.discover_hosts()

        for host in active_hosts:
            print(f"\nEscaneando o host {host}...")
            scan_single_target(host, ports)
    except KeyboardInterrupt:
        print("\nProcesso cancelado pelo usuário.")


def main():
    """
    Função principal do GateHunter.
    """
    while True:
        clear_console()
        show_ascii_art()
        print("GateHunter\n")

        print("Escolha uma opção:")
        print("1. Escanear um único IP ou DNS")
        print("2. Descobrir e escanear todos os hosts ativos em uma rede")
        print("3. Descobrir automaticamente a rede local e escanear todos os hosts")
        print("Digite 'q' ou 'sair' para encerrar o programa.")

        choice = input("Digite sua escolha (1, 2 ou 3): ")
        action = check_exit(choice)
        if action == "voltar":
            continue

        if choice == "1":
            while True:
                target = input("Digite o alvo (IP/DNS) ou 'voltar' para retornar: ")
                action = check_exit(target)
                if action == "voltar":
                    break

                use_common_ports = input(
                    "Deseja usar as portas comuns automaticamente? (s/n) ou 'voltar' para retornar: "
                ).lower()
                action = check_exit(use_common_ports)
                if action == "voltar":
                    continue

                if use_common_ports == "s":
                    ports = get_common_ports()
                else:
                    ports_input = input(
                        "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'voltar' para retornar: "
                    )
                    action = check_exit(ports_input)
                    if action == "voltar":
                        continue
                    ports = list(map(int, ports_input.split(",")))

                print(f"\nIniciando escaneamento do alvo {target}...\n")
                scan_single_target(target, ports)
                input("\nPressione Enter para continuar...")
                break

        elif choice == "2":
            while True:
                network = input(
                    "Digite a rede (ex: 192.168.1.0/24) ou 'voltar' para retornar: "
                )
                action = check_exit(network)
                if action == "voltar":
                    break

                use_common_ports = input(
                    "Deseja usar as portas comuns automaticamente? (s/n) ou 'voltar' para retornar: "
                ).lower()
                action = check_exit(use_common_ports)
                if action == "voltar":
                    continue

                if use_common_ports == "s":
                    ports = get_common_ports()
                else:
                    ports_input = input(
                        "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'voltar' para retornar: "
                    )
                    action = check_exit(ports_input)
                    if action == "voltar":
                        continue
                    ports = list(map(int, ports_input.split(",")))

                print(f"\nIniciando escaneamento da rede {network}...\n")
                scan_network(network, ports)
                input("\nPressione Enter para continuar...")
                break

        elif choice == "3":
            print("Descobrindo automaticamente a rede local...")
            network = get_local_network()
            print(f"Rede detectada: {network}")

            use_common_ports = input(
                "Deseja usar as portas comuns automaticamente? (s/n) ou 'voltar' para retornar: "
            ).lower()
            action = check_exit(use_common_ports)
            if action == "voltar":
                continue

            if use_common_ports == "s":
                ports = get_common_ports()
            else:
                ports_input = input(
                    "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'voltar' para retornar: "
                )
                action = check_exit(ports_input)
                if action == "voltar":
                    continue
                ports = list(map(int, ports_input.split(",")))

            print(f"\nIniciando escaneamento da rede {network}...\n")
            scan_network(network, ports)
            input("\nPressione Enter para continuar...")

        else:
            print("Opção inválida. Por favor, escolha 1, 2 ou 3.")


if __name__ == "__main__":
    main()
