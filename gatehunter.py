import sys
import os
import netifaces
import ipaddress
import locale
import gettext

from modules.scanner import PortScanner
from modules.reporting import ReportGenerator
from modules.network_scanner import NetworkScanner
from common.common_ports import get_common_ports

def get_system_locale():
    """Obtém o idioma padrão do sistema."""
    lang, _ = locale.getdefaultlocale()
    if lang is None:
        lang = 'en_US'  # Padrão para inglês se não conseguir detectar
    return lang

def choose_language():
    """Permite que o usuário escolha o idioma."""
    system_lang = get_system_locale()
    print("Selecione o idioma / Select language / Seleccione el idioma:")
    print("1. Português")
    print("2. English")
    print("3. Español")
    choice = input("Digite o número correspondente ao idioma / Enter the number corresponding to the language: ")

    if choice == '1':
        lang = 'pt_BR'
    elif choice == '2':
        lang = 'en_US'
    elif choice == '3':
        lang = 'es_ES'
    else:
        print("Opção inválida. Usando o idioma do sistema.")
        lang = system_lang
    return lang

def setup_translation(lang):
    """Configura a tradução para o idioma selecionado."""
    try:
        t = gettext.translation('gatehunter', localedir='locales', languages=[lang])
        t.install()
    except FileNotFoundError:
        # Se não encontrar o arquivo de tradução, usa o idioma padrão (inglês)
        gettext.install('gatehunter', localedir='locales')

def show_ascii_art():
    """Função para ler e exibir a arte ASCII a partir de um arquivo."""
    file_path = os.path.join(os.path.dirname(__file__), "ascii_art.txt")
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            ascii_art = file.read()
            print(ascii_art)
    except FileNotFoundError:
        print(_("Arquivo 'ascii_art.txt' não encontrado."))
    except Exception as e:
        print(_("Ocorreu um erro ao ler o arquivo 'ascii_art.txt': {error}").format(error=e))

def clear_console():
    """Limpa o console de acordo com o sistema operacional."""
    os.system('cls' if os.name == 'nt' else 'clear')

def check_exit(input_value):
    """Verifica se o usuário quer sair ou voltar."""
    if input_value.lower() in ["q", "sair", "quit", "exit"]:
        print(_("Encerrando o programa..."))
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
        print(_("\nResultados para {target}:").format(target=target))
        for port, info in results.items():
            print(_("Porta {port} aberta: {info}").format(port=port, info=info))
    except KeyboardInterrupt:
        print(_("\nEscaneamento cancelado pelo usuário."))

def scan_network(network, ports):
    """Descobre e escaneia todos os hosts ativos em uma rede."""
    try:
        print(_("Escaneando todos os hosts ativos na rede {network}...").format(network=network))
        network_scanner = NetworkScanner(str(network))
        active_hosts = network_scanner.discover_hosts()

        for host in active_hosts:
            print(_("\nEscaneando o host {host}...").format(host=host))
            scan_single_target(host, ports)
    except KeyboardInterrupt:
        print(_("\nProcesso cancelado pelo usuário."))

def main():
    """
    Função principal do GateHunter.
    """
    # Configurar o idioma
    lang = choose_language()
    setup_translation(lang)

    while True:
        clear_console()
        show_ascii_art()
        print(_("GateHunter\n"))

        print(_("Escolha uma opção:"))
        print("1. " + _("Escanear um único IP ou DNS"))
        print("2. " + _("Descobrir e escanear todos os hosts ativos em uma rede"))
        print("3. " + _("Descobrir automaticamente a rede local e escanear todos os hosts"))
        print(_("Digite 'q' ou 'sair' para encerrar o programa."))

        choice = input(_("Digite sua escolha (1, 2 ou 3): "))
        action = check_exit(choice)
        if action == "voltar":
            continue

        if choice == "1":
            while True:
                target = input(_("Digite o alvo (IP/DNS) ou 'voltar' para retornar: "))
                action = check_exit(target)
                if action == "voltar":
                    break

                use_common_ports = input(
                    _("Deseja usar as portas comuns automaticamente? (s/n) ou 'voltar' para retornar: ")
                ).lower()
                action = check_exit(use_common_ports)
                if action == "voltar":
                    continue

                if use_common_ports == "s":
                    ports = get_common_ports()
                else:
                    ports_input = input(
                        _("Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'voltar' para retornar: ")
                    )
                    action = check_exit(ports_input)
                    if action == "voltar":
                        continue
                    ports = list(map(int, ports_input.split(",")))

                print(_("\nIniciando escaneamento do alvo {target}...\n").format(target=target))
                scan_single_target(target, ports)
                input(_("\nPressione Enter para continuar..."))
                break

        elif choice == "2":
            while True:
                network = input(_("Digite a rede (ex: 192.168.1.0/24) ou 'voltar' para retornar: "))
                action = check_exit(network)
                if action == "voltar":
                    break

                use_common_ports = input(
                    _("Deseja usar as portas comuns automaticamente? (s/n) ou 'voltar' para retornar: ")
                ).lower()
                action = check_exit(use_common_ports)
                if action == "voltar":
                    continue

                if use_common_ports == "s":
                    ports = get_common_ports()
                else:
                    ports_input = input(
                        _("Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'voltar' para retornar: ")
                    )
                    action = check_exit(ports_input)
                    if action == "voltar":
                        continue
                    ports = list(map(int, ports_input.split(",")))

                print(_("\nIniciando escaneamento da rede {network}...\n").format(network=network))
                scan_network(network, ports)
                input(_("\nPressione Enter para continuar..."))
                break

        elif choice == "3":
            print(_("Descobrindo automaticamente a rede local..."))
            network = get_local_network()
            print(_("Rede detectada: {network}").format(network=network))

            use_common_ports = input(
                _("Deseja usar as portas comuns automaticamente? (s/n) ou 'voltar' para retornar: ")
            ).lower()
            action = check_exit(use_common_ports)
            if action == "voltar":
                continue

            if use_common_ports == "s":
                ports = get_common_ports()
            else:
                ports_input = input(
                    _("Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) ou 'voltar' para retornar: ")
                )
                action = check_exit(ports_input)
                if action == "voltar":
                    continue
                ports = list(map(int, ports_input.split(",")))

            print(_("\nIniciando escaneamento da rede {network}...\n").format(network=network))
            scan_network(network, ports)
            input(_("\nPressione Enter para continuar..."))

        else:
            print(_("Opção inválida. Por favor, escolha 1, 2 ou 3."))

if __name__ == "__main__":
    main()
