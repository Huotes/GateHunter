import ipaddress
import locale
import logging
import netifaces
import os
import sys
import gettext

from common.common_ports import get_common_ports
from modules.network_scanner import NetworkScanner
from modules.reporting import ReportGenerator
from modules.scanner import PortScanner

# Configuração do logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class GateHunter:
    def __init__(self):
        self.lang = self.choose_language()
        self.setup_translation(self.lang)
        # Definir comandos globais de controle após a tradução
        self.BACK_COMMAND = _("voltar").lower()
        self.EXIT_COMMANDS = [
            _("q").lower(),
            _("sair").lower(),
            _("quit").lower(),
            _("exit").lower(),
        ]
        self.YES_OPTION = _("s").lower()
        self.NO_OPTION = _("n").lower()

    def get_system_locale(self):
        """Obtém o idioma padrão do sistema."""
        lang = None
        for variable in ("LC_ALL", "LC_CTYPE", "LANG", "LANGUAGE"):
            lang = os.environ.get(variable)
            if lang:
                lang = lang.split(".")[0]
                break
        if lang is None:
            lang = "en_US"  # Padrão para inglês se não conseguir detectar
        return lang

    def choose_language(self):
        """Permite que o usuário escolha o idioma."""
        system_lang = self.get_system_locale()
        logging.info("Selecione o idioma / Select language / Seleccione el idioma:")
        logging.info("1. Português")
        logging.info("2. English")
        logging.info("3. Español")
        choice = input(
            "Digite o número correspondente ao idioma / "
            "Enter the number corresponding to the language: "
        )

        if choice == "1":
            lang = "pt_BR"
        elif choice == "2":
            lang = "en_US"
        elif choice == "3":
            lang = "es_ES"
        else:
            logging.warning("Opção inválida. Usando o idioma do sistema.")
            lang = system_lang
        return lang

    def setup_translation(self, lang):
        """Configura a tradução para o idioma selecionado."""
        try:
            t = gettext.translation("gatehunter", localedir="locales", languages=[lang])
            t.install()
        except FileNotFoundError:
            # Se não encontrar o arquivo de tradução, usa o idioma padrão (inglês)
            gettext.install("gatehunter", localedir="locales")

    def show_ascii_art(self):
        """Função para ler e exibir a arte ASCII a partir de um arquivo."""
        file_path = os.path.join(os.path.dirname(__file__), "ascii_art.txt")
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                ascii_art = file.read()
                print(ascii_art)
        except FileNotFoundError:
            logging.error(_("Arquivo 'ascii_art.txt' não encontrado."))
        except Exception as e:
            logging.error(
                _("Ocorreu um erro ao ler o arquivo 'ascii_art.txt': {error}").format(
                    error=e
                )
            )

    def clear_console(self):
        """Limpa o console de acordo com o sistema operacional."""
        os.system("cls" if os.name == "nt" else "clear")

    def check_exit(self, input_value):
        """Verifica se o usuário quer sair ou voltar."""
        input_value = input_value.lower()
        if input_value in self.EXIT_COMMANDS:
            logging.info(_("Encerrando o programa..."))
            sys.exit()
        elif input_value == self.BACK_COMMAND:
            return "voltar"
        else:
            return None

    def get_local_network(self):
        """Descobre automaticamente a rede local utilizando o gateway e a máscara."""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get("default", {}).get(
                netifaces.AF_INET, [None]
            )[1]
            if not default_gateway:
                logging.error(_("Não foi possível determinar o gateway padrão."))
                return None
            addresses = netifaces.ifaddresses(default_gateway)
            ip_info = addresses.get(netifaces.AF_INET, [{}])[0]
            ip_address = ip_info.get("addr", None)
            netmask = ip_info.get("netmask", None)
            if not ip_address or not netmask:
                logging.error(
                    _("Não foi possível obter o endereço IP ou a máscara de rede.")
                )
                return None
            network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
            return network
        except Exception as e:
            logging.error(_("Erro ao obter a rede local: {error}").format(error=e))
            return None

    def scan_single_target(self, target, ports, scan_type="tcp"):
        """Escaneia portas em um único alvo e gera um relatório."""
        try:
            arguments = "-sV -sC"
            if scan_type == "udp":
                arguments += " -sU"
            elif scan_type == "tcp_udp":
                arguments += " -sT -sU"

            scanner = PortScanner(target, arguments=arguments)
            results = scanner.scan_ports(ports)
            # Geração de relatório
            report = ReportGenerator(results)
            report.generate_report(f"reports/report_{target}.json")

            # Exibir resultados no console
            logging.info(_("\nResultados para {target}:").format(target=target))
            for port, info in results.items():
                logging.info(
                    _("Porta {port}/{protocol} aberta: {service} {version}").format(
                        port=port,
                        protocol=info.get("protocol", "tcp"),
                        service=info.get("name", "unknown"),
                        version=info.get("version", ""),
                    )
                )
                # Exibir vulnerabilidades encontradas
                vulnerabilities = info.get("vulnerabilities", [])
                if vulnerabilities:
                    logging.warning(
                        _("Vulnerabilidades encontradas para a porta {port}:").format(
                            port=port
                        )
                    )
                    for vuln in vulnerabilities:
                        logging.warning(f"- {vuln['id']}: {vuln['description']}")
                else:
                    logging.info(
                        _(
                            "Nenhuma vulnerabilidade conhecida encontrada para a porta {port}."
                        ).format(port=port)
                    )

        except KeyboardInterrupt:
            logging.warning(_("\nEscaneamento cancelado pelo usuário."))
        except Exception as e:
            logging.error(
                _("Erro ao escanear o alvo {target}: {error}").format(
                    target=target, error=e
                )
            )

    def scan_network(self, network, ports, scan_type="tcp"):
        """Descobre e escaneia todos os hosts ativos em uma rede."""
        try:
            logging.info(
                _("Escaneando todos os hosts ativos na rede {network}...").format(
                    network=network
                )
            )
            network_scanner = NetworkScanner(str(network))
            active_hosts = network_scanner.discover_hosts()

            for host in active_hosts:
                logging.info(_("\nEscaneando o host {host}...").format(host=host))
                self.scan_single_target(host, ports, scan_type)
        except KeyboardInterrupt:
            logging.warning(_("\nProcesso cancelado pelo usuário."))
        except Exception as e:
            logging.error(
                _("Erro ao escanear a rede {network}: {error}").format(
                    network=network, error=e
                )
            )

    def main_menu(self):
        """
        Função principal do GateHunter.
        """
        while True:
            self.clear_console()
            self.show_ascii_art()
            logging.info(_("GateHunter\n"))

            logging.info(_("Escolha uma opção:"))
            logging.info("1. " + _("Escanear um único IP ou DNS"))
            logging.info(
                "2. " + _("Descobrir e escanear todos os hosts ativos em uma rede")
            )
            logging.info(
                "3. "
                + _("Descobrir automaticamente a rede local e escanear todos os hosts")
            )
            logging.info(_("Digite 'q' ou 'sair' para encerrar o programa."))

            choice = input(_("Digite sua escolha (1, 2 ou 3): "))
            action = self.check_exit(choice)
            if action == "voltar":
                continue

            if choice == "1":
                self.option_single_target()
            elif choice == "2":
                self.option_scan_network()
            elif choice == "3":
                self.option_scan_local_network()
            else:
                logging.warning(_("Opção inválida. Por favor, escolha 1, 2 ou 3."))

    def option_single_target(self):
        """Opção para escanear um único alvo."""
        while True:
            target = input(
                _("Digite o alvo (IP/DNS) ou '{back}' para retornar: ").format(
                    back=self.BACK_COMMAND
                )
            )
            action = self.check_exit(target)
            if action == "voltar":
                break

            use_common_ports = input(
                _(
                    "Deseja usar as portas comuns automaticamente? ({yes}/{no}) ou '{back}' para retornar: "
                ).format(
                    yes=self.YES_OPTION.upper(),
                    no=self.NO_OPTION.lower(),
                    back=self.BACK_COMMAND,
                )
            ).lower()
            action = self.check_exit(use_common_ports)
            if action == "voltar":
                continue

            if use_common_ports == self.YES_OPTION:
                ports = get_common_ports()
            else:
                while True:
                    ports_input = input(
                        _(
                            "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) "
                            "ou '{back}' para retornar: "
                        ).format(back=self.BACK_COMMAND)
                    )
                    action = self.check_exit(ports_input)
                    if action == "voltar":
                        continue
                    try:
                        ports = list(map(int, ports_input.split(",")))
                        break  # Sucesso na conversão, sai do loop
                    except ValueError:
                        logging.error(
                            _(
                                "Entrada inválida. Por favor, digite números separados por vírgula."
                            )
                        )

            # Selecionar o tipo de escaneamento
            scan_type = self.select_scan_type()
            logging.info(
                _("\nIniciando escaneamento do alvo {target}...\n").format(
                    target=target
                )
            )
            self.scan_single_target(target, ports, scan_type)
            input(_("\nPressione Enter para continuar..."))
            break

    def option_scan_network(self):
        """Opção para escanear uma rede fornecida pelo usuário."""
        while True:
            network = input(
                _(
                    "Digite a rede (ex: 192.168.1.0/24) ou '{back}' para retornar: "
                ).format(back=self.BACK_COMMAND)
            )
            action = self.check_exit(network)
            if action == "voltar":
                break

            use_common_ports = input(
                _(
                    "Deseja usar as portas comuns automaticamente? ({yes}/{no}) ou '{back}' para retornar: "
                ).format(
                    yes=self.YES_OPTION.upper(),
                    no=self.NO_OPTION.lower(),
                    back=self.BACK_COMMAND,
                )
            ).lower()
            action = self.check_exit(use_common_ports)
            if action == "voltar":
                continue

            if use_common_ports == self.YES_OPTION:
                ports = get_common_ports()
            else:
                while True:
                    ports_input = input(
                        _(
                            "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) "
                            "ou '{back}' para retornar: "
                        ).format(back=self.BACK_COMMAND)
                    )
                    action = self.check_exit(ports_input)
                    if action == "voltar":
                        continue
                    try:
                        ports = list(map(int, ports_input.split(",")))
                        break
                    except ValueError:
                        logging.error(
                            _(
                                "Entrada inválida. Por favor, digite números separados por vírgula."
                            )
                        )

            # Selecionar o tipo de escaneamento
            scan_type = self.select_scan_type()
            logging.info(
                _("\nIniciando escaneamento da rede {network}...\n").format(
                    network=network
                )
            )
            self.scan_network(network, ports, scan_type)
            input(_("\nPressione Enter para continuar..."))
            break

    def option_scan_local_network(self):
        """Opção para descobrir e escanear automaticamente a rede local."""
        logging.info(_("Descobrindo automaticamente a rede local..."))
        network = self.get_local_network()
        if network is None:
            input(_("\nPressione Enter para retornar ao menu..."))
            return
        logging.info(_("Rede detectada: {network}").format(network=network))

        use_common_ports = input(
            _(
                "Deseja usar as portas comuns automaticamente? ({yes}/{no}) ou '{back}' para retornar: "
            ).format(
                yes=self.YES_OPTION.upper(),
                no=self.NO_OPTION.lower(),
                back=self.BACK_COMMAND,
            )
        ).lower()
        action = self.check_exit(use_common_ports)
        if action == "voltar":
            return

        if use_common_ports == self.YES_OPTION:
            ports = get_common_ports()
        else:
            while True:
                ports_input = input(
                    _(
                        "Digite as portas para escanear (separadas por vírgula, ex: 22,80,443) "
                        "ou '{back}' para retornar: "
                    ).format(back=self.BACK_COMMAND)
                )
                action = self.check_exit(ports_input)
                if action == "voltar":
                    continue
                try:
                    ports = list(map(int, ports_input.split(",")))
                    break
                except ValueError:
                    logging.error(
                        _(
                            "Entrada inválida. Por favor, digite números separados por vírgula."
                        )
                    )

        # Selecionar o tipo de escaneamento
        scan_type = self.select_scan_type()
        logging.info(
            _("\nIniciando escaneamento da rede {network}...\n").format(network=network)
        )
        self.scan_network(network, ports, scan_type)
        input(_("\nPressione Enter para continuar..."))

    def select_scan_type(self):
        """Permite que o usuário escolha o tipo de escaneamento."""
        logging.info(_("Escolha o tipo de escaneamento:"))
        logging.info("1. " + _("TCP"))
        logging.info("2. " + _("UDP"))
        logging.info("3. " + _("TCP e UDP"))
        scan_choice = input(_("Digite sua escolha (1, 2 ou 3): "))

        if scan_choice == "1":
            scan_type = "tcp"
        elif scan_choice == "2":
            scan_type = "udp"
        elif scan_choice == "3":
            scan_type = "tcp_udp"
        else:
            logging.warning(_("Opção inválida. Usando TCP por padrão."))
            scan_type = "tcp"
        return scan_type

    def run(self):
        self.main_menu()


if __name__ == "__main__":
    app = GateHunter()
    app.run()
