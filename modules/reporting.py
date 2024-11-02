import json
import logging
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, scan_results):
        """Inicializa o gerador de relatórios com os resultados do escaneamento."""
        self.scan_results = scan_results

    def generate_report(self, filename):
        """Gera um relatório JSON dos resultados do escaneamento."""
        try:
            # Certifique-se de que o diretório 'reports' existe
            reports_dir = os.path.dirname(filename)
            if reports_dir and not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
                logging.info(f"Diretório '{reports_dir}' criado.")

            report_data = {
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'results': self.scan_results
            }
            with open(filename, 'w') as report_file:
                json.dump(report_data, report_file, indent=4)
            logging.info(f"\nRelatório gerado: {filename}")
        except IOError as e:
            logging.error(f"Erro ao escrever o relatório {filename}: {e}")
        except Exception as e:
            logging.error(f"Erro inesperado ao gerar o relatório: {e}")
