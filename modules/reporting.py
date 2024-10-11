import json

class ReportGenerator:
    def __init__(self, scan_results):
        """Inicializa o gerador de relatórios com os resultados do escaneamento."""
        self.scan_results = scan_results

    def generate_report(self, filename):
        """Gera um relatório JSON dos resultados do escaneamento, incluindo banners detalhados."""
        with open(filename, 'w') as report_file:
            json.dump(self.scan_results, report_file, indent=4)
        print(f"Relatório gerado: {filename}")
