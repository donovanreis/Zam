import requests
from bs4 import BeautifulSoup
import pyfiglet
from colorama import Fore, Style, init
from datetime import datetime
import re

# Inicializa o colorama
init()

# Função para buscar subdomínios usando crt.sh
def find_subdomains(domain):
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = list(set([entry['name_value'].lower() for entry in data]))
    except Exception as e:
        print(f"Erro ao buscar subdomínios: {e}")
    return subdomains

# Função para obter status code de subdomínio
def get_status_code(subdomain):
    try:
        response = requests.get(f"http://{subdomain}")
        return response.status_code
    except requests.ConnectionError:
        return None

# Função para detectar vulnerabilidades XSS
def detect_xss(subdomain):
    xss_payload = "<script>alert(1)</script>"
    try:
        response = requests.get(f"http://{subdomain}", params={"q": xss_payload})
        if xss_payload in response.text:
            return True
    except requests.ConnectionError:
        return False
    return False

# Função para criar um relatório
def create_report(domain, results):
    mosca_banner = r"""
     __     __
    /  \~~~/  \
  ,----(     ..)
 /      \__     )
|     __.-'|    \
 \~~~-_____/   / 
  \ \      /  /
"""
    nome_banner = pyfiglet.figlet_format("ZUM")
    report = f"{mosca_banner}\n{nome_banner}\nRelatório de Recon para: {domain}\n"
    report += f"\nData: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    for result in results:
        report += f"\nSubdomínio: {result['subdomain']}"
        report += f"\nStatus Code: {result['status_code']}"
        report += f"\nVulnerável a XSS: {'Sim' if result['xss'] else 'Não'}\n"
    
    with open(f"{domain}_recon_report.txt", "w") as f:
        f.write(report)
    
    print(f"\n{Fore.CYAN}{report}{Style.RESET_ALL}")
    print(f"Relatório salvo como {domain}_recon_report.txt")

# Função principal para executar a geolocalização e criar o relatório
def run_recon(domain):
    subdomains = find_subdomains(domain)
    if not subdomains:
        print("Nenhum subdomínio encontrado.")
        return

    results = []
    for subdomain in subdomains:
        status_code = get_status_code(subdomain)
        xss_vulnerable = detect_xss(subdomain)

        # Exibir subdomínio, status code e se é vulnerável a XSS
        status_color = Fore.GREEN if status_code == 200 else Fore.RED
        xss_color = Fore.RED if xss_vulnerable else Fore.GREEN
        print(f"{Fore.CYAN}{subdomain}{Style.RESET_ALL} - Status Code: {status_color}{status_code}{Style.RESET_ALL} - XSS: {xss_color}{'Vulnerável' if xss_vulnerable else 'Não Vulnerável'}{Style.RESET_ALL}")
        
        results.append({
            'subdomain': subdomain,
            'status_code': status_code,
            'xss': xss_vulnerable
        })
    
    create_report(domain, results)

if __name__ == "__main__":
    target_domain = input("Digite o domínio alvo: ")
    run_recon(target_domain)
