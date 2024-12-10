import requests
from bs4 import BeautifulSoup
import pyfiglet
from colorama import Fore, Style, init
from datetime import datetime
import re
import socket
import threading

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

# Função para verificar portas abertas
def check_open_ports(subdomain):
    open_ports = []
    common_ports = [80, 443, 21, 22, 23, 25, 53, 110, 143, 3389]
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((subdomain, port))
        except:
            continue
        else:
            open_ports.append(port)
        s.close()
    return open_ports

# Função para fazer crawling de JS e JSON
def crawl_js_json(subdomain):
    js_files = []
    json_files = []
    try:
        response = requests.get(f"http://{subdomain}")
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup.find_all('script'):
            src = script.get('src')
            if src and src.endswith('.js'):
                js_files.append(src)
            elif src and src.endswith('.json'):
                json_files.append(src)
    except requests.ConnectionError:
        pass
    return js_files, json_files

# Função para criar um relatório
def create_report(domain, results):
    banner = pyfiglet.figlet_format("ZAM")
    assinatura = "feita por Donovan.Sadon"
    report = f"{banner}\n{assinatura}\nRelatório de Recon para: {domain}\n"
    report += f"\nData: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    for result in results:
        report += f"\nSubdomínio: {result['subdomain']}"
        report += f"\nStatus Code: {result['status_code']}"
        report += f"\nPortas Abertas: {', '.join(map(str, result['open_ports']))}"
        report += f"\nArquivos JS: {', '.join(result['js_files'])}"
        report += f"\nArquivos JSON: {', '.join(result['json_files'])}"
        report += f"\nVulnerável a XSS: {'Sim' if result['xss'] else 'Não'}\n"
    
    with open(f"{domain}_recon_report.txt", "w") as f:
        f.write(report)
    
    print(f"\n{Fore.CYAN}{report}{Style.RESET_ALL}")
    print(f"Relatório salvo como {domain}_recon_report.txt")

# Função principal para executar a geolocalização e criar o relatório
def run_recon(domain):
    banner = pyfiglet.figlet_format("ZAM")
    assinatura = "feita por Donovan.Sadon"
    print(f"{banner}\n{assinatura}")
    
    subdomains = find_subdomains(domain)
    if not subdomains:
        print("Nenhum subdomínio encontrado.")
        return

    results = []
    for subdomain in subdomains:
        status_code = get_status_code(subdomain)
        xss_vulnerable = detect_xss(subdomain)
        open_ports = check_open_ports(subdomain)
        js_files, json_files = crawl_js_json(subdomain)

        # Exibir subdomínio, status code, portas abertas, arquivos JS/JSON e se é vulnerável a XSS
        status_color = Fore.GREEN if status_code == 200 else Fore.RED
        xss_color = Fore.RED if xss_vulnerable else Fore.GREEN
        print(f"{Fore.CYAN}{subdomain}{Style.RESET_ALL} - Status Code: {status_color}{status_code}{Style.RESET_ALL} - Portas Abertas: {Fore.YELLOW}{', '.join(map(str, open_ports))}{Style.RESET_ALL} - Arquivos JS: {Fore.YELLOW}{', '.join(js_files)}{Style.RESET_ALL} - Arquivos JSON: {Fore.YELLOW}{', '.join(json_files)}{Style.RESET_ALL} - XSS: {xss_color}{'Vulnerável' if xss_vulnerable else 'Não Vulnerável'}{Style.RESET_ALL}")
        
        results.append({
            'subdomain': subdomain,
            'status_code': status_code,
            'open_ports': open_ports,
            'js_files': js_files,
            'json_files': json_files,
            'xss': xss_vulnerable
        })
    
    create_report(domain, results)

def find_xss_vulnerabilities(domain):
    subdomains = find_subdomains(domain)
    if not subdomains:
        print("Nenhum subdomínio encontrado.")
        return

    for subdomain in subdomains:
        xss_vulnerable = detect_xss(subdomain)
        xss_color = Fore.RED if xss_vulnerable else Fore.GREEN
        print(f"{Fore.CYAN}{subdomain}{Style.RESET_ALL} - XSS: {xss_color}{'Vulnerável' if xss_vulnerable else 'Não Vulnerável'}{Style.RESET_ALL}")

def start_automation(domain):
    while True:
        run_recon(domain)
        print("Digite 'stop' para parar o reconhecimento ou 'continue' para continuar:")
        user_input = input().lower()
        if user_input == 'stop':
            print("Processo de reconhecimento interrompido.")
            break

if __name__ == "__main__":
    banner = pyfiglet.figlet_format("ZAM")
    assinatura = "feita por Donovan.Sadon"
    print(f"{banner}\n{assinatura}")
    print("Opções disponíveis:")
    print("1. Realizar Reconhecimento de Subdomínios")
    print("2. Encontrar Falhas de XSS")
    print("3. Iniciar Automação de Reconhecimento")

    opcao = input("Escolha uma opção (1/2/3): ")

    if opcao == "1":
        target_domain = input("Digite o domínio alvo: ")
        run_recon(target_domain)
    elif opcao == "2":
        target_domain = input("Digite o domínio alvo: ")
        find_xss_vulnerabilities(target_domain)
    elif opcao == "3":
        target_domain = input("Digite o domínio alvo: ")
        start_automation(target_domain)
    else:
        print("Opção inválida. Tente novamente.")
