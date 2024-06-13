import requests
import time
import re

# Substitua pelas suas chaves de API
URLSCAN_API_KEY = 'URLSCAN_API_KEY'
VIRUSTOTAL_API_KEY = 'VIRUSTOTAL_API_KEY'
IPINFO_API_KEY = 'IPINFO_API_KEY'

URLSCAN_ENDPOINT = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT_ENDPOINT = 'https://urlscan.io/api/v1/result/'

VIRUSTOTAL_SCAN_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/url/scan'
VIRUSTOTAL_REPORT_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/url/report'
IPINFO_ENDPOINT = 'https://ipinfo.io/'

def is_valid_ip(address):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(address) is not None

def get_urlscan_verdict(scan_id):
    result_url = f"{URLSCAN_RESULT_ENDPOINT}{scan_id}/"
    for _ in range(10):
        response = requests.get(result_url)
        if response.status_code == 200:
            result_data = response.json()
            verdict = result_data.get('verdicts', {}).get('overall', {}).get('score')
            ip = result_data.get('page', {}).get('ip', 'IP não encontrado')
            status = result_data.get('page', {}).get('status', 'Status não encontrado')
            title = result_data.get('page', {}).get('title', 'Título não encontrado')
            domain = result_data.get('page', {}).get('domain', 'Domínio não encontrado')
            server = result_data.get('page', {}).get('server', 'Servidor não encontrado')
            mime_type = result_data.get('page', {}).get('mimeType', 'Tipo MIME não encontrado')
            
            threat_indicators = result_data.get('lists', {}).get('indicators', [])
            threat_indicators = threat_indicators if isinstance(threat_indicators, list) else ['Indicadores de ameaças não encontrados']
            
            return (verdict, ip, status, title, domain, server, mime_type, threat_indicators)
        elif response.status_code == 404:
            print("Resultados ainda não disponíveis. Tentando novamente em 5 segundos...")
            time.sleep(5)
        else:
            print(f"Erro ao obter resultado da análise. Código de status: {response.status_code}")
            break
    return None, None, None, None, None, None, None, None

def get_ip_abuse_contact(ip):
    response = requests.get(f"{IPINFO_ENDPOINT}/{ip}/abuse", params={'token': IPINFO_API_KEY})
    if response.status_code == 200:
        abuse_data = response.json()
        return abuse_data.get('contact', 'Contato de abuso não encontrado')
    return 'Contato de abuso não encontrado'

def get_ip_geolocation(ip):
    response = requests.get(f"{IPINFO_ENDPOINT}/{ip}", params={'token': IPINFO_API_KEY})
    if response.status_code == 200:
        geo_data = response.json()
        city = geo_data.get('city', 'Cidade não encontrada')
        country = geo_data.get('country', 'País não encontrado')
        org = geo_data.get('org', 'Organização não encontrada')
        loc = geo_data.get('loc', 'Coordenadas não encontradas')
        hostname = geo_data.get('hostname', 'Hostname não encontrado')
        abuse_contact = get_ip_abuse_contact(ip)
        return {
            'location': f"{city}, {country} (Org: {org}, Coordenadas: {loc})",
            'hostname': hostname,
            'abuse_contact': abuse_contact
        }
    else:
        return {
            'location': 'Geolocalização não encontrada',
            'hostname': 'Hostname não encontrado',
            'abuse_contact': 'Contato de abuso não encontrado'
        }

def get_virustotal_verdict(resource, is_url=True):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    report_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
    response = requests.get(VIRUSTOTAL_REPORT_ENDPOINT, params=report_params)
    if response.status_code == 200:
        report_data = response.json()
        positives = report_data.get('positives', 'Positivos não encontrados')
        total = report_data.get('total', 'Total não encontrado')
        scans = report_data.get('scans', {})
        relevant_verdicts = [(engine, details['result']) for engine, details in scans.items() if details['detected']]
        reputation = report_data.get('reputation', 'Reputação não encontrada')

        if isinstance(report_data.get('total'), dict):
            harmless = report_data['total'].get('harmless', 'Não encontrado')
            malicious = report_data['total'].get('malicious', 'Não encontrado')
            suspicious = report_data['total'].get('suspicious', 'Não encontrado')
        else:
            harmless = 'Não encontrado'
            malicious = 'Não encontrado'
            suspicious = 'Não encontrado'

        return positives, total, relevant_verdicts, report_data, reputation, harmless, malicious, suspicious

    elif response.status_code == 204:
        print("Resultados ainda não disponíveis. Tentando novamente em 5 segundos...")
        time.sleep(5)

    else:
        print("Relatório não encontrado, iniciando nova análise.")
        scan_params = {'apikey': VIRUSTOTAL_API_KEY, 'url': resource} if is_url else {'apikey': VIRUSTOTAL_API_KEY, 'ip': resource}
        response = requests.post(VIRUSTOTAL_SCAN_ENDPOINT, data=scan_params)
        if response.status_code == 200:
            scan_data = response.json()
            if isinstance(scan_data, list) and not scan_data:
                print("Lista vazia retornada pela API do VirusTotal")
                return None, None, None, None, None, None, None, None

            scan_id = scan_data.get('scan_id', 'N/A')
            time.sleep(15)  # Esperar para permitir que a análise seja processada

            report_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource, 'scan': 1}
            for _ in range(10):
                response = requests.get(VIRUSTOTAL_REPORT_ENDPOINT, params=report_params)
                if response.status_code == 200:
                    report_data = response.json()
                    positives = report_data.get('positives', 'Positivos não encontrados')
                    total = report_data.get('total', 'Total não encontrado')
                    scans = report_data.get('scans', {})
                    relevant_verdicts = [(engine, details['result']) for engine, details in scans.items() if details['detected']]
                    reputation = report_data.get('reputation', 'Reputação não encontrada')

                    if isinstance(report_data.get('total'), dict):
                        harmless = report_data['total'].get('harmless', 'Não encontrado')
                        malicious = report_data['total'].get('malicious', 'Não encontrado')
                        suspicious = report_data['total'].get('suspicious', 'Não encontrado')
                    else:
                        harmless = 'Não encontrado'
                        malicious = 'Não encontrado'
                        suspicious = 'Não encontrado'

                    return positives, total, relevant_verdicts, report_data, reputation, harmless, malicious, suspicious
                elif response.status_code == 204:
                    print("Resultados ainda não disponíveis. Tentando novamente em 5 segundos...")
                    time.sleep(5)
                else:
                    print(f"Erro ao obter resultado do relatório. Código de status: {response.status_code}")
                    break
        else:
            print(f"Erro ao iniciar a análise no VirusTotal. Código de status: {response.status_code}")
    return None, None, None, None, None, None, None, None

def check_url_protocol(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    try:
        response = requests.get(url)
        return response.url.startswith('https://'), response.url
    except requests.exceptions.RequestException as e:
        print(f"Erro ao verificar o protocolo da URL: {e}")
        return False, url

def main():
    input_value = input("Digite a URL ou IP que você deseja analisar: ")
    
    if is_valid_ip(input_value):
        final_ip = input_value
        geo_data = get_ip_geolocation(final_ip)
        positives, total, relevant_verdicts, report_data, reputation, harmless, malicious, suspicious = get_virustotal_verdict(final_ip, is_url=False)
        
        if positives is not None:
            print(f"\n---- Scan Results (IP) ----")
            print(f"* IP: {final_ip}")
            print(f"* Geolocalização: {geo_data['location']}")
            print(f"* Hostname: {geo_data['hostname']}")
            print(f"* Contato de Abuso: {geo_data['abuse_contact']}")
            print(f"* ASN: {report_data.get('asn', 'ASN não encontrado')}")
            print(f"* Organizações: {report_data.get('as_owner', 'Organização não encontrada')}")
            print(f"* País: {report_data.get('country', 'País não encontrado')}")
            print("\n---- Vereditos ----")
            print(f"* VirusTotal: Positivos: {positives}/{total}")
            print(f"* Reputação: {reputation}")
            print(f"* Harmless: {harmless}")
            print(f"* Malicious: {malicious}")
            print(f"* Suspicious: {suspicious}")
            print("\n---- Results ----")
            if relevant_verdicts:
                print("* Detecções:")
                for engine, result in relevant_verdicts:
                    print(f"  - {engine}: {result}")
            else:
                print("* Nenhuma detecção encontrada.")
            print(f"--------------------\n")
        else:
            print("Não foi possível obter o veredito da análise.")
    else:
        is_https, final_url = check_url_protocol(input_value)
        
        headers = {
            'API-Key': URLSCAN_API_KEY,
            'Content-Type': 'application/json'
        }

        data = {
            'url': final_url,
            'visibility': 'public'
        }

        response = requests.post(URLSCAN_ENDPOINT, headers=headers, json=data)
        
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data.get('uuid')
            
            print("\n### Script criado por Marcelo Bentes ###")
            print("\n* Análise iniciada.")
            print(f"* ID da análise: {scan_id}")
            print("* Aguarde para que a análise seja concluída...\n")
            
            # Esperar alguns segundos para a análise ser concluída
            time.sleep(10)
            
            (verdict, ip, status, title, domain, server, mime_type, threat_indicators) = get_urlscan_verdict(scan_id)
            
            if ip != 'IP não encontrado':
                geo_data = get_ip_geolocation(ip)
            else:
                geo_data = {'location': 'Geolocalização não encontrada', 'hostname': 'Hostname não encontrado', 'abuse_contact': 'Contato de abuso não encontrado'}

            positives, total, relevant_verdicts, report_data, reputation, harmless, malicious, suspicious = get_virustotal_verdict(final_url)
            
            if verdict is not None and positives is not None:
                print(f"\n---- Scan Results (URLScan) ----")
                print(f"* URL: {final_url}")
                print(f"* IP: {ip}")
                print(f"* Status: {status}")
                print(f"* Título: {title}")
                print(f"* Domínio: {domain}")
                print(f"* Servidor: {server}")
                print(f"* Tipo MIME: {mime_type}")
                print(f"* Geolocalização: {geo_data['location']}")
                print(f"* Hostname: {geo_data['hostname']}")
                print(f"* Contato de Abuso: {geo_data['abuse_contact']}")
                print(f"* ASN: {report_data.get('asn', 'ASN não encontrado')}")
                print(f"* Organizações: {report_data.get('as_owner', 'Organização não encontrada')}")
                print(f"* País: {report_data.get('country', 'País não encontrado')}")
                print(f"* Indicadores de Ameaças: {', '.join(threat_indicators) if threat_indicators else 'Nenhum'}")
                print("\n---- Vereditos ----")
                print(f"* URLScan: {'Malicioso' if verdict < 0 else 'Não Malicioso'} (Score: {verdict})")
                print(f"* VirusTotal: Positivos: {positives}/{total}")
                print(f"* Reputação: {reputation}")
                print(f"* Harmless: {harmless}")
                print(f"* Malicious: {malicious}")
                print(f"* Suspicious: {suspicious}")
                print("\n---- Results ----")
                if relevant_verdicts:
                    print("* Detecções:")
                    for engine, result in relevant_verdicts:
                        print(f"  - {engine}: {result}")
                else:
                    print("* Nenhuma detecção encontrada.")
                print(f"--------------------\n")
            else:
                print("Não foi possível obter o veredito da análise.")
        else:
            print(f"Erro ao iniciar a análise no URLScan. Código de status: {response.status_code}")

if __name__ == "__main__":
    main()

# ### Script criado por Marcelo Bentes ###
