import requests
from colorama import Fore, Style, init
from time import sleep
init(autoreset=True)

def vt_get_ip(api):
    
    ip_addr = input('\nDigite o IP: ')
    while ip_addr == "":
        print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
        sleep(1)
        ip_addr = input('\nDigite o IP: ')

    response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}', 
        headers={
            'x-apikey': api
        }).json()

    try:
        attributes = response['data']['attributes']
        analysis_stats = response['data']['attributes']['last_analysis_stats']
        analysis_results = response['data']['attributes']['last_analysis_results']

        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

        reputation = attributes["reputation"]
        if reputation < 0:
            reputation = Fore.RED + f"{reputation}"
        else:
            reputation = Fore.GREEN + f"{reputation}"

        print(f'Reputação: {reputation}\n')
        print(f'País: {attributes["country"]}')
        print(f'Continente: {attributes["continent"]}\n')
        print(f'Registro de internet regional: {attributes["regional_internet_registry"]}')
        print(f'Rede: {attributes["network"]}')
        print(f'WHOIS Lookup: {attributes["whois"]}')
        print(f'Autonomous System Owner: {attributes["as_owner"]}')
        print(f'Autonomous System Number: {attributes["asn"]}')
        if "jarm" in attributes:
            print(f'JARM fingerprint: {attributes["jarm"]}\n')
        else:
            print('')

        print(Fore.CYAN + Style.BRIGHT + f'\n=== CONTAGEM TOTAL DAS CLASSIFICAÇÕES ===\n')
        for i in analysis_stats:
            print(f'{i}: {analysis_stats[i]}')

        if analysis_stats['malicious'] == 0 and analysis_stats['suspicious'] == 0:
            print(Fore.MAGENTA + '\nNenhum motor de busca identificou este IP como malicioso ou como suspeito\n')

        else:
            print(Fore.CYAN + Style.BRIGHT + f'\n=== DETECÇÃO ===\n')

            for i in analysis_results:

                if analysis_results[i]['category'] == 'malicious' or analysis_results[i]['category'] == 'suspicious':
                        print(Fore.YELLOW + (analysis_results[i]['engine_name']).upper())

                        category = analysis_results[i]['category']
                        if category == 'malicious':
                            category = Fore.RED + f"{category}"
                        else:
                            category = Fore.YELLOW + f"{category}"

                        print(f"Classificação: {analysis_results[i]['category']}")
                        print(f"Resultado: {analysis_results[i]['result']}")
                        print(f"Método: {analysis_results[i]['method']}\n")

    except:
        print(Fore.RED + Style.BRIGHT + '\n=== ERRO ENCONTRADO - Virus Total ===\n')

        print(f'Mensagem: {response["error"]["message"]}')
        print(f'Código: {response["error"]["code"]}\n')

        print('Verfique e tente novamente.\n')