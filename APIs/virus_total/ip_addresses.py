import requests
from colorama import Fore, Style, init
from time import sleep
init(autoreset=True)

def vt_get_ip(api, ip_addr):
    
    response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}', 
        headers={
            'x-apikey': api
        }).json()

    try:
        attributes = response['data']['attributes']
        analysis_stats = response['data']['attributes']['last_analysis_stats']
        analysis_results = response['data']['attributes']['last_analysis_results']

        print(Fore.MAGENTA + Style.BRIGHT + '\n\n-=-=-=- VirusTotal -=-=-=-\n')
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


        print(Fore.CYAN + Style.BRIGHT + f'\n=== CONTAGEM TOTAL DAS CLASSIFICAÇÕES ===\n')
        for i in analysis_stats:
            print(f'{i}: {analysis_stats[i]}')

        if analysis_stats['malicious'] == 0 and analysis_stats['suspicious'] == 0:
            print(Fore.MAGENTA + '\nNenhum motor de busca identificou este IP como malicioso ou como suspeito\n')

        else:
            print(Fore.CYAN + Style.BRIGHT + f'\n=== DETECÇÃO ===\n')

            for i in analysis_results:

                if analysis_results[i]['category'] == 'malicious' or analysis_results[i]['category'] == 'suspicious':
                        print(Fore.YELLOW + Style.BRIGHT + (analysis_results[i]['engine_name']).upper())

                        category = analysis_results[i]['category']
                        if category == 'malicious':
                            category = Fore.RED + Style.BRIGHT + f"{category}"
                        else:
                            category = Fore.YELLOW + Style.BRIGHT + f"{category}"

                        print(f"Classificação: {category}")
                        print(f"Resultado: {analysis_results[i]['result']}")
                        print(f"Método: {analysis_results[i]['method']}\n")

    except Exception as e:
        print(e)

    except:
        print(Fore.RED + Style.BRIGHT + '\n=== ERRO ENCONTRADO - Virus Total ===\n')

        print(f'Mensagem: {response["error"]["message"]}')
        print(f'Código: {response["error"]["code"]}\n')

        print('Verfique e tente novamente.\n')
