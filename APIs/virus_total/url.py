from time import sleep
import requests
import base64
from colorama import Fore, Back, Style, init
init(autoreset=True)

def vt_get_url(api, url = None):

    if not url:
        url = input('\nDigite a URL: ')

    response = requests.post('https://www.virustotal.com/api/v3/urls',
    data=f'url={url}', 
    headers={
        "accept": "application/json",
        'x-apikey': api,
        "content-type": "application/x-www-form-urlencoded"
    }).json()
    
    url_id = response['data']['id']

    response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{url_id}', 
        headers={
            'x-apikey': api,
            "accept": "application/json"
        }).json()

    url_id = response['meta']['url_info']['id']

    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', 
        headers={
            'x-apikey': api,
            "accept": "application/json"
        }).json()

    try:

        attributes = response['data']['attributes']
        analysis_stats = response['data']['attributes']['last_analysis_stats']
        analysis_results = response['data']['attributes']['last_analysis_results']

        if len(analysis_results) == 0:
            print(Fore.YELLOW + '\nCarregando...')    
            sleep(5)
            vt_get_url(api, url)

        else:

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

            reputation = attributes["reputation"]
            if reputation < 0:
                reputation = Fore.RED + f"{reputation}"
            else:
                reputation = Fore.GREEN + f"{reputation}"

            print(f'Reputação: {reputation}\n')
            if "title" in attributes:
                print(f'Título: {attributes["title"]}\n')   
            else:
                print(f'Título: Não disponível\n')   

            print(f'URL final: {attributes["last_final_url"]}')
            if "last_http_response_code" in attributes:
                print(f'Última resposta de código HTTP: {attributes["last_http_response_code"]}\n')
                
            print(f'ID SHA256: {response["data"]["id"]}')

            print(Fore.CYAN + Style.BRIGHT + '\n=== CATEGORIAS ===\n')
            for i in attributes['categories']:
                print(Fore.YELLOW + i)
                print(f"{attributes['categories'][i]}\n")

            if len(attributes["tags"]) > 0:
                print(Fore.CYAN + Style.BRIGHT + '\n=== TAGS ===\n')
                for i in attributes['tags']:
                    print(f'-> {i}')

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

                        print(f"Classificação: {category}")
                        print(f"Resultado: {analysis_results[i]['result']}")
                        print(f"Método: {analysis_results[i]['method']}\n")

            if 'threat_names' in attributes:
                print(Fore.CYAN + Style.BRIGHT + '\n=== NOME DAS AMEAÇAS ===\n')
                for i in attributes['threat_names']:
                    print(f'-> {i}') 
            
            if "redirection_chain" in attributes:
                print(Fore.CYAN + Style.BRIGHT + f'\n=== CADEIA DE REDIRECIONAMENTOS ===\n')
                for i in range(len(attributes["redirection_chain"])):
                    print(f'{i + 1} -> {attributes["redirection_chain"][i]}')

            if "outgoing_links" in attributes:
                print(Fore.CYAN + Style.BRIGHT + f'\n=== OUTGOING LINKS ===\n')
                for i in range(len(attributes["outgoing_links"])):
                    print(f'{i + 1} -> {attributes["outgoing_links"][i]}') 
              

    except:

        error_code = response['error']['code']
        error_message = response['error']['message']

        if error_code == "NotFoundError":
            vt_get_url(api, url)
        else:
            print(Fore.RED + Style.BRIGHT + '\n=== ERRO ENCONTRADO ===\n')

            print(f'Mensagem: {error_message}')
            print(f'Código: {error_code}\n')

            print('Verfique e tente novamente.\n')