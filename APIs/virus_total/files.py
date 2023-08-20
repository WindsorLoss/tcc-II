import requests
import urllib.parse 
from colorama import Fore, Back, Style, init
from time import ctime, sleep
init(autoreset=True)


def vt_get_file(api, file_path = None):

    if not file_path:
        file_path = input('Caminho do arquivo: ')

    response_upload = requests.post("https://www.virustotal.com/api/v3/files", 
        files = {"file": open(file_path, "rb")}, 
        headers= {
            "accept": "application/json",
            "x-apikey": api
        }).json()

    id_upload = urllib.parse.quote(response_upload['data']['id'])

    response_analyses = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id_upload}", 
        headers={
            "accept": "application/json",
            "x-apikey": api
        }).json()

    id_analyses = response_analyses['meta']['file_info']['sha256']

    response_result = requests.get(f"https://www.virustotal.com/api/v3/files/{id_analyses}", 
        headers={
            "accept": "application/json",
            "x-apikey": api
        }).json()

    try:
        attributes = response_result['data']['attributes']
        analysis_stats = response_result['data']['attributes']['last_analysis_stats']
        analysis_results = response_result['data']['attributes']['last_analysis_results']

        if len(analysis_results) == 0:
            print(Fore.YELLOW + '\nCarregando...')
            sleep(20)
            vt_get_file(api, file_path)

        else:

            print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

            print(f'Nome do arquivo: {attributes["meaningful_name"]}')
            print(f'Tipo: {response_result["data"]["type"]}')
            print(f'Tamanho do arquivo: {attributes["size"]} bytes')

            reputation = attributes["reputation"]
            if reputation < 0:
                reputation = Fore.RED + f"{reputation}"
            else:
                reputation = Fore.GREEN + f"{reputation}"
            print(f'Reputação: {reputation}\n')

            print(Fore.YELLOW + 'Possíveis nomes:')
            for i in attributes['names']:
                print(f'-> {i}')

            print(f'\nMD5: {attributes["md5"]}')
            print(f'SHA1: {attributes["sha1"]}')
            print(f'SHA256: {attributes["sha256"]}\n')

            print(f'Primeira data de submissão: {ctime(attributes["first_submission_date"])}')
            print(f'Última data de submissão: {ctime(attributes["last_submission_date"])}')
            print(f'Última data de modificação: {ctime(attributes["last_submission_date"])}\n')

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

                        print(f"Classificação: {analysis_results[i]['category']}")
                        print(f"Resultado: {analysis_results[i]['result']}")
                        print(f"Método: {analysis_results[i]['method']}\n")

            if 'threat_names' in attributes:
                print(Fore.CYAN + Style.BRIGHT + '\n=== NOME DAS AMEAÇAS ===\n')
                for i in attributes['threat_names']:
                    print(f'-> {i}')

    except:
        print(Fore.RED + Style.BRIGHT + '\n=== ERRO ENCONTRADO ===\n')

        print(f'Mensagem: {response_result["error"]["message"]}')
        print(f'Código: {response_result["error"]["code"]}\n')

        print('Verfique e tente novamente.\n')
    