import requests
from colorama import Fore, Back, Style, init
from time import ctime, sleep
init(autoreset=True)

def vt_get_hash(api, hash = None):

    if not hash:
        hash = input('\nDigite a Hash: ')
        while hash == "":
            print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
            sleep(1)
            hash = input('\nDigite a Hash: ')

    response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash}', 
        headers={
            'x-apikey': api,
            'accept': 'application/json'
        }).json()
    
    try: 
        attributes = response['data']['attributes']
        analysis_stats = response['data']['attributes']['last_analysis_stats']
        analysis_results = response['data']['attributes']['last_analysis_results']

        print(Fore.CYAN + Style.BRIGHT + '\n=== INFORMAÇÕES GERAIS ===\n')

        if 'meaningful_name' in attributes:
            print(f"Nome do arquivo: {attributes['meaningful_name']}")
        if 'names' in attributes and len(attributes['names']) > 0:
            print(f"Possíveis nomes:")
            for i in attributes['names']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')

        print(f"\nTipo de arquivo: {response['data']['type']}")
        if 'type_extension' in attributes:
            print(f"Extensão do arquivo: {attributes['type_extension']}")
        print(f"Descrição do tipo de arquivo: {attributes['type_description']}")
        if 'type_tags' in attributes:
            print("Tags do tipo de arquivo:")
            for i in attributes['type_tags']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')
        
        if 'tags' in attributes:
            print("\nTags:")
            for i in attributes['tags']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')


        print(Fore.CYAN + Style.BRIGHT + '\n=== ANÁLISE DO ARQUIVO ===\n')
        
        if 'signature_info' in attributes:
            info_assinatura = attributes["signature_info"]
            print('Informações da assinatura do arquivo:')
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Produto: {info_assinatura["product"]}')
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Nome interno: {info_assinatura["internal name"]}')
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Copyright: {info_assinatura["copyright"]}')
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Nome original: {info_assinatura["original name"]}')
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Versão do arquivo: {info_assinatura["file version"]}')
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Descrição: {info_assinatura["description"]}')
        
        if 'detectiteasy' in attributes:
            print('\nAnálise pelo utilitário "detectiteasy":')
            print(f'  Tipo do arquivo: {attributes["detectiteasy"]["filetype"]}')
            print(f'  Valores:')
            valores = attributes["detectiteasy"]["values"]
            for i in range(len(valores)):
                if 'info' in valores:
                    print( Fore.YELLOW + Style.BRIGHT + f'    -> Informação: {valores[i]["info"]}')

                if 'version' in valores:
                    print(Fore.YELLOW + Style.BRIGHT + f'    -> Versão: {valores[i]["version"]}')

                if 'type' in valores:
                    print(Fore.YELLOW + Style.BRIGHT + f'    -> Tipo: {valores[i]["type"]}')

                if 'name' in valores:
                    print(Fore.YELLOW + Style.BRIGHT + f'    -> Nome: {valores[i]["name"]}')

        if 'known_distributors' in attributes:
            print('\nDistribuidores conhhecidos:')
            for i in attributes['known_distributors']['distributors']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')

        if 'trid' in attributes:
            print('\nAnálise TrID')
            for i in attributes['trid']:
                print(Fore.YELLOW + Style.BRIGHT + f"  -> Tipo do arquivo: {i['file_type']}")
                print(f"    - Probabilidade: {i['probability']}%\n")

        if 'magic' in attributes:
            print(f'\nAnálise do bit mágico: {attributes["magic"]}')

        print(Fore.CYAN + Style.BRIGHT + '\n=== HASHES ===\n')

        print(f'SHA256: {attributes["sha256"]}')
        print(f'SHA1: {attributes["sha1"]}')
        print(f'MD5: {attributes["md5"]}')
        if 'imphash' in attributes:
            print(f'IMPHASH: {attributes["imphash"]}')

        print(Fore.CYAN + Style.BRIGHT + f'\n=== CONTAGEM TOTAL DAS CLASSIFICAÇÕES ===\n')

        reputation = attributes["reputation"]
        if reputation < 0:
            reputation = Fore.RED + f"{reputation}"
        else:
            reputation = Fore.GREEN + f"{reputation}"
        print(f'Reputação: {reputation}')
        print(f"Total de vezes enviado para análise: {attributes['times_submitted']}\n")

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

        if 'popular_threat_classification' in attributes:
            ameaca_popular = attributes['popular_threat_classification']
            print('Classificação de ameaça popular:')
            print(f'  -> Sugestão de rótulo de ameaça: {ameaca_popular["suggested_threat_label"]}')

            print('  -> Categoria popular da ameaça:')
            for i in ameaca_popular['popular_threat_category']:
                print(Fore.YELLOW + Style.BRIGHT + f'    - Categoria: {i["value"]}')
                print(f'    - Contagem: {i["count"]}\n')

            print('  -> Nome popular da ameaça')
            for i in ameaca_popular['popular_threat_name']:
                print(Fore.YELLOW + Style.BRIGHT + f'    - Nome: {i["value"]}')
                print(f'    - Contagem: {i["count"]}\n')

        if 'sandbox_verdicts' in attributes:
            print(Fore.CYAN + Style.BRIGHT + f'\n=== ANÁLISE DE SANDBOX ===\n')

            sandbox = attributes['sandbox_verdicts']
            for i in sandbox:
                print(Fore.YELLOW + Style.BRIGHT + f'{i}')
                if 'category' in sandbox[i]:
                    print(f'Categoria: {sandbox[i]["category"]}')
                if 'confidence' in sandbox[i]:
                    print(f'Confiança: {sandbox[i]["confidence"]}')
                if 'malware_classification' in sandbox[i]:
                    print('Classificação do malware:')
                    for j in sandbox[i]['malware_classification']:
                        print(f'  -> {j}')

                if 'malware_names' in i:
                    print('Nome dos malwares:')
                    for j in sandbox[i]['malware_names']:
                        print(f'  -> {j}')
            
                print('\n')

    except:
        print(Fore.RED + Style.BRIGHT + '\n=== ERRO ENCONTRADO - Virus Total ===\n')

        print(f'Mensagem: {response["error"]["message"]}')
        print(f'Código: {response["error"]["code"]}\n')

        print('Verfique e tente novamente.\n')