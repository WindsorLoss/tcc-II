import requests
from colorama import Fore, Back, Style, init
from time import ctime
init(autoreset=True)

def get_tatics(api):

    tactic = input('\nDigite o código da tática: ')

    response = requests.get(f'https://www.virustotal.com/api/v3/attack_tactics/{tactic}', 
        headers={
            'x-apikey': api
        }).json()

    try:
        attributes = response['data']['attributes']

        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES DA TÁTICA ===\n')

        print(f'Nome: {attributes["name"]}\n')
        print(f'Descrição: {attributes["description"]}\n')

        print(f'Data de criação: {ctime(attributes["creation_date"])}')
        print(f'Data da última alteração: {ctime(attributes["last_modification_date"])}\n')

        print(f'Link para página do MITRE: {attributes["link"]}')
        print(f'STIX ID da tática: {attributes["stix_id"]}\n')

    except:
        print(Fore.RED + Style.BRIGHT + '\n=== ERRO ENCONTRADO ===\n')

        print(f'Mensagem: {response["error"]["message"]}')
        print(f'Código: {response["error"]["code"]}\n')

        print('Verfique e tente novamente.\n')