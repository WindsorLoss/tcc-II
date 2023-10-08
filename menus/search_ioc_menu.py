from colorama import Fore, Back, Style, init
from APIs.virus_total.ip_addresses import vt_get_ip
from APIs.virus_total.url import vt_get_url
from APIs.virus_total.files import vt_get_file
from APIs.virus_total.hash import vt_get_hash
from menus.functions.keys_organizer import keys_organizer
from time import sleep

init(autoreset=True)

def search_ioc_menu():
    while True:

        file = open('api_keys.txt', 'r')
        api_names, api_keys = keys_organizer(file)

        print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

        print(Fore.CYAN + Style.BRIGHT + '\n=== PESQUISAR INDICADORES DE COMPROMETIMENTO ===\n')
        
        print(Fore.YELLOW + 'Escolha uma opção:')
        print('1 - Análise de arquivo')
        print('2 - Análise de hash')
        print('3 - Análise de IP')
        print('4 - Análise de URL')
        print('0 - Voltar\n')

        option = int(input('Opção: '))

        if option < 0 or option > 4:
            print('\nOpção inválida, tente novamente.')

        elif option == 0:
            print('\nVoltando...\n')
            break

        elif option == 1:
            vt_get_file(api_keys[api_names.index('virustotal')])
        
        elif option == 2:
            vt_get_hash(api_keys[api_names.index('virustotal')])
        
        elif option == 3:
            vt_get_ip(api_keys[api_names.index('virustotal')])

        elif option == 4:
            vt_get_url(api_keys[api_names.index('virustotal')])
