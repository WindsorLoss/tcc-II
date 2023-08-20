from colorama import Fore, Back, Style, init
from APIs.virus_total.ip_addresses import vt_get_ip
from APIs.virus_total.url import vt_get_url
from APIs.virus_total.files import vt_get_file
from time import sleep

init(autoreset=True)

def search_ioc_menu():
    api = '9de140082d446eb47b068a421d61cf873ecbe0d515957ca4a3cad968d3c9f9de'

    print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

    print(Fore.CYAN + Style.BRIGHT + '\n=== PESQUISAR INDICADORES DE COMPROMETIMENTO ===\n')
    
    print(Fore.YELLOW + 'Escolha uma opção:')
    print('1 - Análise de arquivo')
    print('2 - Análise de hash (NOT AVAILABLE)')
    print('3 - Análise de IP')
    print('4 - Análise de URL')
    print('0 - Voltar\n')

    option = int(input('Opção: '))

    if option < 0 or option > 4:
        print('\nOpção inválida, tente novamente.')
        search_ioc_menu()

    elif option == 0:
        print('\nVoltando...\n')

    elif option == 1:
        vt_get_file(api)
        search_ioc_menu()
    
    elif option == 2:
        print('\nOpção não disponível no momento.')
        sleep(1)
        search_ioc_menu()
    
    elif option == 3:
        vt_get_ip(api)
        search_ioc_menu()

    elif option == 4:
        vt_get_url(api)
        search_ioc_menu()
