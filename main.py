from colorama import Fore, Back, Style, init
import os
from time import sleep
from menus.search_ioc_menu import search_ioc_menu
from menus.api_config_menu import api_config_menu

init(autoreset=True)

def main():

    print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

    print(Fore.CYAN + Style.BRIGHT + '\n=== O UM PROGRAMA PARA TUDO ANALISAR ===\n')
    
    print(Fore.YELLOW + 'Escolha uma opção:')
    print('1 - Pesquisar IOCs')
    print('2 - Configurar chaves de API')
    print('3 - Créditos (?)')
    print('0 - Sair\n')

    option = int(input('Opção: '))

    if option < 0 or option > 3:
        print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')
        sleep(1)
        main()

    elif option == 0:
        print('\nSaindo...\n')
        exit()

    elif option == 1:
        if os.path.isfile('api_keys.txt'):
            search_ioc_menu()
        else:
            print(Fore.RED + Style.BRIGHT + '\nOh, não :(\n')
            print(Fore.RED + Style.BRIGHT + 'Para acessar esta opção, primeiro é necessário configurar as suas chaves de API.\nTente novamente após realizar a configuração!')
            sleep(2)
        main()

    elif option == 2:
        api_config_menu()
        main()

if __name__ == "__main__":
    main()