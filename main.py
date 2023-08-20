from colorama import Fore, Back, Style, init
from ip_addresses import get_ip
from url import get_url
from tactics import get_tatics
from files import get_file
init(autoreset=True)

def main():
    api = '9de140082d446eb47b068a421d61cf873ecbe0d515957ca4a3cad968d3c9f9de'

    print(Fore.CYAN + Style.BRIGHT + '\n=== O UM PROGRAMA PARA TUDO ANALISAR ===\n')
    
    print(Fore.YELLOW + 'Escolha uma opção:')
    print('1 - Análise de arquivo')
    print('2 - Análise de hash (NOT AVAILABLE)')
    print('3 - Análise de IP')
    print('4 - Análise de URL')
    print('5 - Análise de Domínio (NOT AVAILABLE)')
    print('6 - Análise de Táticas')
    print('7 - Análise de Técnicas (NOT AVAILABLE)')
    print('0 - Sair\n')

    option = int(input('Opção: '))

    if option < 0 or option > 7:
        print('\nOpção inválida, tente novamente.')
        main()

    elif option == 0:
        print('\nSaindo...\n')
        exit()

    elif option == 1:
        get_file(api)
        main()
    
    elif option == 2:
        print('\nOpção não disponível no momento.')
        main()
    
    elif option == 3:
        get_ip(api)
        main()

    elif option == 4:
        get_url(api)
        main()

    elif option == 5:
        print('\nOpção não disponível no momento.')
        main()

    elif option == 6:
        get_tatics(api)
        main()

    elif option == 7:
        print('\nOpção não disponível no momento.')
        main()

if __name__ == "__main__":
    main()