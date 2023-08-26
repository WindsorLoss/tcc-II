from colorama import Fore, Back, Style
import os
from time import sleep
from .functions.keys_organizer import keys_organizer

def api_config_menu():

    print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

    print(Fore.CYAN + Style.BRIGHT + '\n=== CONFIGURAÇÃO DE CHAVES DE API ===\n')
    
    print(Fore.YELLOW + 'Escolha uma opção:')
    print('1 - Chave para Virus Total')
    print('2 - Chave para OTX Alien Vault')
    print('0 - Voltar\n')

    option = int(input('Opção: '))

    if option < 0 or option > 2:
        print('\nOpção inválida, tente novamente.')

    elif option == 0:
        print('\nVoltando...\n')

    else:

        if os.path.isfile('api_keys.txt'):
            print(Fore.GREEN + Style.BRIGHT + '\nArquivo de chaves detectado com sucesso!\n')
            file = open('api_keys.txt', 'r')
            api_names = keys_organizer(file)
            file.close()
            sleep(1)

        else:
            print(Fore.MAGENTA + Style.BRIGHT + '\nArquivo de chaves não encontrado. Criando arquivo...\n')
            file = open('api_keys.txt', 'a+')
            sleep(1)
            
        if option == 1:

            if 'virustotal' in api_names:
                print('\nJá existe um registro para a chave do Virus Total.')
                option = input('Deseja substituir? (S/N)').lower()
                while (option != 'n' and option != 's') or option == '' :
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                    sleep(1)
                    option = input('\nDeseja substituir? (S/N) ')

                if option == 's':
                    api_vt = input('\nQual o valor da sua chave de API do Virus Total? ')
                    while api_vt == '':
                        print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                        sleep(1)
                        api_vt = input('\nQual o valor da sua chave de API do Virus Total? ')

                else:
                    api_config_menu()

            else:
                api_vt = input('\nQual o valor da sua chave de API do Virus Total? ')
                while api_vt == '':
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                    sleep(1)
                    api_vt = input('\nQual o valor da sua chave de API do Virus Total? ')
                
                file = open('api_keys.txt', 'a+')
