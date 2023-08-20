from colorama import Fore, Back, Style
import os
from time import sleep

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

            
        if option == 1:
            api_vt = input('\nQual o valor da sua chave de API do Virus Total? ')
            while api_vt == '':
                print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                sleep(1)
                api_vt = input('\nQual o valor da sua chave de API do Virus Total?')
        

