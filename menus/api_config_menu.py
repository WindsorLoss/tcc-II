from colorama import Fore, Style
import os
from time import sleep
from .functions.keys_organizer import keys_organizer
from .functions.overwrite_key import overwrite_key

def api_config_menu():

    if os.path.isfile('api_keys.txt'):
        print(Fore.GREEN + Style.BRIGHT + '\nArquivo de chaves detectado com sucesso!')
        file = open('api_keys.txt', 'r')
        api_names, api_keys = keys_organizer(file)
        file.close()
        sleep(1)

    else:
        print(Fore.MAGENTA + Style.BRIGHT + '\nArquivo de chaves não encontrado.\nCriando arquivo...')
        file = open('api_keys.txt', 'a+')
        api_names = []
        file.close()
        sleep(1)

    while True:

        print(Fore.YELLOW + Style.BRIGHT + '\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-')

        print(Fore.CYAN + Style.BRIGHT + '\n=== CONFIGURAÇÃO DE CHAVES DE API ===\n')
        
        print(Fore.YELLOW + 'Escolha uma opção:')
        print('1 - Chave para Virus Total')
        print('2 - Chave para OTX Alien Vault')
        print('9 - Arquivo de chaves')
        print('0 - Voltar\n')

        option = int(input('Opção: '))

        if option != 0 and option != 1 and option != 2 and option != 9:
            print('\nOpção inválida, tente novamente.')

        elif option == 0:
            print('\nVoltando...\n')
            sleep(1)
            break

        else:

                
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
                        overwrite_key('api_keys.txt', 'virustotal', api_vt)
                        sleep(1)

                else:
                    api_vt = input('\nQual o valor da sua chave de API do Virus Total? ')
                    while api_vt == '':
                        print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                        sleep(1)
                        api_vt = input('\nQual o valor da sua chave de API do Virus Total? ')
                    
                    file = open('api_keys.txt', 'a+')
                    file.write(f'virustotal:{api_vt}\n')
                    file.close()
                    print(Fore.GREEN + Style.BRIGHT + '\nChave adicionada com sucesso!\n')

            elif option == 2:

                if 'alienvault' in api_names:
                    print('\nJá existe um registro para a chave do OTX Alien Vault.')
                    option = input('Deseja substituir? (S/N)').lower()
                    while (option != 'n' and option != 's') or option == '' :
                        print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                        sleep(1)
                        option = input('\nDeseja substituir? (S/N) ')

                    if option == 's':
                        api_vt = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                        while api_vt == '':
                            print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                            sleep(1)
                            api_vt = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                        overwrite_key('api_keys.txt', 'alienvault', api_vt)

                else:
                    api_vt = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                    while api_vt == '':
                        print(Fore.RED + Style.BRIGHT + 'Valor inválido! Tente novamente.')
                        sleep(1)
                        api_vt = input('\nQual o valor da sua chave de API do OTX Alien Vault? ')
                    
                    file = open('api_keys.txt', 'a+')
                    file.write(f'alienvault:{api_vt}\n')
                    file.close()
                    print(Fore.GREEN + Style.BRIGHT + '\nChave adicionada com sucesso!\n')
                    sleep(1)

            elif option == 9:
                if api_names:
                    file = open('api_keys.txt', 'r')
                    lines = file.readlines()
                    for line in lines:
                        print(line)
                    file.close()
                    sleep(1)

                else:
                    print('O arquivo ainda não contem nenhuma informação.')
                    sleep(1)