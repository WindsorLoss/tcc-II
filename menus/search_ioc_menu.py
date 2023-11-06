from colorama import Fore, Back, Style, init
from APIs.virus_total.ip_addresses import vt_get_ip
from APIs.otx_alienvault.ip_addresses import alv_get_ip
from APIs.ibm_xforce.ip_addresses import xfr_get_ip
from APIs.virus_total.url import vt_get_url
from APIs.otx_alienvault.url import alv_get_url
from APIs.ibm_xforce.url import xfr_get_url
from APIs.virus_total.hash import vt_get_hash
from APIs.otx_alienvault.hash import alv_get_hash
from APIs.ibm_xforce.hash import xfr_get_hash
from menus.functions.keys_organizer import keys_organizer
from menus.functions.file_to_hash import file_to_hash
from menus.functions.ip_checker import ip_checker
from menus.functions.url_checker import url_checker
from time import sleep
import os


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

        try:
            option = int(input('Opção: '))

            if option < 0 or option > 4:
                print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')

            elif option == 0:
                print('\nVoltando...\n')
                break

            elif option == 1:
                file = input('\nCaminho do arquivo: ')
                file = "\\\\".join(file.split('\\'))
                while file == "" or not os.path.isfile(file):
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    file = input('\nCaminho do arquivo: ')
                    file = "\\\\".join(file.split('\\'))

                hash = file_to_hash(file)
                print(hash)
                vt_get_hash(api_keys[api_names.index('virustotal')], hash)
                alv_get_hash(api_keys[api_names.index('alienvault')], hash)
                xfr_get_hash(api_keys[api_names.index('xforce')], hash)
            
            elif option == 2:
                hash = input('\nDigite a hash: ')
                while hash == "":
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    hash = input('\nDigite a hash: ')

                vt_get_hash(api_keys[api_names.index('virustotal')], hash)
                alv_get_hash(api_keys[api_names.index('alienvault')], hash)
                xfr_get_hash(api_keys[api_names.index('xforce')], hash)
            
            elif option == 3:        
                ip_addr = input('\nDigite o IP: ')
                while ip_addr == "" or not ip_checker(ip_addr):
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    ip_addr = input('\nDigite o IP: ')

                vt_get_ip(api_keys[api_names.index('virustotal')], ip_addr)
                alv_get_ip(api_keys[api_names.index('alienvault')], ip_addr)
                xfr_get_ip(api_keys[api_names.index('xforce')], ip_addr)

            elif option == 4:
                url = input('\nDigite a URL: ')
                while url == "" or not url_checker(url):
                    print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
                    sleep(1)
                    url = input('\nDigite a URL: ')
                vt_get_url(api_keys[api_names.index('virustotal')], url)
                alv_get_url(api_keys[api_names.index('alienvault')], url)
                xfr_get_url(api_keys[api_names.index('xforce')], url)

        except: 
            print(Fore.RED + Style.BRIGHT + '\nOpção inválida, tente novamente.')
            sleep(1)

