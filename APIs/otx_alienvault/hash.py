import requests
from colorama import Fore, Style, init
from .utils.pulse_info import alv_pulse_info
from time import sleep
init(autoreset=True)

def alv_get_hash(api, hash):

    response_general = requests.get(f'https://otx.alienvault.com/api/v1/indicator/file/{hash}/general', 
    headers={
        'X-OTX-API-KEY': api
    }).json()

    response_analysis = requests.get(f'https://otx.alienvault.com/api/v1/indicator/file/{hash}/analysis', 
    headers={
        'X-OTX-API-KEY': api
    }).json()

    try:
        
        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- OTX Alien Vault -=-=-=-\n')

        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

        print(f'Título do tipo: {response_general["type_title"]}')

        file_type = response_analysis['analysis']['info']['results']
        if file_type["file_type"]:
            print(f'Tipo do arquivo: {file_type["file_type"]}')
        if file_type["file_class"]:
            print(f'Título do tipo: {file_type["file_class"]}')


        print(Fore.CYAN + Style.BRIGHT + '\n=== HASHES ===\n')

        print(f'Tipo do hash do IOC: {response_general["type"]}')
        print('Outras hashes deste IOC:')
        hashes = response_analysis['analysis']['info']['results']
        if hashes['md5']:
            print(Fore.YELLOW + Style.BRIGHT + f'  -> MD5: {hashes["md5"]}')

        if hashes['sha1']:
            print(Fore.YELLOW + Style.BRIGHT + f'  -> SHA1: {hashes["sha1"]}')

        if hashes['sha256']:
            print(Fore.YELLOW + Style.BRIGHT + f'  -> sha256: {hashes["sha256"]}')

        if hashes['sha1']:
            print(Fore.YELLOW + Style.BRIGHT + f'  -> SHA1: {hashes["sha1"]}')


        # ----------------- PULSE INFO -----------------

        alv_pulse_info(response_general)

        print(Fore.CYAN + Style.BRIGHT + '\n=== MALWARES ===\n')

        plugins = response_analysis["analysis"]["plugins"]
        for i in plugins:
            if i != "peanomal" and "results" in plugins[i] and "detection" in plugins[i]["results"] and plugins[i]["results"]["detection"]:
                print(Fore.YELLOW + Style.BRIGHT + f'Plugin: {i}')
                print(f'Detecção: {plugins[i]["results"]["detection"]}\n')


    except Exception as e:
        print(e.message, e.args)


