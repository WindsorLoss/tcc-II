import requests
from .utils.malware import malware_info
from colorama import Fore, Style, init
init(autoreset=True)

def xfr_get_hash(api, hash):

    response = requests.get(f"https://api.xforce.ibmcloud.com/api/malware/{hash}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    }).json()

    try:

        malware = response['malware']
        origins = malware['origins']
        risco = malware['risk'].upper()
        risco = risco == 'LOW' and Fore.GREEN + f"{risco}" or (risco == 'MEDIUM' and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
        tags = response['tags']

        print(Fore.MAGENTA + Style.BRIGHT + '\n\n-=-=-=- X-FORCE -=-=-=-\n')

        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')  

        print(f'Tipo do arquivo: {malware["type"].upper()}')
        print(f'Risco: {risco}')

        if tags:
            print("Tags:")
            if len(tags) <= 10:
                for i in tags:
                    print(Fore.YELLOW + Style.BRIGHT + f"  -> {i['tag']}")
            else:
                i = 0
                while i < 10:
                    print(Fore.YELLOW + Style.BRIGHT + f"  -> {tags[i]['tag']}")
                    i += 1
                print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(tags) - 10})')

        print(Fore.CYAN + Style.BRIGHT + '\n=== MALWARES ===\n')  

        for i in origins:
            print(f'Origem: {Fore.YELLOW + Style.BRIGHT + i}')
            fonte = origins[i] 
            if i == 'external':

                print(f'Fonte da detecção: {fonte["source"]}')
                print(f'Visto pela primeira vez: {fonte["firstSeen"]}')
                print(f'Visto pela última vez: {fonte["lastSeen"]}')
                print(f'Família do malware: {", ".join(fonte["family"])}')
                print(f'Tipo do malware: {fonte["malwareType"]}')
                print(f'Cobertura da comunidade: {fonte["detectionCoverage"]}%')
                print(f'Plataforma: {fonte["platform"]}')
                if "subPlatform" in fonte:
                    print(f'Sub-plataforma: {fonte["subPlatform"]}')

            elif i != 'external' and not i == 'subjects':
                
                malware_info(origins[i])

    except Exception as e:
        print(e.message, e.args)