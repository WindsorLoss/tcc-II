import requests
import base64
from colorama import Fore, Style, init
init(autoreset=True)

def xfr_get_ip():

    key = "5a2aeec4-48ad-4883-9c15-8db98c93b508"
    password ="a04c3263-8993-41d4-b93b-9a9b12b47105"

    data_string = (f"{key}:{password}")
    data_bytes = data_string.encode("utf-8")
    token = base64.b64encode(data_bytes)
    token = f"{token}".split("'")[1]
    ip = '68.178.163.67'
    ip2 = '8.8.8.8'

    response = requests.get(f"https://api.xforce.ibmcloud.com/api/ipr/{ip}", headers= {
        "Authorization": f"Basic {token}",
        "accept": "application/json"
    }).json()

    # response_history = requests.get(f"https://api.xforce.ibmcloud.com/api/ipr/history/{ip}", headers= {
    #     "Authorization": f"Basic {token}",
    #     "accept": "application/json"
    # }).json()

    response_malware = requests.get(f"https://api.xforce.ibmcloud.com/api/ipr/malware/{ip}", headers= {
        "Authorization": f"Basic {token}",
        "accept": "application/json"
    }).json()

    try:

        print(Fore.MAGENTA + Style.BRIGHT + '\n-=-=-=- X-FORCE -=-=-=-\n')
        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

        print(f'País: {response["geo"]["country"]}')

        print(Fore.CYAN + Style.BRIGHT + '\n=== HISTÓRICO ===\n')



        malware = response_malware['malware']
        if malware:
            print(Fore.CYAN + Style.BRIGHT + '\n=== MALWARES ===\n')

            print('Quantidade total de detecções: ' + Fore.RED + Style.BRIGHT + f'{len(malware)}\n')

            print(Fore.YELLOW + Style.BRIGHT + "Detecções:\n")
            if len(malware) <= 10:
                for i in malware:
                    print(Fore.YELLOW + Style.BRIGHT + f"Tipo do malware: {i['type']}")
                    print(f"MD5: {i['md5']}")
                    print(f"URI: {i['uri']}")
                    print(f"Schema: {i['schema']}")
                    print(f"Família de malware(s): {', '.join(i['family'])}")
                    print("Contagem de detecções: " + Fore.RED + Style.BRIGHT + f"{i['count']}\n")
            else:
                i = 0
                while i < 10:
                    print(Fore.YELLOW + Style.BRIGHT + f"Tipo do malware: {malware[i]['type']}")
                    print(f"MD5: {malware[i]['md5']}")
                    print(f"URI: {malware[i]['uri']}")
                    print(f"Schema: {malware[i]['schema']}")
                    print(f"Família de malware(s): {', '.join(malware[i]['family'])}")
                    print("Contagem de detecções: " + Fore.RED + Style.BRIGHT + f"{malware[i]['count']}\n")
                    i += 1
            print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(malware) - 10})')


    except Exception as e:
        print(e.message, e.args)


xfr_get_ip()
