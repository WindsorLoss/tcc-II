import requests
import base64
from colorama import Fore, Style, init
init(autoreset=True)

def xfr_get_ip(api, ip):

    response = requests.get(f"https://api.xforce.ibmcloud.com/api/ipr/{ip}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    }).json()

    response_malware = requests.get(f"https://api.xforce.ibmcloud.com/api/ipr/malware/{ip}", headers= {
        "Authorization": f"Basic {api}",
        "accept": "application/json"
    }).json()

    try:

        print(Fore.MAGENTA + Style.BRIGHT + '\n\n-=-=-=- X-FORCE -=-=-=-\n')
        print(Fore.CYAN + Style.BRIGHT + '\n=== DETALHES ===\n')

        print(f'País: {response["geo"]["country"]}\n')

        print('Sub-redes:')
        subnets = response['subnets']
        for i in subnets:
            print(Fore.YELLOW + Style.BRIGHT + f'  -> {i["subnet"]}')
            if "geo" in i:
                print(f'     País: {i["geo"]["country"]}')

            for j in i["asns"].keys():
                print(f'     ASN: {j}')
                if "Company" in i["asns"][j]:
                    print(f'     Companhia: {i["asns"][j]["Company"]}')


            risco = i["score"]
            risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
            print(Style.BRIGHT + f'     Risco: {risco}\n')
        
        risco = response["score"]
        risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
        print(f'Risco do IP: {risco}')
        print(f'Motivo: {response["reason"]}\n')

        tags = response["tags"]
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

        print(Fore.CYAN + Style.BRIGHT + '\n=== HISTÓRICO DE DETECÇÕES ===\n')

        historico = response["history"]
        historico.sort(key=lambda dict: dict["score"], reverse=True)

        if len(historico) <= 10:
            for i in historico:
                dia, hora = i["created"].split('T')
                dia = '-'.join(list(reversed(dia.split('-'))))
                hora = hora.split('.')[0]
                print(Fore.YELLOW + Style.BRIGHT + f'Data da detecção: {dia}, às {hora}')

                if "malware_extended" in i:
                    malware, *resto = i['malware_extended'].keys()
                    print(Fore.RED + Style.BRIGHT + f'{malware}: {i["malware_extended"][malware]}')

                risco = i["score"]
                risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
                print(Style.BRIGHT + f'Risco: {risco}')
                print(f'Motivo: {i["reason"]}\n')

        else:
            i = 0
            while i < 10:
                dia, hora = historico[i]["created"].split('T')
                dia = '-'.join(list(reversed(dia.split('-'))))
                hora = hora.split('.')[0]
                print(Fore.YELLOW + Style.BRIGHT + f'Data da detecção: {dia}, às {hora}')

                if "malware_extended" in historico[i]:
                    malware, *resto = historico[i]['malware_extended'].keys()
                    print(Fore.RED + Style.BRIGHT + f'{malware}: {historico[i]["malware_extended"][malware]}')

                risco = historico[i]["score"]
                risco = risco < 4 and Fore.GREEN + f"{risco}" or (risco < 7 and Fore.YELLOW + f"{risco}" or Fore.RED + f"{risco}")
                print(Style.BRIGHT + f'Risco: {risco}')
                print(f'Motivo: {historico[i]["reason"]}\n')
                
                i += 1

            print(Fore.YELLOW + Style.BRIGHT + f'-> Entre outras ({len(historico) - 10})')


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