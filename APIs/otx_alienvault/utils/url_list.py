from colorama import Fore, Style, init
init(autoreset=True)

def alv_url_list(response):
    if len(response['url_list']) > 0:
        print(Fore.CYAN + Style.BRIGHT + '\n=== LISTA DE URLS ===\n')

        if len(response['url_list']) <= 10:
            for i in response['url_list']:
                print(Fore.YELLOW + Style.BRIGHT + f"-> {i['url']}")
                if 'httpcode' in i:
                    print(f"Status Code: {i['httpcode']}\n")
        else:
            i = 0
            while i < 10:
                print(Fore.YELLOW + Style.BRIGHT + f"-> {i['url']}")
                if 'httpcode' in i:
                    print(f"Status Code: {i['httpcode']}\n")
                i += 1
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(response["url_list"]) - 10})')