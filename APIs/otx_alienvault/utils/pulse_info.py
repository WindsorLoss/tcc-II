from colorama import Fore, Style, init
init(autoreset=True)

def alv_pulse_info(response):
    print(Fore.CYAN + Style.BRIGHT + '\n=== PULSES ===\n')
        
    pulse_count = response["pulse_info"]["count"]
    if pulse_count == 0:
        pulse_count = Fore.GREEN + f"{pulse_count}"
    elif pulse_count > 0 and pulse_count <= 10:
        pulse_count = Fore.YELLOW + f"{pulse_count}"
    else:
        pulse_count = Fore.RED + f"{pulse_count}"
    print(f'Quantidade de Pulse Reports: {pulse_count}') 

    pulse_references = response['pulse_info']['references']
    if pulse_references:
        print("Referências do Pulse:")
        if len(pulse_references) <= 10:
            for i in pulse_references:
                print(Fore.YELLOW + Style.BRIGHT + f"  -> {i}")
        else:
            i = 0
            while i < 10:
                print(Fore.YELLOW + Style.BRIGHT + f"  -> {pulse_references[i]}")
                i += 1
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(pulse_references) - 10})')

    related = response['pulse_info']['related']

    if related['alienvault']['malware_families']:
        print("Familias de malware identificadas pelo Alien Vault:")

        if len(related['alienvault']['malware_families']) <= 10:
            for i in related['alienvault']['malware_families']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')
        else:
            i = 0
            while i < 10:
                print(Fore.YELLOW + Style.BRIGHT + f"  -> {related['alienvault']['malware_families'][i]}")
                i += 1
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(related["alienvault"]["malware_families"]) - 10})')

    if related['other']['malware_families']:
        print("\nFamilias de malware identificadas por outras ferramentas:")

        if len(related['other']['malware_families']) <= 10:
            for i in related['other']['malware_families']:
                print(Fore.YELLOW + Style.BRIGHT + f'  -> {i}')
        else:
            i = 0
            while i < 10:
                print(Fore.YELLOW + Style.BRIGHT + f"  -> {related['other']['malware_families'][i]}")
                i += 1
            print(Fore.YELLOW + Style.BRIGHT + f'  -> Entre outras ({len(related["other"]["malware_families"]) - 10})')
