import requests
import urllib.parse 
from colorama import Fore, Style, init
from time import ctime, sleep
from .hash import vt_get_hash
init(autoreset=True)


def vt_get_file(api, file_path = None):

    if not file_path:
        file_path = input('\nCaminho do arquivo: ')
        while file_path == "":
            print(Fore.RED + Style.BRIGHT + 'Valor inválido. Tente novamente.')
            sleep(1)
            file_path = input('\nCaminho do arquivo: ')

    response_upload = requests.post("https://www.virustotal.com/api/v3/files", 
        files = {"file": open(file_path, "rb")}, 
        headers= {
            "accept": "application/json",
            "x-apikey": api
        }).json()

    id_upload = urllib.parse.quote(response_upload['data']['id'])

    response_analyses = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id_upload}", 
        headers={
            "accept": "application/json",
            "x-apikey": api
        }).json()

    id_analyses = response_analyses['meta']['file_info']['sha256']
    sleep(10)
    vt_get_hash(api, id_analyses)
    