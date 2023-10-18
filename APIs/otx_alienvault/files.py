import requests
from colorama import Fore, Style, init
from .hash import alv_get_hash
from time import sleep
init(autoreset=True)

def alv_get_file(api, file):


    response_submit_file = requests.post(f'https://otx.alienvault.com/api/v1/indicators/submit_file',
        files={
            'file': file,
            'Content-type': 'multipart/form-data'
        },
        headers={
            'X-OTX-API-KEY': api,
        }).json()
    
    response_submitted_file = requests.get(f'https://otx.alienvault.com/api/v1/indicators/submitted_files', 
        headers={
            'X-OTX-API-KEY': api
        }).json()
    
    isComplete = response_submitted_file["results"][0]["complete_date"]

    while not isComplete:
        sleep(10)
        response_submitted_urls = requests.get(f'https://otx.alienvault.com/api/v1/indicators/submitted_files', 
        headers={
            'X-OTX-API-KEY': api
        }).json() 

        isComplete = response_submitted_file["results"][0]["complete_date"]

    alv_get_hash(api, response_submitted_file["results"][0]["sha256"])
