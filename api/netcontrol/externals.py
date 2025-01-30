import requests
import os
from dotenv import load_dotenv
import json
import time

load_dotenv()

API_KEY = json.loads(os.getenv("API_KEY", "[]"))
API_KEY_VIRUSTOTAL = json.loads(os.getenv("API_KEY_VIRUSTOTAL", "[]"))
API_KEY_IPVOID = json.loads(os.getenv("API_KEY_IPVOID", "[]"))
API_KEY_PULSEDIVE = json.loads(os.getenv("API_KEY_PULSEDIVE", "[]"))

keys = [
        "131a7051f53083c099a23c17d0396e62e11c58487e3039c21a1c51bdd92752cb4056f9975ad22770",
        "b1a00dfc5c78fbcb1e425d73023371aea5197480e15ec8779d613c5a57296850e71afa7f306df83d",
        "5c0eca389148f18627fcd9cb495f2a3cecfbc135ee41548ba4763374817d7f4dfcb8602b6c380d3b",
        "8993ce81b68e2c70c0862f45256bf48e9edc1af1de365d4c89050aefa155db16b4aadfb76fc3bc8c",
        "6ed38b00c1c47176fab21de3755b75c5c2f94aaca34eafc0a8b85a76f0c45a7f8be6f0071165d3b3",
        "b44738ec716cd82d22375a9e9113b5331e7bc88b63216e0912a5652c148ddc000649e9bdad63ac29",
        "64c03a20ca49a6c31b8e0430a7204bd278a8e9a56e3bce30636f23f2583792d73e871143aa23ee2f",
        "58a7ccccb02cd523dc8f80fe255069cf716b87dc46fc411c3226a15093318679679563ad9071c477",
        "92e9a91b1da722d4f920c8c31f959c81f3c97934f283f4bbe67908649df14c0749ce947a903fa22e",
        "ade4e36ed2f1eb7545407cf635b1be2ff413585dcb172561c9334106876cb2ebd0a07b7db63fab1c",
    ]


class SearchAbuse:
    def __init__(self, ip_tarpit):
        self.ip_tarpit = ip_tarpit

    #Consulta a Blacklist da Abuse
    def buscar_dados():
        #Começa temporizador
        start_time = time.time()

        url = "https://api.abuseipdb.com/api/v2/blacklist"
        params = {
            'confidenceMinimum': 75,
            'limit': 9999999
        }
        for key in API_KEY:
            headers = {
                'Key': key,
                'Accept': 'application/json'
            }   
            
            print(f"Chave atual: {key}")
            response = requests.get(url, headers=headers, params=params)
            print(f'Response task: {response}')

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429 or 401: #429 é limite de requisição e 401 é falha de autenticação
                print(f"Erro {response.status_code} com a chave atual, mudando para a proxima...")
            else:
                print(f"Erro ao buscar dados: {response.status_code}")
                return None
        
        # Calcula o tempo de execução
        execution_time = time.time() - start_time
        print(f"Tempo pra consultar a Blacklist do ABUSEAPI: {execution_time:.2f} segundos")

    def buscar_score(ip_tarpit):
        url_abuse = "https://api.abuseipdb.com/api/v2/check"
        
        params_abuse = {'ipAddress': ip_tarpit.ip_address, 'maxAgeInDays': 15}  # Checar relatórios dos últimos 15 dias

        for key in API_KEY:
        # url_abuse = "https://api.abuseipdb.com/api/v2/check"
        # headers_abuse = {'Key': API_KEY, 'Accept': 'application/json'}
        # params_abuse = {'ipAddress': ip_tarpit.ip_address, 'maxAgeInDays': 15}  # Checar relatórios dos últimos 15 dias
            headers_abuse = {'Key': key, 'Accept': 'application/json'}
        
            response_abuse = requests.get(url=url_abuse, headers=headers_abuse, params=params_abuse)
            print(f"Chave atual score: {params_abuse}")

            if response_abuse.status_code == 200:
                return response_abuse
            elif response_abuse.status_code == 429 or 401: # 429 é limite de requisição e 401 é falha de autenticação
                print(f"Erro {response_abuse.status_code} com a chave atual, mudando para a proxima...")
            else:
                print(f"Erro ao buscar dados: {response_abuse.status_code}")
                return None
            
class SearchVirusTotal:
    def buscar_dados(ip_address):
        url_virus = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'

        for key in API_KEY_VIRUSTOTAL:
            print(f'key: {key}')
            headers_virus = {
                'Accept': 'application/json', 
                'x-apikey': key,
            }   

            response_virus = requests.get(url=url_virus, headers=headers_virus)

            if response_virus.status_code == 200:
                return response_virus.json()
            elif response_virus.status_code == 429 or 401:
                print(f"Erro ao obter dados do VirusTotal: {response_virus.status_code}")
            else:
                print(f"Erro ao buscar dados: {response_virus.status_code}")
                return None

class SearchIpVoid:
    def buscar_dados(ip_address):
        for key in API_KEY_IPVOID:
            print(f'Usando a chave: {key}')
            
            url_ipvoid = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/"
            params_ipvoid = {
                'key': key,
                'ip': ip_address
            }

            response_ipvoid = requests.get(url=url_ipvoid, params=params_ipvoid)
            
            if response_ipvoid.status_code == 200:
                try:
                    data = response_ipvoid.json()
                    if 'data' in data and 'report' in data['data'] and 'blacklists' in data['data']['report']:
                        return data
                    else:
                        print(f"Resposta inválida da API do IPVoid: {data}")
                except ValueError:
                    print("Erro ao analisar a resposta JSON.")
            elif response_ipvoid.status_code == 429:
                print(f"Chave esgotada: {key}")
            elif response_ipvoid.status_code == 401:
                print(f"Chave inválida: {key}")
            else:
                print(f"Erro ao buscar dados do IPVoid: {response_ipvoid.status_code} - {response_ipvoid.text}")
        
        # Retornar None caso todas as chaves falhem
        print("Todas as chaves falharam ou foram esgotadas.")
        return None
            
class SearchPulsedive:
    def buscar_dados(ip_address):
        for key in API_KEY_PULSEDIVE:
            url = "https://pulsedive.com/api/info.php"
            params = {
                "key": key,
                "pretty": 1,
                "indicator": ip_address  
            }

            response_pulsedive = requests.get(url, params=params)
            print(key)
            
            if response_pulsedive.status_code == 200:
                data = response_pulsedive.json() 
                return data
            elif response_pulsedive.status_code == 429:
                print(f"Erro {response_pulsedive.status_code}: Chave da API do Pulsedive esgotada")
            elif response_pulsedive.status_code == 401:
                print(f"Erro {response_pulsedive.status_code}: Chave da API do Pulsedive é inválida")
            else:
                print(f"Erro ao buscar dados do Pulsedive: {response_pulsedive.status_code}")
                return None  