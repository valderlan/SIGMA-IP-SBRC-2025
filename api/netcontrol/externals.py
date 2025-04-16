import requests
import os
from dotenv import load_dotenv
import json
import time
import logging

load_dotenv()

API_KEY = json.loads(os.getenv("API_KEY", "[]"))
API_KEY_VIRUSTOTAL = json.loads(os.getenv("API_KEY_VIRUSTOTAL", "[]"))
API_KEY_IPVOID = json.loads(os.getenv("API_KEY_IPVOID", "[]"))
API_KEY_PULSEDIVE = json.loads(os.getenv("API_KEY_PULSEDIVE", "[]"))

logger = logging.getLogger(__name__)

class SearchAbuse:
# Consulta a Blacklist da Abuse
    def buscar_dados_blacklist_abuse():
        # Começa temporizador
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
            
            logger.info(f"Chave atual AbuseIPDB: {key}")
            response = requests.get(url, headers=headers, params=params)
            logger.info(f'Response AbuseIPDB: {response}')

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429 or 401: # 429 é limite de requisição e 401 é falha de autenticação
                logger.error(f"Erro {response.status_code} com a chave atual do AbuseIPDB, mudando para a proxima...")
            else:
                logger.error(f"Erro ao buscar dados do AbuseIPDB: {response.status_code}")
                return None
        
        # Calcula o tempo de execução
        execution_time = time.time() - start_time
        logger.info(f"Tempo pra consultar a Blacklist do AbuseIPDB: {execution_time:.2f} segundos")

    def buscar_dados_abuse(ip_tarpit):
        url_abuse = "https://api.abuseipdb.com/api/v2/check"
        
        params_abuse = {'ipAddress': ip_tarpit.ip_address, 'maxAgeInDays': 15}  # Checar relatórios dos últimos 15 dias

        for key in API_KEY:
            headers_abuse = {'Key': key, 'Accept': 'application/json'}
        
            response_abuse = requests.get(url=url_abuse, headers=headers_abuse, params=params_abuse)
            logger.info(f"Chave atual score AbuseIPDB: {params_abuse}")

            if response_abuse.status_code == 200:
                return response_abuse
            elif response_abuse.status_code == 429 or 401: # 429 é limite de requisição e 401 é falha de autenticação
                logger.error(f"Erro {response_abuse.status_code} com a chave atual do AbuseIPDB, mudando para a proxima...")
            else:
                logger.error(f"Erro ao buscar dados do AbuseIPDB: {response_abuse.status_code}")
                return None
            

class SearchVirusTotal:
    def buscar_dados_virustotal(ip_address):
        url_virus = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'

        for key in API_KEY_VIRUSTOTAL:
            headers_virus = {
                'Accept': 'application/json', 
                'x-apikey': key,
            } 

            logger.info(f'Chave atual do VirusTotal: {key}')

            response_virus = requests.get(url=url_virus, headers=headers_virus)

            if response_virus.status_code == 200:
                logger.info(response_virus.json())
                return response_virus.json()
            elif response_virus.status_code == 429 or 401:
                logger.error(f"Erro ao obter dados do VirusTotal: {response_virus.status_code}")
            else:
                logger.error(f"Erro ao buscar dados: {response_virus.status_code}")
                return None


class SearchIPVoid:
    def buscar_dados_ipvoid(ip_address):
        for key in API_KEY_IPVOID:
            logger.info(f'Usando a chave do IPVoid: {key}')
            
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
                        logging.error(f"Resposta inválida da API do IPVoid: {data}")
                except ValueError:
                    logging.error("Erro ao analisar a resposta JSON do IPVoid.")
            elif response_ipvoid.status_code == 429:
                logging.error(f"Chave do IPVoid esgotada: {key}")
            elif response_ipvoid.status_code == 401:
                logging.error(f"Chave do IPVoid inválida: {key}")
            else:
                logging.error(f"Erro ao buscar dados do IPVoid: {response_ipvoid.status_code} - {response_ipvoid.text}")
        
        # Retornar None caso todas as chaves falhem
        logging.error("Todas as chaves do IPVoid falharam ou foram esgotadas.")
        return None
            

class SearchPulsedive:
    def buscar_dados_pulsedive(ip_address):
        for key in API_KEY_PULSEDIVE:
            url = "https://pulsedive.com/api/info.php"
            params = {
                "key": key,
                "pretty": 1,
                "indicator": ip_address  
            }

            response_pulsedive = requests.get(url, params=params)
            logger.info(f"Chave atual do Pulsedive: {key}")
            
            if response_pulsedive.status_code == 200:
                data = response_pulsedive.json() 
                return data
            elif response_pulsedive.status_code == 429:
                logger.error(f"Erro {response_pulsedive.status_code}: Chave da API do Pulsedive esgotada")
            elif response_pulsedive.status_code == 401:
                logger.error(f"Erro {response_pulsedive.status_code}: Chave da API do Pulsedive é inválida")
            else:
                logger.error(f"Erro ao buscar dados do Pulsedive: {response_pulsedive.status_code}")
                return None  