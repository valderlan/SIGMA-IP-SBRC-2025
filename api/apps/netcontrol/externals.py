import requests
import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()

# Carregar chaves das variáveis de ambiente
API_KEY_ABUSE = json.loads(os.getenv("API_KEY", "[]"))
API_KEY_VIRUSTOTAL = json.loads(os.getenv("API_KEY_VIRUSTOTAL", "[]"))
API_KEY_IPVOID = json.loads(os.getenv("API_KEY_IPVOID", "[]"))
API_KEY_PULSEDIVE = json.loads(os.getenv("API_KEY_PULSEDIVE", "[]"))

# Setup de logger
logger = logging.getLogger(__name__)


class SearchAbuse:
    @staticmethod
    def buscar_blacklist_abuse():
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        params = {'confidenceMinimum': 75, 'limit': 9999999}

        for key in API_KEY_ABUSE:
            headers = {'Key': key, 'Accept': 'application/json'}

            try:
                response = requests.get(url, headers=headers, params=params)
                logger.info(f"Response AbuseIPDB: {response}")

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(f"Erro {response.status_code} com a chave do AbuseIPDB, tentando próxima...")
                    continue
                else:
                    logger.error(f"Erro inesperado AbuseIPDB: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta AbuseIPDB: {str(e)}")
                continue

        logger.error("Todas as chaves do AbuseIPDB falharam.")
        return None

    @staticmethod
    def buscar_dados_abuse(ip_address):
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {'ipAddress': ip_address, 'maxAgeInDays': 15}

        for key in API_KEY_ABUSE:
            headers = {'Key': key, 'Accept': 'application/json'}

            try:
                response = requests.get(url, headers=headers, params=params)
                logger.info(f"Response AbuseIPDB Check: {response}")

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(f"Erro {response.status_code} na chave do AbuseIPDB Check, tentando próxima...")
                    continue
                else:
                    logger.error(f"Erro inesperado AbuseIPDB Check: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta AbuseIPDB Check: {str(e)}")
                continue

        logger.error("Todas as chaves do AbuseIPDB Check falharam.")
        return None


class SearchVirusTotal:
    @staticmethod
    def buscar_dados_virustotal(ip_address):
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'

        for key in API_KEY_VIRUSTOTAL:
            headers = {'Accept': 'application/json', 'x-apikey': key}

            try:
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(f"Erro {response.status_code} na chave do VirusTotal, tentando próxima...")
                    continue
                else:
                    logger.error(f"Erro inesperado VirusTotal: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta VirusTotal: {str(e)}")
                continue

        logger.error("Todas as chaves do VirusTotal falharam.")
        return None


class SearchIPVoid:
    @staticmethod
    def buscar_dados_ipvoid(ip_address):
        url = "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/"

        for key in API_KEY_IPVOID:
            params = {'key': key, 'ip': ip_address}

            try:
                response = requests.get(url, params=params)

                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and 'report' in data['data'] and 'blacklists' in data['data']['report']:
                        return data
                    else:
                        logger.error(f"Resposta inválida IPVoid: {data}")
                        return None
                elif response.status_code in (429, 401):
                    logger.error(f"Erro {response.status_code} na chave do IPVoid, tentando próxima...")
                    continue
                else:
                    logger.error(f"Erro inesperado IPVoid: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta IPVoid: {str(e)}")
                continue

        logger.error("Todas as chaves do IPVoid falharam.")
        return None


class SearchPulsedive:
    @staticmethod
    def buscar_dados_pulsedive(ip_address):
        url = "https://pulsedive.com/api/info.php"

        for key in API_KEY_PULSEDIVE:
            params = {
                "key": key,
                "indicator": ip_address,
                "pretty": 1
            }

            try:
                response = requests.get(url, params=params)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(f"Erro {response.status_code} na chave do Pulsedive, tentando próxima...")
                    continue
                else:
                    logger.error(f"Erro inesperado Pulsedive: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta Pulsedive: {str(e)}")
                continue

        logger.error("Todas as chaves do Pulsedive falharam.")
        return None
