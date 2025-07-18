import requests
import os
import logging
import json
from datetime import datetime
from dotenv import load_dotenv

script_dir = os.path.dirname(os.path.abspath(__file__))         
DOTENV_PATH = os.path.join(os.path.dirname(__file__), "..", "api", ".env")      

load_dotenv(DOTENV_PATH)

token = os.environ.get('token')

API_KEY = json.loads(os.getenv("API_KEY", "[]"))
API_KEY_VIRUSTOTAL = json.loads(os.getenv("API_KEY_VIRUSTOTAL", "[]"))
API_KEY_IPVOID = json.loads(os.getenv("API_KEY_IPVOID", "[]"))
API_KEY_PULSEDIVE = json.loads(os.getenv("API_KEY_PULSEDIVE", "[]"))

# Função para logging
def setup_logging():
    """
    Configura o logging para a aplicação
    """

    # Configuração básica do logging (apenas para terminal)
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


def buscar_dados():
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
        
        logger.info(f"Chave atual: {key}")
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429 or 401: # 429 é limite de requisicao e 401 é falha de autenticacao
            logger.error(f"Erro {response.status_code} com a chave atual, mudando para a proxima...")
        else:
            logger.error(f"Erro ao buscar dados: {response.status_code}")
            return None

def ip_ja_existe(ip_address):
    url = 'http://localhost:8001/api/blacklist/'
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    response = requests.get(url,headers=headers)
    if response.status_code == 200:
        data = response.json()
        for ips in data['results']:
            if ips['ip_address'] == ip_address:
                return True 
        return False
    else:
        logger.error(f"Erro ao acessar a API: {response.status_code}")
        return False  

def inserir_dados_no_postgresql(dados):
    try:
        for registro in dados['data']:
            # Formata a data para o padrão aceito pelo PostgreSQL
            data_formatada = datetime.strptime(registro['lastReportedAt'], "%Y-%m-%dT%H:%M:%S+00:00").isoformat()

            if not ip_ja_existe(registro['ipAddress']):
                url = 'http://localhost:8001/api/blacklist/'
                headers = {
                    'Authorization': f'Token {token}',
                    'Content-Type': 'application/json'
                }

                data = {
                    'ip_address': registro['ipAddress'],
                    'country_code': registro['countryCode'],
                    'abuseipdb_confidence_score': registro['abuseConfidenceScore'],
                    'last_reported_at': data_formatada 
                }

                response = requests.post(url,headers=headers,json=data)

                if response.status_code == 201:  
                    logger.info(f"IP {registro['ipAddress']} inserido com sucesso na API.")
                else:
                    logger.error(f"Erro ao inserir IP {registro['ipAddress']} na API:", response.status_code, response.text)

    except (Exception) as error:
        logger.error(f'Erro ao atualizar blacklist com dados do AbuseIPDB: {error}')

if __name__ == "__main__":
    logger = setup_logging()

    dados = buscar_dados()
    if dados:
        inserir_dados_no_postgresql(dados)