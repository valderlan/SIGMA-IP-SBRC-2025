import requests
from datetime import datetime

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

token = '3c538481a94db48a8316f71c736e8af5d19e36ff' # Insira seu token aqui

def buscar_dados():
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    params = {
        'confidenceMinimum': 75,
        'limit': 9999999
    }
    for key in keys:
        headers = {
            'Key': key,
            'Accept': 'application/json'
        }   
        
        print(f"Chave atual: {key}")
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429 or 401: #429 eh limite de requisicao e 401 eh falha de autenticacao
            print(f"Erro {response.status_code} com a chave atual, mudando para a proxima...")
        else:
            print(f"Erro ao buscar dados: {response.status_code}")
            return None

def ip_ja_existe(ip_address):
    url = 'http://localhost:8000/api/blacklist/list/'
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
        print(f"Erro ao acessar a API: {response.status_code}")
        return False  

def inserir_dados_no_postgresql(dados):
    for registro in dados['data']:
        # Formata a data para o padrão aceito pelo PostgreSQL
        data_formatada = datetime.strptime(registro['lastReportedAt'], "%Y-%m-%dT%H:%M:%S+00:00").isoformat()

        if not ip_ja_existe(registro['ipAddress']):
            url = 'http://localhost:8000/api/blacklist/list/'
            headers = {
                'Authorization': f'Token {token}',
                'Content-Type': 'application/json'
            }

            data = {
                'ip_address': registro['ipAddress'],
                'country_code': registro['countryCode'],
                'abuse_confidence_score': registro['abuseConfidenceScore'],
                'last_reported_at': data_formatada 
            }

            response = requests.post(url,headers=headers,json=data)

            if response.status_code == 201:  
                print(f"IP {registro['ipAddress']} inserido com sucesso na API.")
            else:
                print(f"Erro ao inserir IP {registro['ipAddress']} na API:", response.status_code, response.text)

dados = buscar_dados()
if dados:
    inserir_dados_no_postgresql(dados)