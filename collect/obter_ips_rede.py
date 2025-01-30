import subprocess
import psycopg2
import re
import os
import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.getcwd(), "api", ".env"))

token = os.environ.get('token')

db_host = os.environ.get('PG_HOST')
db_name = os.environ.get('PG_DB_LOCAL')
db_user = os.environ.get('PG_USER')
db_password = os.environ.get('PG_PASSWORD')
db_port = os.environ.get('PG_PORT')

def scan_network_local(network):
    # Executa o comando nmap e captura a saída
    result = subprocess.run(['nmap', '-sn', network], capture_output=True, text=True)

    url_api = "http://localhost:8000/api/whitelist/list/"
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    
    # Verifica se o comando foi bem-sucedido
    if result.returncode == 0:
        active_hosts = []
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                # Extrai o IP, removendo parênteses e outros caracteres indesejados
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(0)
                    print(f"ip: {ip}")
                    active_hosts.append(ip)

                    params = {
                        'ip_address': ip
                    }
                    response_api = requests.post(url=url_api, json=params, headers=headers)

                    if response_api.status_code == 201:
                        print(f"IP {ip} foi inserido na whitelist da API com sucesso")
                    else:
                        print(f"Houve um erro ao inserir o IP {ip} na whitelist da API: {response_api.status_code}")


        # Insere os IPs ativos na whitelist do banco local de uma vez
        conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_password, port=db_port)
        cursor = conn.cursor()

        try:
            insert_query = "INSERT INTO wl_address_local (ip_address) VALUES (%s)"
            cursor.executemany(insert_query, [(ip,) for ip in active_hosts])
            
            conn.commit()
            print(f"{len(active_hosts)} hosts ativos inseridos na tabela wl_address_local.")

        except (Exception, psycopg2.DatabaseError) as error:
            print("Erro ao inserir IPs da rede na tabela wl_address_local: ", error)

        cursor.close()
        conn.close()
    else:
        print("Erro ao executar o nmap:", result.stderr)

if __name__ == "__main__":
    faixa = input("Digite sua faixa: ")
    scan_network_local(faixa)


        