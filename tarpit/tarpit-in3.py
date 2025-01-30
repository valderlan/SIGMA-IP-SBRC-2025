import requests
import psycopg2
import re
import os
from datetime import datetime, timezone
from ipaddress import ip_address

# Dados de conexão ao banco de dados
db_host = 'localhost'
db_name = 'firewall'
db_user = 'admin'
db_password = 'Q1w2e3r4'

# Chave da API do AbuseIPDB
API_KEY = os.getenv('API_KEY')

def e_ip_privado(ip):
    return ip_address(ip).is_private

def obter_ips_para_checar():
    conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
    cursor = conexao.cursor()
    # Ajuste aqui para incluir country_code e city
    cursor.execute("SELECT DISTINCT src_ip, src_country_code, src_city, src_longitude, src_latitude FROM network_traffic;")
    resultados = cursor.fetchall()
    cursor.close()
    conexao.close()
    # Ajuste a compreensão de lista para incluir country_code e city
    return [(resultado[0], resultado[1], resultado[2], resultado[3], resultado[4]) for resultado in resultados if not e_ip_privado(resultado[0])]


def ip_ja_existe_na_tp(ip_address):
    conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
    cursor = conexao.cursor()
    cursor.execute("SELECT 1 FROM tp_address_local WHERE ip_address = %s;", (ip_address,))
    existe = cursor.fetchone() is not None
    cursor.close()
    conexao.close()
    return existe

def ip_existe_na_bl_local_cache(ip_address):
    conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
    cursor = conexao.cursor()
    cursor.execute("SELECT 1 FROM bl_local_cache WHERE ip_address = %s;", (ip_address,))
    existe = cursor.fetchone() is not None
    cursor.close()
    conexao.close()
    return existe

def ip_existe_na_bl_address_local(ip_address):
    conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
    cursor = conexao.cursor()
    cursor.execute("SELECT 1 FROM bl_address_local WHERE ip_address = %s;", (ip_address,))
    existe = cursor.fetchone() is not None
    cursor.close()
    conexao.close()
    return existe

def inserir_na_bl_address_local(ip_address, country_code, city, src_longitude, src_latitude):
    conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
    cursor = conexao.cursor()
    comando_sql = """
    INSERT INTO bl_address_local (ip_address, country_code, city, src_longitude, src_latitude)
    VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(comando_sql, (ip_address, country_code, city, src_longitude, src_latitude))
    conexao.commit()
    cursor.close()
    conexao.close()
    print(f"IP {ip_address} com localização (País: {country_code}, Cidade: {city}, Longitude: {src_longitude}, Latitude: {src_latitude}) inserido na tabela bl_address_local.")

def checar_reputacao_ip_e_inserir(ip_address, src_longitude, src_latitude):
    if ip_ja_existe_na_tp(ip_address):
        print(f"IP {ip_address} já existe na tabela tp_address_local.")
        return

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 15, 'verbose': ''}

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        dados = response.json()['data']
        inserir_dados_no_postgresql(dados, src_longitude, src_latitude)
    else:
        print(f"Erro ao checar IP {ip_address}: {response.status_code}")

def ip_valido(ip):
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return pattern.match(ip) is not None

def inserir_dados_no_postgresql(dados, src_longitude, src_latitude):
    conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
    cursor = conexao.cursor()

    if not ip_valido(dados['ipAddress']):
        print(f"Endereço IP inválido ou não é IPv4: {dados['ipAddress']}")
        return

    comando_sql = """
    INSERT INTO tp_address_local (ip_address, country_code, abuse_confidence_score, last_reported_at, src_longitude, src_latitude)
    VALUES (%s, %s, %s, %s, %s, %s)
    """

    data_report = dados.get('lastReportedAt')
    if data_report:
        data_formatada = datetime.strptime(data_report, "%Y-%m-%dT%H:%M:%S+00:00")
    else:
        data_formatada = datetime.now(timezone.utc)

    cursor.execute(comando_sql, (dados['ipAddress'], dados['countryCode'], dados['abuseConfidenceScore'], data_formatada, src_longitude, src_latitude))

    conexao.commit()
    cursor.close()
    conexao.close()
    print(f"Dados inseridos com sucesso para o IP: {dados['ipAddress']}")

def main():
    ips_para_checar = obter_ips_para_checar()
    for ip, country_code, city, longitude, latitude in ips_para_checar:
        if ip_existe_na_bl_local_cache(ip):
            if not ip_existe_na_bl_address_local(ip):
                inserir_na_bl_address_local(ip, country_code, city, longitude, latitude)
            else:
                print(f"IP {ip} já existe na tabela bl_address_local, pulando inserção.")
        else:
            checar_reputacao_ip_e_inserir(ip, longitude, latitude)

if __name__ == "__main__":
    main()
