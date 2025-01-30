import json
from scapy.all import sniff, IP, TCP
from geoip2.database import Reader
import datetime
import ipaddress
import requests
import psycopg2
import os
import time  
from dotenv import load_dotenv
import subprocess
import tarpitrule5
import whitelist_rules
import blacklist_rules
import csv

load_dotenv(os.path.join(os.getcwd(), "api", ".env"))

token = os.environ.get('token')

# Configurações do banco local
db_host = os.environ.get('PG_HOST')
db_name = os.environ.get('PG_DB_LOCAL')
db_user = os.environ.get('PG_USER')
db_password = os.environ.get('PG_PASSWORD')
db_port = os.environ.get('PG_PORT')

# Conexão com o banco local
conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_password, port=db_port)
cur = conn.cursor()
cur.execute("SET TIMEZONE TO 'America/Fortaleza';")

# Determinar o diretório onde o script está localizado (pasta collect)
base_dir = os.path.dirname(os.path.abspath(__file__))

# Construir o caminho absoluto para o arquivo JSON
path = os.path.join(base_dir, "mappings.json")

# Escreve o CSV no visualizer
visualizer_dir = os.path.join(base_dir, "..", "visualizer")

# Garantir que o diretório visualizer existe
if not os.path.exists(visualizer_dir):
    os.makedirs(visualizer_dir)

# Carregar mapeamentos de protocolo e serviço a partir de um arquivo JSON
with open(path, 'r') as f:
    mappings = json.load(f)

protocol_mapping = {int(k): v for k, v in mappings["protocol_mapping"].items()}
service_mapping = {int(k): v for k, v in mappings["service_mapping"].items()}

# Arquivo CSV contendo as temporizações
csv_file = os.path.join(visualizer_dir, "execution_times.csv")

# Cabeçalho do CSV
header = ["src_ip", "dst_ip", "src_tempo_checagem_iptables",
        "src_tempo_checagem_wl_local", "src_tempo_resposta_api", "src_tempo_checagem_api", 
        "src_tempo_aplicar_regras_blacklist", "src_tempo_aplicar_regras_whitelist",
        "dst_tempo_checagem_iptables", "dst_tempo_checagem_wl_local", 
        "dst_tempo_resposta_api", "dst_tempo_checagem_api", 
        "dst_tempo_aplicar_regras_blacklist", "dst_tempo_aplicar_regras_whitelist",
        "tempo_inserir_network_traffic", "tempo_detecção_conexao"
        ]

# Função para escrever no CSV
def write_to_csv(data):
    # Se o arquivo não existir, cria o arquivo e escreve o cabeçalho
    file_exists = os.path.exists(csv_file)
    with open(csv_file, mode="a", newline="") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(header)  # Escreve o cabeçalho
        writer.writerow(data)

# Função para obter as informações de protocolo
def get_protocol_info(packet):
    protocol_code = packet[IP].proto
    protocol_name = protocol_mapping.get(protocol_code, 'Unknown')
    return protocol_code, protocol_name

# Função para obter as informações de serviço
def get_service_info(packet):
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    src_service = service_mapping.get(src_port, 'Unknown')
    dst_service = service_mapping.get(dst_port, 'Unknown')
    return src_service, dst_service

# Função para obter latitude, longitude e country code
def get_geo_info(ip_address):
    try:
        with Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            country_code = response.country.iso_code
            city = response.city.name
            latitude = response.location.latitude
            longitude = response.location.longitude

            return country_code, city, latitude, longitude
    except Exception as e:
        print(f"Error getting geo info for {ip_address}: {e}")
        return None, None, None, None  # Valores padrão

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

# A checagem se o IP está na whitelist é com o banco local
def ip_existe_na_wl_address_local(ip_address):
    # Começa temporizador
    start_time = time.time()

    cur.execute("SELECT 1 FROM wl_address_local WHERE ip_address = %s;", (ip_address,))

    # Calcula o tempo de execução
    execution_time = (time.time() - start_time) * 1000
    print(f"Tempo de checagem na wl_address_local: {execution_time:.3f} milisegundos")

    return execution_time, cur.fetchone() is not None

def ip_existe_na_bl_address_local(ip_address):
    # Começa o temporizador
    start_check_blacklist = time.time()
    
    cur.execute("SELECT 1 FROM bl_address_local WHERE ip_address = %s;", (ip_address,))

    # Calcula o tempo de execução
    execution_check_blacklist = (time.time() - start_check_blacklist) * 1000
    print(f"Tempo de checagem na bl_address_local: {execution_check_blacklist:.3f} milisegundos")

    return execution_check_blacklist, cur.fetchone() is not None

# Função para checar se o ip está na whitelist local, e se não tiver jogar na tarpit da API
def checar_reputacao_ip_e_inserir(ip_address, src_longitude, country_code, src_latitude, token):
    
    # Verificar se o IP está na wl_address_local do banco local
    checagem_wl_local_time, ip_existe_wl_local = ip_existe_na_wl_address_local(ip_address)

    if ip_existe_wl_local:
        print(f"IP {ip_address} está na whitelist local, acesso liberado.")
        return checagem_wl_local_time, 0, 0, 0, 0
    else:
        # Começa temporizador
        start_time = time.time()

        # Degradar o IP antes de inserí-lo na tarpit
        tarpitrule5.apply_tarpit_rules(ip=ip_address)

        start_request = time.time()
        
        # Se o IP não está na whitelist, mover para a tarpit da API
        url = "http://localhost:8000/api/tarpit/list/"
        headers = {
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json'
        }
        
        country_code, city, latitude, longitude = get_geo_info(ip_address) or (None, None, None, None)

        params = {
            'ip_address': ip_address,
            'country_code': country_code,
            'city': city,
            'abuse_confidence_score': None,
            'last_reported_at': None,
            'src_longitude': src_longitude,
            'src_latitude': src_latitude
        }

        response = requests.post(url, headers=headers, json=params)

        #Tempo p/ receber qualquer resposta da requisição
        execution_request = (time.time() - start_request) * 1000
        print(f"Tempo de resposta da API: {execution_request:.3f} milisegundos")

        # Checar velocidade
        if response.status_code == 201:
            # Calcula o tempo de execução. Espera o resultado da requisição p/ contabilizar.
            execution_time = (time.time() - start_time) * 1000
            print(f"Tempo de checagem na API: {execution_time:.3f} milisegundos")

            print(f'response: {response.json()}')
            response_data = response.json()
            status = response_data["status"]

            if status == "blacklist" or status == "none":
                # Começa temporizador
                start_time = time.time()

                # Aplica as regras pra blacklist
                print("chegou na status blacklist")

                # Insere na blacklist local
                query = """
                    INSERT INTO bl_address_local (ip_address, country_code, city, abuse_confidence_score, total_reports, num_distinct_users, virustotal_reputation, harmless_virustotal, malicious_virustotal, suspicious_virustotal, undetected_virustotal, ipvoid_detection_count, risk_recommended_pulsedive, last_reported_at, src_longitude, src_latitude)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                values = (
                    ip_address,
                    country_code,
                    city,
                    response_data["abuse_confidence_score"],
                    response_data["total_reports"],
                    response_data["num_distinct_users"],
                    response_data["virustotal_reputation"],
                    response_data["harmless_virustotal"],
                    response_data["malicious_virustotal"],
                    response_data["suspicious_virustotal"],
                    response_data["undetected_virustotal"],
                    response_data["ipvoid_detection_count"],
                    response_data["risk_recommended_pulsedive"],
                    response_data["last_reported_at"],
                    src_longitude,
                    src_latitude
                )
                cur.execute(query, values)
                conn.commit()

                blacklist_rules.apply_blacklist_rules(ip=ip_address)

                # Calcula o tempo de execução
                execution_blacklist = time.time() - start_time
                print(f"Tempo pra aplicar regras no firewall (Blacklist): {execution_blacklist:.3f} segundos")

                tarpitrule5.deletar_ip_tarpit(ip=ip_address)
                return checagem_wl_local_time, execution_request, execution_time, execution_blacklist, 0

            elif status == "whitelist":
                # Começa temporizador
                start_time = time.time()

                print("chegou na status whitelist")
                print(f"status: {status}")

                # Insere na whitelist local
                query = """
                    INSERT INTO wl_address_local (ip_address, country_code, city, abuse_confidence_score, total_reports, num_distinct_users, virustotal_reputation, harmless_virustotal, malicious_virustotal, suspicious_virustotal, undetected_virustotal, ipvoid_detection_count, risk_recommended_pulsedive, last_reported_at, src_longitude, src_latitude)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                values = (
                    ip_address,
                    country_code,
                    city,
                    response_data["abuse_confidence_score"],
                    response_data["total_reports"],
                    response_data["num_distinct_users"],
                    response_data["virustotal_reputation"],
                    response_data["harmless_virustotal"],
                    response_data["malicious_virustotal"],
                    response_data["suspicious_virustotal"],
                    response_data["undetected_virustotal"],
                    response_data["ipvoid_detection_count"],
                    response_data["risk_recommended_pulsedive"],
                    response_data["last_reported_at"],
                    src_longitude,
                    src_latitude
                )

                cur.execute(query, values)
                conn.commit()
                print("Dados inseridos na tabela wl_address_local com sucesso")

                # Aplica as regras pra whitelist
                whitelist_rules.apply_whitelist_rules(ip=ip_address)

                # Calcula o tempo de execução
                execution_whitelist = (time.time() - start_time) * 1000
                print(f"Tempo pra aplicar regras no firewall (Whitelist): {execution_whitelist:.3f} milisegundos")

                tarpitrule5.deletar_ip_tarpit(ip=ip_address)
                return checagem_wl_local_time, execution_request, execution_time, 0, execution_whitelist

            elif status == "existente_whitelist":
                print("Já existe no banco da API")
                # Insere na whitelist local
                query = """
                    INSERT INTO wl_address_local (ip_address, country_code, city, abuse_confidence_score, total_reports, num_distinct_users, virustotal_reputation, harmless_virustotal, malicious_virustotal, suspicious_virustotal, undetected_virustotal, ipvoid_detection_count, risk_recommended_pulsedive, last_reported_at, src_longitude, src_latitude)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                values = (
                    ip_address,
                    country_code,
                    city,
                    response_data["abuse_confidence_score"],
                    response_data["total_reports"],
                    response_data["num_distinct_users"],
                    response_data["virustotal_reputation"],
                    response_data["harmless_virustotal"],
                    response_data["malicious_virustotal"],
                    response_data["suspicious_virustotal"],
                    response_data["undetected_virustotal"],
                    response_data["ipvoid_detection_count"],
                    response_data["risk_recommended_pulsedive"],
                    response_data["last_reported_at"],
                    src_longitude,
                    src_latitude
                )
                cur.execute(query, values)
                conn.commit()

                # Aplica as regras para whitelist
                whitelist_rules.apply_whitelist_rules(ip=ip_address)

                tarpitrule5.deletar_ip_tarpit(ip=ip_address)
                return checagem_wl_local_time, execution_request, execution_time, 0, 0
            
            elif status == "existente_blacklist":
                print(f"O IP {ip_address} já existe no banco da API")
                # Insere na blacklist local
                query = """
                    INSERT INTO bl_address_local (ip_address, country_code, city, abuse_confidence_score, total_reports, num_distinct_users, virustotal_reputation, harmless_virustotal, malicious_virustotal, suspicious_virustotal, undetected_virustotal, ipvoid_detection_count, risk_recommended_pulsedive, last_reported_at, src_longitude, src_latitude)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                values = (
                    ip_address,
                    country_code,
                    city,
                    response_data["abuse_confidence_score"],
                    response_data["total_reports"],
                    response_data["num_distinct_users"],
                    response_data["virustotal_reputation"],
                    response_data["harmless_virustotal"],
                    response_data["malicious_virustotal"],
                    response_data["suspicious_virustotal"],
                    response_data["undetected_virustotal"],
                    response_data["ipvoid_detection_count"],
                    response_data["risk_recommended_pulsedive"],
                    response_data["last_reported_at"],
                    src_longitude,
                    src_latitude
                )
                cur.execute(query, values)
                conn.commit()

                tarpitrule5.deletar_ip_tarpit(ip=ip_address)
                blacklist_rules.apply_blacklist_rules(ip=ip_address)
                return checagem_wl_local_time, execution_request, execution_time, 0, 0

        else:
            print(f"Houve um erro ao inserir o IP {ip_address}: {response.status_code}")
            tarpitrule5.deletar_ip_tarpit(ip=ip_address)
            return checagem_wl_local_time, 0, 0, 0, 0

# Função para inserir dados na tabela de tráfego de rede
def insert_data(src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port, connection_time):
    try:
        # Começa temporizador
        start_time = time.time()

        timestamp = datetime.datetime.now()
        query = """
        INSERT INTO network_traffic (timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_latitude, src_longitude, dst_country_code, dst_city, dst_latitude, dst_longitude, src_port, dst_port, connection_time)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        cur.execute(query, (timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port, connection_time))
        # Calcula o tempo de execução
        insert_time = (time.time() - start_time) * 1000
        print(f"Tempo pra inserir os dados na network-traffic: {insert_time:.3f} milisegundos")
        conn.commit()

        return insert_time

    except psycopg2.IntegrityError:
        # Se já existe uma conexão igual, ignorar o erro
        conn.rollback()
        print(f"Conexão entre {src_ip}:{src_port} e {dst_ip}:{dst_port} já registrada, ignorando.")

# Função para manipular pacotes de rede
def handle_packet(packet):
    if not (IP in packet and TCP in packet):
        return

    start_time = time.time()  # Início do tempo para cada conexão

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Obter informações geográficas
    src_country_code, src_city, src_lat, src_lon = (None, None, None, None) if is_private_ip(src_ip) else get_geo_info(src_ip)
    dst_country_code, dst_city, dst_lat, dst_lon = (None, None, None, None) if is_private_ip(dst_ip) else get_geo_info(dst_ip)

    # Obter informações de protocolo e serviços
    protocol_code, protocol_name = get_protocol_info(packet)
    src_service, dst_service = get_service_info(packet)

    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    # Inserção de dados condicionada à tentativa de conexão (flag SYN sem ACK)
    if 'S' in packet[TCP].flags and not 'A' in packet[TCP].flags:
        connection_time = time.time() - start_time  # Calcula o tempo decorrido
        
        # src_ip_iptables_time, src_ip_iptables_is_blacklisted = checar_blacklist_ip_tables(src_ip)
        # dst_ip_iptables_time, dst_ip_iptables_is_blacklisted = checar_blacklist_ip_tables(dst_ip)

        src_execution_checagem_blacklist, src_is_blacklisted = ip_existe_na_bl_address_local(src_ip)
        dst_execution_checagem_blacklist, dst_is_blacklisted = ip_existe_na_bl_address_local(dst_ip)

        # Inicializando as variáveis de tempo como 0 para evitar erros
        src_checagem_wl_local_time = 0
        src_execution_request = 0
        src_execution_time = 0
        src_execution_blacklist = 0
        src_execution_whitelist = 0
        dst_checagem_wl_local_time = 0
        dst_execution_request = 0
        dst_execution_time = 0
        dst_execution_blacklist = 0
        dst_execution_whitelist = 0
        insert_time = 0
        detection_time = 0

        # Checagem do IP de origem e destino na blacklist do iptables (caso esteja lá, nem insere na network-traffic)
        if src_is_blacklisted:
            print(f"O IP de origem {src_ip} está na bl_address_local")
            pass
        elif dst_is_blacklisted:
            print(f"O IP de destino {dst_ip} está na bl_address_local")
            pass
        else:
            # Chama a função insert_data
            insert_time = insert_data(src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port, connection_time)

            # Calcula o tempo de execução
            detection_time = (time.time() - start_time) * 1000
            print(f"Tempo pra detecção de conexão na wl_address_local: {detection_time:.3f} milisegundos")

            # Verificar e inserir o IP na tp_address_local ou bl_address_local se necessário
            src_checagem_wl_local_time, src_execution_request, src_execution_time, src_execution_blacklist, src_execution_whitelist = checar_reputacao_ip_e_inserir(src_ip, src_lon, src_country_code, src_lat, token)
            dst_checagem_wl_local_time, dst_execution_request, dst_execution_time, dst_execution_blacklist, dst_execution_whitelist = checar_reputacao_ip_e_inserir(dst_ip, dst_lon, dst_country_code, dst_lat, token)

            deletar_trafego_filtrado(src_ip=src_ip, dst_ip=dst_ip)

        data = [
            src_ip, dst_ip,
            src_execution_checagem_blacklist, src_checagem_wl_local_time, 
            src_execution_request, src_execution_time, 
            src_execution_blacklist, src_execution_whitelist,
            dst_execution_checagem_blacklist, dst_checagem_wl_local_time, dst_execution_request,
            dst_execution_time, dst_execution_blacklist,
            dst_execution_whitelist, insert_time, detection_time,
        ]
        write_to_csv(data)

# Deleta os objetos da network-traffic depois de serem filtrados
def deletar_trafego_filtrado(src_ip, dst_ip):
    try:
        query = """
        DELETE FROM network_traffic 
        WHERE src_ip = %s OR dst_ip = %s
        """
        cur.execute(query, (src_ip, dst_ip))  # Passa src_ip e dst_ip como parâmetros pois a função de checar é chamada para src_ip e dst_ip
        conn.commit()

        print(f"Registros com src_ip = {src_ip} ou dst_ip = {dst_ip} foram deletados com sucesso.")
    
    except Exception as e:
        print(f"Erro ao deletar: {e}")

if __name__ == "__main__":
    # Criar banco local ao rodar o collect
    # possivelmente rodar para setar as chains
    print("Monitorando tráfego de rede...")
    sniff(prn=handle_packet, filter="tcp", store=0)
