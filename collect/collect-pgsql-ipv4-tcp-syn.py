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
from tarpitrule5 import apply_tarpit_rules, deletar_ip_tarpit
from whitelist_rules import apply_whitelist_rules
from blacklist_rules import apply_blacklist_rules
import csv
import logging

dotenv_path = os.path.join(os.path.dirname(__file__), "..", "api", ".env")
load_dotenv(dotenv_path)

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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Construir o caminho absoluto para o arquivo JSON
MAPPINGS_PATH = os.path.join(BASE_DIR, "mappings.json")

# Escreve o CSV no visualizer
VISUALIZER_DIR = os.path.join(BASE_DIR, "..", "visualizer")

# Arquivo de logs para a collect
COLLECT_LOG_FILE = os.path.join(BASE_DIR, "collect_outputs", "collect.log")

# Arquivo CSV contendo as temporizações
CSV_FILE = os.path.join(VISUALIZER_DIR, "execution_times.csv")

# Garantir que o diretório visualizer existe
if not os.path.exists(VISUALIZER_DIR):
    os.makedirs(VISUALIZER_DIR)

# Carregar mapeamentos de protocolo e serviço a partir de um arquivo JSON
with open(MAPPINGS_PATH, 'r') as f:
    mappings = json.load(f)

protocol_mapping = {int(k): v for k, v in mappings["protocol_mapping"].items()}
service_mapping = {int(k): v for k, v in mappings["service_mapping"].items()}


# Cabeçalho do CSV
header = [
    "src_ip", "dst_ip",
    "src_tempo_checagem_bl_local",
    "src_tempo_checagem_wl_local",
    "src_tempo_checagem_suspect_local",
    "src_tempo_resposta_api",
    "src_tempo_checagem_api",
    "src_tempo_aplicar_regras_blacklist",
    "src_tempo_aplicar_regras_whitelist",
    "src_tempo_aplicar_regras_suspect",
    "dst_tempo_checagem_bl_local",
    "dst_tempo_checagem_wl_local",
    "dst_tempo_checagem_suspect_local",
    "dst_tempo_resposta_api",
    "dst_tempo_checagem_api",
    "dst_tempo_aplicar_regras_blacklist",
    "dst_tempo_aplicar_regras_whitelist",
    "dst_tempo_aplicar_regras_suspect",
    "tempo_inserir_network_traffic",
    "tempo_deteccao_conexao"
]


# Função para logging
def setup_logging(log_file=COLLECT_LOG_FILE):
    """
    Configura o logging para a aplicação

    Args:
        log_file (str): Caminho do arquivo de log. Se None, só loga no console.
    """
    # Cria o diretório dos logs caso ele não exista
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Configuração básica do logging
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


# Função para escrever no CSV
def write_to_csv(data):
    # Se o arquivo não existir, cria o arquivo e escreve o cabeçalho
    file_exists = os.path.exists(CSV_FILE)
    with open(CSV_FILE, mode="a", newline="") as file:
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
        logger.error(f"Error getting geo info for {ip_address}: {e}")
        return None, None, None, None  # Valores padrão

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

# Checa se o IP está na wl_address_local
def ip_existe_na_wl_address_local(ip_address):
    # Começa temporizador
    start_time = time.time()

    cur.execute("SELECT 1 FROM wl_address_local WHERE ip_address = %s;", (ip_address,))

    # Calcula o tempo de execução
    execution_time = (time.time() - start_time) * 1000
    logger.info(f"Tempo de checagem do IP {ip_address} na wl_address_local: {execution_time:.3f} milisegundos")

    return execution_time, cur.fetchone() is not None

def ip_existe_na_bl_address_local(ip_address):
    # Começa o temporizador
    start_check_blacklist = time.time()
    
    cur.execute("SELECT 1 FROM bl_address_local WHERE ip_address = %s;", (ip_address,))

    # Calcula o tempo de execução
    execution_check_blacklist = (time.time() - start_check_blacklist) * 1000
    logger.info(f"Tempo de checagem do IP {ip_address} na bl_address_local: {execution_check_blacklist:.3f} milisegundos")

    return execution_check_blacklist, cur.fetchone() is not None

def ip_existe_na_suspect_local(ip_address):
    # Começa o temporizador
    start_check_suspect = time.time()

    cur.execute("SELECT 1 FROM suspect_local WHERE ip_address = %s;", (ip_address,))

    # Calcula o tempo de execução
    suspect_check_time = (time.time() - start_check_suspect) * 1000
    logger.info(f"Tempo de checagem do IP {ip_address} na suspect_local: {suspect_check_time:.3f} milisegundos")

    return suspect_check_time, cur.fetchone() is not None


def inserir_ip_na_lista(tabela, ip_address, country_code, city, response_data, src_longitude, src_latitude):
    query = f"""
        INSERT INTO {tabela} (
            ip_address, 
            country_code, 
            city, 
            abuseipdb_confidence_score, 
            abuseipdb_total_reports, 
            abuseipdb_num_distinct_users, 
            virustotal_reputation, virustotal_harmless, 
            virustotal_malicious, virustotal_suspicious, 
            virustotal_undetected, 
            ipvoid_detection_count, 
            risk_recommended_pulsedive, 
            last_reported_at, src_longitude, 
            src_latitude 
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    values = (
        ip_address, country_code, city,
        response_data["abuseipdb_confidence_score"],
        response_data["abuseipdb_total_reports"],
        response_data["abuseipdb_num_distinct_users"],
        response_data["virustotal_reputation"],
        response_data["virustotal_harmless"],
        response_data["virustotal_malicious"],
        response_data["virustotal_suspicious"],
        response_data["virustotal_undetected"],
        response_data["ipvoid_detection_count"],
        response_data["risk_recommended_pulsedive"],
        response_data["last_reported_at"],
        src_longitude, src_latitude
    )
    cur.execute(query, values)
    conn.commit()
    logger.info(f'Dados do IP {ip_address} inseridos na tabela {tabela} com sucesso')


def aplicar_regras(status, ip_address):
    if status in ["blacklist", "existente_blacklist"]:
        apply_blacklist_rules(ip=ip_address)
    elif status in ["whitelist", "existente_whitelist"]:
        apply_whitelist_rules(ip=ip_address)
    elif status in ["suspect", "existente_suspect"]:
        apply_tarpit_rules(ip=ip_address)


def checar_reputacao_ip_e_inserir(ip_address, src_longitude, country_code, src_latitude, token):
    # Verificar se o IP está na wl_address_local do banco local
    checagem_wl_local_time, ip_existe_wl_local = ip_existe_na_wl_address_local(ip_address)

    if ip_existe_wl_local:
        logger.info(f"IP {ip_address} está na whitelist local, acesso liberado.")
        return checagem_wl_local_time, 0, 0, 0, 0, 0
    else:
        # Começa temporizador
        start_time = time.time()

        # Degradar o IP para limitar sua conexão
        apply_tarpit_rules(ip=ip_address)

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
            'src_longitude': src_longitude,
            'src_latitude': src_latitude
        }

        response = requests.post(url, headers=headers, json=params)

        # Tempo p/ receber qualquer resposta da requisição
        api_response_time = (time.time() - start_request) * 1000
        logger.info(f"Tempo de resposta da API: {api_response_time:.3f} milisegundos")

        # Checar velocidade
        if response.status_code == 201:
            # print(f'response: {response.json()}')
            response_data = response.json()
            status = response_data["status"]
            

            if status in ["blacklist", "none", "existente_blacklist"]:
                inserir_ip_na_lista("bl_address_local", ip_address, country_code, city, response_data, src_longitude, src_latitude)
                
                start_time = time.time()
                aplicar_regras(status, ip_address)
                time_apply_bl_rules = (time.time() - start_time) * 1000

                # Calcula tempo total
                execution_time = (time.time() - start_time) * 1000

                # Remove IP da tarpit no IPtables
                deletar_ip_tarpit(ip=ip_address)
                logger.info(f"Tempo total de execução: {execution_time:.3f} milisegundos")

                return checagem_wl_local_time, api_response_time, execution_time, time_apply_bl_rules, 0, 0
            
            elif status in ["suspicious", "existente_suspect"]:
                inserir_ip_na_lista("suspect_local", ip_address, country_code, city, response_data, src_longitude, src_latitude)

                start_time = time.time()
                # Não é necessário pois já está na Tarpit
                # aplicar_regras(status, ip_address)
                time_apply_suspect_rules = (time.time() - start_time) * 1000

                # Calcula tempo total
                execution_time = (time.time() - start_time) * 1000

                # Remove IP da tarpit no IPtables
                deletar_ip_tarpit(ip=ip_address)
                logger.info(f"Tempo total de execução: {execution_time:.3f} milisegundos")

                return checagem_wl_local_time, api_response_time, execution_time, 0, 0, time_apply_suspect_rules

            elif status in ["whitelist", "existente_whitelist"]:
                inserir_ip_na_lista("wl_address_local", ip_address, country_code, city, response_data, src_longitude, src_latitude)

                start_time = time.time()
                aplicar_regras(status, ip_address)
                time_apply_wl_rules = (time.time() - start_time) * 1000

                # Calcula tempo total
                execution_time = (time.time() - start_time) * 1000
                
                # Remove IP da tarpit no IPtables
                deletar_ip_tarpit(ip=ip_address)
                logger.info(f"Tempo total de execução: {execution_time:.3f} milisegundos")

                return checagem_wl_local_time, api_response_time, execution_time, 0, time_apply_wl_rules, 0

        else:
            logger.error(f"Erro ao enviar IP para API: {response.status_code}")
            deletar_ip_tarpit(ip=ip_address)


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
        logger.info(f"Tempo pra inserir os dados na network-traffic: {insert_time:.3f} milisegundos")
        conn.commit()

        return insert_time

    except psycopg2.IntegrityError:
        # Se já existe uma conexão igual, ignorar o erro
        conn.rollback()
        logger.error(f"Conexão entre {src_ip}:{src_port} e {dst_ip}:{dst_port} já registrada, ignorando.")


# Deleta os objetos da network-traffic depois de serem enviados para a API
def deletar_da_network_traffic(src_ip, dst_ip):
    try:
        query = """
        DELETE FROM network_traffic 
        WHERE src_ip = %s OR dst_ip = %s
        """
        cur.execute(query, (src_ip, dst_ip))  # Passa src_ip e dst_ip como parâmetros pois a função de checar é chamada para src_ip e dst_ip
        conn.commit()

        logger.info(f"Registros com src_ip = {src_ip} ou dst_ip = {dst_ip} foram deletados com sucesso.")
    
    except Exception as e:
        logger.error(f"Erro ao deletar: {e}")


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

        src_checagem_bl_local_time, src_is_blacklisted = ip_existe_na_bl_address_local(src_ip)
        dst_checagem_bl_local_time, dst_is_blacklisted = ip_existe_na_bl_address_local(dst_ip)

        src_checagem_suspect_local_time, src_is_suspect = ip_existe_na_suspect_local(src_ip)
        dst_checagem_suspect_local_time, dst_is_suspect = ip_existe_na_suspect_local(dst_ip)

        # Checagem do IP de origem e destino na blacklist do iptables (caso esteja lá, nem insere na network-traffic)
        if src_is_blacklisted:
            logger.info(f"O IP de origem {src_ip} está na bl_address_local")
            pass
        elif dst_is_blacklisted:
            logger.info(f"O IP de destino {dst_ip} está na bl_address_local")
            pass
        elif src_is_suspect:
            logger.info(f"O IP de origem {src_ip} está na suspect_local")
            pass
        elif dst_is_suspect:
            logger.info(f"O IP de destino {dst_ip} está na suspect_local")
            pass
        else:
            # Chama a função insert_data
            insert_time = insert_data(src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port, connection_time)

            # Calcula o tempo de execução
            detection_time = (time.time() - start_time) * 1000
            logger.info(f"Tempo pra detecção de conexão na wl_address_local: {detection_time:.3f} milisegundos")

            # Verificar e inserir o IP na tp_address_local ou bl_address_local se necessário
            src_checagem_wl_local_time, src_request_api_time, src_total_execution_time, src_time_apply_bl_rules, src_time_apply_wl_rules, src_time_apply_suspect_rules = checar_reputacao_ip_e_inserir(src_ip, src_lon, src_country_code, src_lat, token)
            dst_checagem_wl_local_time, dst_request_api_time, dst_total_execution_time, dst_time_apply_bl_rules, dst_time_apply_wl_rules, dst_time_apply_suspect_rules = checar_reputacao_ip_e_inserir(dst_ip, dst_lon, dst_country_code, dst_lat, token)

            deletar_da_network_traffic(src_ip, dst_ip)

            data = [
                src_ip, dst_ip,
                src_checagem_bl_local_time, src_checagem_wl_local_time, 
                src_checagem_suspect_local_time,
                src_request_api_time, src_total_execution_time,
                src_time_apply_bl_rules, src_time_apply_wl_rules, src_time_apply_suspect_rules,
                dst_checagem_bl_local_time, dst_checagem_wl_local_time, 
                dst_checagem_suspect_local_time, dst_request_api_time,
                dst_total_execution_time, dst_time_apply_bl_rules, dst_time_apply_wl_rules,
                dst_time_apply_suspect_rules, insert_time, detection_time,
            ]
            write_to_csv(data)


if __name__ == "__main__":
    # Criar banco local ao rodar o collect
    # possivelmente rodar para setar as chains
    logger = setup_logging()
    print("Monitorando tráfego de rede...")
    sniff(prn=handle_packet, filter="tcp", store=0)
