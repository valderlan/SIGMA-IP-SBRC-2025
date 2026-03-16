import ipaddress
import json
import logging
import os
import time
import requests
import redis
import csv
from geoip2.database import Reader
from dotenv import load_dotenv
from scapy.all import IP, TCP, sniff
from blacklist_rules import apply_blacklist_rules
from tarpit_rules import apply_tarpit_rules, remove_ip_from_iptables_tarpit
from whitelist_rules import apply_whitelist_rules
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COLLECT_DIR = os.path.join(BASE_DIR, "collect_outputs")

# cria o diretório caso não exista
os.makedirs(COLLECT_DIR, exist_ok=True)

CSV_PATH = os.path.join(COLLECT_DIR, "collected_data.csv")

csv_file = open(CSV_PATH, mode="a", newline="")
csv_writer = csv.writer(csv_file)

if os.stat(CSV_PATH).st_size == 0:
    csv_writer.writerow([
        "timestamp",
        "ip",
        "type",
        "latency_ms",
        "verdict",
        "country_code",
        "city",
    ])

dotenv_path = os.path.join(BASE_DIR, "..", "api", ".env")
load_dotenv(dotenv_path)

token = os.environ.get("token")

# Configurações do Redis para cache
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

BLACKLIST_KEY = "firewall:blacklist"
WHITELIST_KEY = "firewall:whitelist"
SUSPECT_KEY = "firewall:suspect"
PROCESSED_KEY = "firewall:processed"


# Construir o caminho absoluto para o arquivo JSON
MAPPINGS_PATH = os.path.join(BASE_DIR, "mappings.json")

COLLECT_LOG_PATH = os.path.join(BASE_DIR, "collect_outputs", "collect.log")

# Carregar mapeamentos de protocolo e serviço a partir de um arquivo JSON
with open(MAPPINGS_PATH, "r") as f:
    mappings = json.load(f)

protocol_mapping = {int(k): v for k, v in mappings["protocol_mapping"].items()}
service_mapping = {int(k): v for k, v in mappings["service_mapping"].items()}


# Função para logging
def setup_logging(log_file=COLLECT_LOG_PATH):
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


# Função para obter as informações de protocolo
def get_protocol_info(packet):
    protocol_code = packet[IP].proto
    protocol_name = protocol_mapping.get(protocol_code, "Unknown")
    return protocol_code, protocol_name


# Função para obter as informações de serviço
def get_service_info(packet):
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    src_service = service_mapping.get(src_port, "Unknown")
    dst_service = service_mapping.get(dst_port, "Unknown")
    return src_service, dst_service


# Função para obter latitude, longitude e country code
def get_geolocation_info(ip_address):
    try:
        with Reader("/usr/share/GeoIP/GeoLite2-City.mmdb") as reader:
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


def add_to_blacklist(ip, ttl=None):
    r.sadd(BLACKLIST_KEY, ip)
    if ttl:
        r.expire(BLACKLIST_KEY, ttl)


def add_to_whitelist(ip, ttl=None):
    r.sadd(WHITELIST_KEY, ip)
    if ttl:
        r.expire(WHITELIST_KEY, ttl)


def add_to_suspect(ip, ttl=None):
    r.sadd(SUSPECT_KEY, ip)
    if ttl:
        r.expire(SUSPECT_KEY, ttl)


def is_blacklisted(ip):
    return r.sismember(BLACKLIST_KEY, ip)


def is_whitelisted(ip):
    return r.sismember(WHITELIST_KEY, ip)


def is_suspect(ip):
    return r.sismember(SUSPECT_KEY, ip)


def mark_processed(ip, ttl=3600):  # 1 hora de expiração
    r.sadd(PROCESSED_KEY, ip)
    r.expire(PROCESSED_KEY, ttl)


def already_processed(ip):
    return r.sismember(PROCESSED_KEY, ip)


def apply_firewall_rules(verdict, ip_address):
    if verdict in ["blacklist", "exists_in_api_blacklist"]:
        apply_blacklist_rules(ip=ip_address)
    elif verdict in ["whitelist", "exists_in_api_whitelist"]:
        apply_whitelist_rules(ip=ip_address)
    elif verdict in ["suspect", "exists_in_api_suspect"]:
        apply_tarpit_rules(ip=ip_address)


def check_ip_reputation_and_insert(
    ip_address, src_longitude, country_code, city, src_latitude, token
):
    try:
        request_start_time = time.time()

        url = "http://localhost:8000/api/v1/pending-analysis/"
        headers = {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        }

        params = {
            "ip_address": ip_address,
            "country_code": country_code,
            "city": city,
            "src_longitude": src_longitude,
            "src_latitude": src_latitude,
        }

        response = requests.post(url, headers=headers, json=params)
        api_response_time_ms = (time.time() - request_start_time) * 1000
        logger.info(
            f"Tempo de checar o IP {ip_address} na API: {api_response_time_ms:.3f} ms"
        )
        logger.info(f"Status Code: {response.status_code}")

        if response.status_code != 201:
            logger.error(f"Erro ao enviar IP para API: {response.status_code}")
            remove_ip_from_iptables_tarpit(ip=ip_address)
            return

        response_data = response.json()
        verdict = response_data["verdict"]

        csv_writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            ip_address,
            "api",
            f"{api_response_time_ms:.3f}",
            verdict,
            country_code,
            city,
        ])
        csv_file.flush()

        # Aplicar regras baseadas no veredito
        if verdict in ["denylist", "none", "exists_in_api_blacklist"]:
            add_to_blacklist(ip_address)
            apply_firewall_rules(verdict, ip_address)

        elif verdict in ["suspicious", "exists_in_api_suspect"]:
            add_to_suspect(ip_address)
            apply_firewall_rules(verdict, ip_address)

        elif verdict in ["allowlist", "exists_in_api_whitelist"]:
            add_to_whitelist(ip_address)
            apply_firewall_rules(verdict, ip_address)

        else:
            logger.error(f"Status desconhecido recebido da API: {verdict}")

        return 

    except Exception as e:
        logger.error(f"Erro inesperado ao processar IP {ip_address}: {str(e)}")
        return


# Função para manipular pacotes de rede
def handle_packet(packet):
    if not (IP in packet and TCP in packet):
        return

    start_time = time.time()  # Início do tempo para cada conexão

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Obter informações de protocolo e serviços
    protocol_code, protocol_name = get_protocol_info(packet)
    src_service, dst_service = get_service_info(packet)

    # src_port = packet[TCP].sport
    # dst_port = packet[TCP].dport

    # Inserção de dados condicionada a tentativa de conexão (flag SYN sem ACK)
    if "S" in packet[TCP].flags and "A" not in packet[TCP].flags:
        start_time = time.time()

        # Checa se é preciso processar o source IP
        process_src = (
            not is_blacklisted(src_ip)
            and not is_whitelisted(src_ip)
            and not is_suspect(src_ip)
            and not already_processed(src_ip)
        )

        # Checa se é preciso processar o destination IP
        process_dst = (
            not is_blacklisted(dst_ip)
            and not is_whitelisted(dst_ip)
            and not is_suspect(dst_ip)
            and not already_processed(dst_ip)
        )

        # Se nenhum dos dois precisa ser processado, retorna
        if not process_src and not process_dst:
            detection_duration_ms = (time.time() - start_time) * 1000

            csv_writer.writerow([
                datetime.now(timezone.utc).isoformat(),
                f"{src_ip}->{dst_ip}",
                "cache",
                f"{detection_duration_ms:.3f}",
                "",
                "",
                "",
            ])
            csv_file.flush()

            logger.info(
                f"Tempo pra detecção de conexão ({src_ip} -> {dst_ip}) no cache: "
                f"{detection_duration_ms:.3f} ms"
            )
            return

        # Processa o source IP se necessário
        if process_src:
            mark_processed(src_ip)
            src_country_code, src_city, src_lat, src_lon = get_geolocation_info(src_ip)
            check_ip_reputation_and_insert(
                src_ip, src_lon, src_country_code, src_city, src_lat, token
            )

        # Processa o destination IP se necessário
        if process_dst:
            mark_processed(dst_ip)
            dst_country_code, dst_city, dst_lat, dst_lon = get_geolocation_info(dst_ip)
            check_ip_reputation_and_insert(
                dst_ip, dst_lon, dst_country_code, dst_city, dst_lat, token
            )


if __name__ == "__main__":
    logger = setup_logging()
    print("Monitorando tráfego de rede...")
    sniff(prn=handle_packet, filter="tcp", store=0)
