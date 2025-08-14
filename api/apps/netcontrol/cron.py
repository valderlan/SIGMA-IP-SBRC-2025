import logging
import os
from datetime import timedelta

import psycopg2
from django.utils.timezone import now

from api.core.settings import (
    POSTGRES_DB,
    POSTGRES_HOST,
    POSTGRES_PASSWORD,
    POSTGRES_PORT,
    POSTGRES_USER,
)

from .externals import SearchAbuse
from .models import Blacklist, Tarpit, Whitelist
from .services import filter_and_classify_ip, insert_new_blacklist_entries

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRON_LOGS_PATH = os.path.join(BASE_DIR, "api_outputs", "cron.log")


# Função para logging
def setup_logging(log_file=CRON_LOGS_PATH):
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


# Função pra requisitar novos dados pra blacklist
def update_blacklist():
    logger = setup_logging()
    logger.info("Buscando dados para atualizar a Blacklist...")
    dados = SearchAbuse.search_abuse_blacklist()
    if dados:
        insert_new_blacklist_entries(dados)


# Função para verificar IPs antigos da Whitelist
def reprocess_old_whitelist_ips():
    logger = setup_logging()

    tres_dias_atras = now() - timedelta(days=3)
    queryset = Whitelist.objects.filter(timestamp_added__lt=tres_dias_atras)

    tarpit_objs = []
    ip_addresses = []

    for obj_whitelist in queryset:
        tarpit_objs.append(
            Tarpit(
                ip_address=obj_whitelist.ip_address,
                country_code=obj_whitelist.country_code,
                city=obj_whitelist.city,
                abuseipdb_confidence_score=obj_whitelist.abuseipdb_confidence_score,
                abuseipdb_total_reports=obj_whitelist.abuseipdb_total_reports,
                abuseipdb_num_distinct_users=obj_whitelist.abuseipdb_num_distinct_users,
                virustotal_reputation=obj_whitelist.virustotal_reputation,
                virustotal_harmless=obj_whitelist.virustotal_harmless,
                virustotal_malicious=obj_whitelist.virustotal_malicious,
                virustotal_suspicious=obj_whitelist.virustotal_suspicious,
                virustotal_undetected=obj_whitelist.virustotal_undetected,
                ipvoid_detection_count=obj_whitelist.ipvoid_detection_count,
                risk_recommended_pulsedive=obj_whitelist.risk_recommended_pulsedive,
                last_reported_at=obj_whitelist.last_reported_at,
                src_longitude=obj_whitelist.src_longitude,
                src_latitude=obj_whitelist.src_latitude,
            )
        )
        ip_addresses.append(obj_whitelist.ip_address)

    try:
        # Cria os objetos de uma vez na tarpit
        Tarpit.objects.bulk_create(tarpit_objs)
        logger.info(f"{len(tarpit_objs)} IPs inseridos na tarpit.")

        # Deleta todos da wl_address_local com um único DELETE
        if ip_addresses:
            conn = psycopg2.connect(
                host=POSTGRES_HOST,
                dbname=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
                port=POSTGRES_PORT,
            )
            cur = conn.cursor()
            cur.execute("SET TIMEZONE TO 'America/Fortaleza';")

            delete_query = "DELETE FROM wl_address_local WHERE ip_address = ANY(%s)"
            cur.execute(delete_query, (ip_addresses,))
            conn.commit()
            conn.close()
            logger.info(f"{len(ip_addresses)} IPs removidos de wl_address_local.")

        # Deleta da Whitelist do Django
        queryset.delete()

        # Refiltra os IPs
        for ip in ip_addresses:
            filter_and_classify_ip(ip)

    except Exception as e:
        logger.error(f"Erro ao processar atualização da whitelist: {e}")


# Função pra verificar IPs antigos da blacklist
def reprocess_old_blacklist_ips():
    logger = setup_logging()

    tres_dias_atras = now() - timedelta(days=3)
    queryset = Blacklist.objects.filter(timestamp_added__lt=tres_dias_atras)

    tarpit_objs = []
    ip_addresses = []

    for obj_blacklist in queryset:
        tarpit_objs.append(
            Tarpit(
                ip_address=obj_blacklist.ip_address,
                country_code=obj_blacklist.country_code,
                city=obj_blacklist.city,
                abuseipdb_confidence_score=obj_blacklist.abuseipdb_confidence_score,
                abuseipdb_total_reports=obj_blacklist.abuseipdb_total_reports,
                abuseipdb_num_distinct_users=obj_blacklist.abuseipdb_num_distinct_users,
                virustotal_reputation=obj_blacklist.virustotal_reputation,
                virustotal_harmless=obj_blacklist.virustotal_harmless,
                virustotal_malicious=obj_blacklist.virustotal_malicious,
                virustotal_suspicious=obj_blacklist.virustotal_suspicious,
                virustotal_undetected=obj_blacklist.virustotal_undetected,
                ipvoid_detection_count=obj_blacklist.ipvoid_detection_count,
                risk_recommended_pulsedive=obj_blacklist.risk_recommended_pulsedive,
                last_reported_at=obj_blacklist.last_reported_at,
                src_longitude=obj_blacklist.src_longitude,
                src_latitude=obj_blacklist.src_latitude,
            )
        )
        ip_addresses.append(obj_blacklist.ip_address)

    try:
        # Criação em lote
        Tarpit.objects.bulk_create(tarpit_objs)
        logger.info(f"{len(tarpit_objs)} IPs migrados da blacklist para a tarpit.")

        # Deleta da bl_address_local em uma única query
        if ip_addresses:
            conn = psycopg2.connect(
                host=POSTGRES_HOST,
                dbname=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
                port=POSTGRES_PORT,
            )
            cur = conn.cursor()
            cur.execute("SET TIMEZONE TO 'America/Fortaleza';")
            delete_query = "DELETE FROM bl_address_local WHERE ip_address = ANY(%s)"
            cur.execute(delete_query, (ip_addresses,))
            conn.commit()
            conn.close()
            logger.info(f"{len(ip_addresses)} IPs removidos de bl_address_local.")

        # Deleta os objetos da blacklist Django
        queryset.delete()

        # Refaz filtragem
        for ip in ip_addresses:
            filter_and_classify_ip(ip)

    except Exception as e:
        logger.error(f"Erro ao processar atualização da blacklist: {e}")
