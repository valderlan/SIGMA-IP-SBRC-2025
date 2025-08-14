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


# Função pra requisitar novos IPs pra blacklist
def update_blacklist():
    logger = setup_logging()
    logger.info("Buscando IPs para atualizar a Blacklist...")
    blacklist_records = SearchAbuse.search_abuse_blacklist()
    if blacklist_records:
        insert_new_blacklist_entries(blacklist_records)


# Função para verificar IPs antigos da Whitelist
def reprocess_old_whitelist_ips():
    logger = setup_logging()

    three_days_ago = now() - timedelta(days=3)
    queryset = Whitelist.objects.filter(timestamp_added__lt=three_days_ago)

    tarpit_records = []
    ip_addresses = []

    for whitelist_record in queryset:
        tarpit_records.append(
            Tarpit(
                ip_address=whitelist_record.ip_address,
                country_code=whitelist_record.country_code,
                city=whitelist_record.city,
                abuseipdb_confidence_score=whitelist_record.abuseipdb_confidence_score,
                abuseipdb_total_reports=whitelist_record.abuseipdb_total_reports,
                abuseipdb_num_distinct_users=whitelist_record.abuseipdb_num_distinct_users,
                virustotal_reputation=whitelist_record.virustotal_reputation,
                virustotal_harmless=whitelist_record.virustotal_harmless,
                virustotal_malicious=whitelist_record.virustotal_malicious,
                virustotal_suspicious=whitelist_record.virustotal_suspicious,
                virustotal_undetected=whitelist_record.virustotal_undetected,
                ipvoid_detection_count=whitelist_record.ipvoid_detection_count,
                risk_recommended_pulsedive=whitelist_record.risk_recommended_pulsedive,
                last_reported_at=whitelist_record.last_reported_at,
                src_longitude=whitelist_record.src_longitude,
                src_latitude=whitelist_record.src_latitude,
            )
        )
        ip_addresses.append(whitelist_record.ip_address)

    try:
        # Cria os objetos de uma vez na tarpit
        Tarpit.objects.bulk_create(tarpit_records)
        logger.info(f"{len(tarpit_records)} IPs inseridos na tarpit.")

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

    three_days_ago = now() - timedelta(days=3)
    queryset = Blacklist.objects.filter(timestamp_added__lt=three_days_ago)

    tarpit_records = []
    ip_addresses = []

    for blacklist_records in queryset:
        tarpit_records.append(
            Tarpit(
                ip_address=blacklist_records.ip_address,
                country_code=blacklist_records.country_code,
                city=blacklist_records.city,
                abuseipdb_confidence_score=blacklist_records.abuseipdb_confidence_score,
                abuseipdb_total_reports=blacklist_records.abuseipdb_total_reports,
                abuseipdb_num_distinct_users=blacklist_records.abuseipdb_num_distinct_users,
                virustotal_reputation=blacklist_records.virustotal_reputation,
                virustotal_harmless=blacklist_records.virustotal_harmless,
                virustotal_malicious=blacklist_records.virustotal_malicious,
                virustotal_suspicious=blacklist_records.virustotal_suspicious,
                virustotal_undetected=blacklist_records.virustotal_undetected,
                ipvoid_detection_count=blacklist_records.ipvoid_detection_count,
                risk_recommended_pulsedive=blacklist_records.risk_recommended_pulsedive,
                last_reported_at=blacklist_records.last_reported_at,
                src_longitude=blacklist_records.src_longitude,
                src_latitude=blacklist_records.src_latitude,
            )
        )
        ip_addresses.append(blacklist_records.ip_address)

    try:
        # Criação em lote
        Tarpit.objects.bulk_create(tarpit_records)
        logger.info(f"{len(tarpit_records)} IPs migrados da blacklist para a tarpit.")

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
