import logging
import os
from datetime import timedelta
from django.utils.timezone import now
from .externals import SearchAbuse
from .models import Blacklist, Analysis, Whitelist, Suspect
from .services import filter_and_classify_ip, insert_new_blacklist_entries
from collect.tarpit_rules import remove_ip_from_iptables_tarpit
from collect.blacklist_rules import remove_ip_from_iptables_blacklist
from collect.whitelist_rules import remove_ip_from_iptables_whitelist

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


# Função pra verificar IPs antigos de todas as tabelas
def reprocess_old_ips(model_class, old_days=3):
    logger = setup_logging()

    threshold_date = now() - timedelta(days=old_days)
    queryset = model_class.objects.filter(timestamp_added__lt=threshold_date)

    logger.info(
        f"Reprocessando {queryset.count()} IPs antigos de {model_class.__name__}"
    )

    for record in queryset:
        ip = record.ip_address
        try:
            # Chama a função de classificação
            data = filter_and_classify_ip(ip)

            if not data or "verdict" not in data:
                logger.warning(f"IP {ip} retornou dados inválidos ou sem veredito")
                continue

            verdict = data["verdict"]
            logger.info(f"IP {ip} veredito após reprocessamento: {verdict}")

            # Atualiza Analysis com os dados e veredito
            Analysis.objects.update_or_create(
                ip_address=ip, defaults={**data, "verdict": verdict}
            )

            # Remove do IPTables e do Redis
            if model_class == Blacklist and verdict != "blacklist":
                remove_ip_from_iptables_blacklist(ip)
                logger.info(f"IP {ip} removido da chain BLACKLIST e Redis (antes blacklist)")
            elif model_class == Whitelist and verdict != "whitelist":
                remove_ip_from_iptables_whitelist(ip)
                logger.info(f"IP {ip} removido da chain WHITELIST e Redis (antes whitelist)")
            elif model_class == Suspect and verdict in ["whitelist", "blacklist"]:
                remove_ip_from_iptables_tarpit(ip)
                logger.info(f"IP {ip} removido da chain TARPIT e Redis (antes suspect)")


            # Remove o registro antigo da tabela original
            record.delete()

        except Exception as e:
            logger.error(f"Erro ao reprocessar IP {ip}: {e}")


def reprocess_old_blacklist_ips():
    reprocess_old_ips(Blacklist, old_days=3)

def reprocess_old_whitelist_ips():
    reprocess_old_ips(Whitelist, old_days=3)

def reprocess_old_suspect_ips():
    reprocess_old_ips(Suspect, old_days=3)