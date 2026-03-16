import os
import logging
import json
import time
from datetime import datetime
from dotenv import load_dotenv
from django.db import IntegrityError
from .models import Blacklist, Whitelist, Analysis, Suspect
from .externals.abuseipdb import SearchAbuse
from .externals.virustotal import SearchVirusTotal
from .externals.apivoid import SearchIPVoid
from .externals.pulsedive import SearchPulsedive
from concurrent.futures import ThreadPoolExecutor
from apps.netcontrol.ia_model.ip_prediction import IPClassificationPredictor
from utils.convert_datetime import convert_unix_to_datetime
from utils.pulsedive_utils import apply_riskfactors_to_pending_record
from utils.time import timed_call, write_timing_csv


load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_LOGS_PATH = os.path.join(BASE_DIR, "api_outputs", "sigma_api.log")

MODEL_NAME = "Decision Tree"
MODELS_DIR = os.path.join(BASE_DIR, "ia_model", "data", "models")
SCALER_PARAMS_FILE = os.path.join(BASE_DIR, "ia_model", "scaler_params.pkl")


def setup_logging(log_file=API_LOGS_PATH):
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


def ip_exists_in_blacklist(ip_address):
        logger = logging.getLogger(__name__)

        logger.info(f"Verificando se o IP {ip_address} já existe no banco de dados.")
        ip_query = Blacklist.objects.filter(ip_address=ip_address)

        if ip_query.exists():
            logger.warning(f"O IP {ip_address} já existe na Blacklist.")
            return True
        else:
            return False


def insert_new_blacklist_entries(dados):
    logger = logging.getLogger(__name__)

    # Lista pra inserir vários objetos na blacklist em uma única conexão com o banco
    blacklist_entries = []

    for entry in dados["data"]:
        formatted_date = datetime.strptime(
            entry["lastReportedAt"], "%Y-%m-%dT%H:%M:%S+00:00"
        ).isoformat()

        ip_address = entry["ipAddress"]

        if not ip_exists_in_blacklist(ip_address):
            data = Blacklist(
                ip_address=entry["ipAddress"],
                country_code=entry["countryCode"],
                abuseipdb_confidence_score=entry["abuseConfidenceScore"],
                abuseipdb_last_reported_at=formatted_date,
            )
            blacklist_entries.append(data)
            logger.info(f"O IP {ip_address} foi adicionado à lista para inserção.")

    if blacklist_entries:
        try:
            # Utilizando bulk_create para inserir todos de uma vez
            Blacklist.objects.bulk_create(blacklist_entries)
            logger.info(f"{len(blacklist_entries)} IPs foram inseridos no banco com sucesso.")
        except IntegrityError as e:
            logger.error(f"Erro de integridade ao tentar inserir os dados: {e}")


def fetch_and_update_ip_reputation_data(pending_record):
    timings = {}
    start_total = time.perf_counter()
    
    logger = logging.getLogger(__name__)

    with ThreadPoolExecutor() as executor:
        # Faz as requisições para as APIs paralelamente
        futures = {
            "abuse": executor.submit(
                timed_call, 
                "abuse", 
                SearchAbuse.get_abuseipdb_report, 
                pending_record.ip_address, 
                timings=timings
            ),
            "virustotal": executor.submit(
                timed_call, 
                "virustotal", 
                SearchVirusTotal.get_virustotal_report, 
                pending_record.ip_address, 
                timings=timings
            ),
            "apivoid": executor.submit(
                timed_call, 
                "apivoid", 
                SearchIPVoid.get_ipvoid_report, 
                pending_record.ip_address, 
                timings=timings
            ),
            "pulsedive": executor.submit(
                timed_call, 
                "pulsedive", 
                SearchPulsedive.get_pulsedive_report, 
                pending_record.ip_address, 
                timings=timings
            ),
        }

        responses = {}
        for key, future in futures.items():
            try:
                responses[key] = future.result()
            except Exception as e:
                logger.error(f"Erro ao buscar na API {key}: {e}")
                responses[key] = None

    timings["total"] = round((time.perf_counter() - start_total) * 1000, 3)

    logger.info(f"TIMINGS CAPTURADOS: {timings}")

    write_timing_csv(pending_record.ip_address, timings)

    # Processar as respostas e salvar no objeto
    if responses.get("abuse"):
        report_abuse = responses["abuse"].get("data", {})
        pending_record.abuseipdb_confidence_score = report_abuse.get("abuseConfidenceScore")
        pending_record.abuseipdb_total_reports = report_abuse.get("totalReports")
        pending_record.abuseipdb_num_distinct_users = report_abuse.get("numDistinctUsers")
        pending_record.abuseipdb_recent_reports_count = report_abuse.get("")
        pending_record.abuseipdb_last_reported_at = report_abuse.get("lastReportedAt")
        pending_record.abuseipdb_country_code = report_abuse.get("countryCode")
        pending_record.abuseipdb_is_whitelisted = report_abuse.get("isWhitelisted")

    if responses.get("virustotal"):
        report_virustotal = (
            responses["virustotal"].get("data", {}).get("attributes", {})
        )
        report_virustotal_meta = report_virustotal.get("last_analysis_stats", {})
        pending_record.virustotal_reputation = report_virustotal.get("reputation")
        pending_record.virustotal_harmless = report_virustotal_meta.get("harmless")
        pending_record.virustotal_malicious = report_virustotal_meta.get("malicious")
        pending_record.virustotal_suspicious = report_virustotal_meta.get("suspicious")
        pending_record.virustotal_undetected = report_virustotal_meta.get("undetected")

        vt_last_modification = report_virustotal.get("last_modification_date")
        pending_record.virustotal_last_modification_date = convert_unix_to_datetime(vt_last_modification)


    if responses.get("apivoid"):
        report_apivoid = responses["apivoid"]
        pending_record.apivoid_risk_score = report_apivoid["risk_score"]["result"]
        pending_record.apivoid_blacklists_engines_count = report_apivoid["blacklists"]["engines_count"]
        rate_raw = report_apivoid["blacklists"]["detection_rate"]  # "32%"
        apivoid_blacklists_detection_rate = float(rate_raw.replace("%", ""))
        pending_record.apivoid_blacklists_detection_rate = apivoid_blacklists_detection_rate
        pending_record.apivoid_country_name = report_apivoid["information"]["country_name"]


    if responses.get("pulsedive"):
        report_pulsedive = responses["pulsedive"]
        pending_record.risk_recommended_pulsedive = report_pulsedive.get("risk_recommended", "unknown")
        pending_record.stamp_updated_pulsedive = report_pulsedive["stamp_updated"]
        pending_record.unknown_pulsedive = 0
        # pending_record.none_pulsedive = 0
        # pending_record.low_pulsedive = 0
        # pending_record.medium_pulsedive = 0
        # pending_record.high_pulsedive = 0
        # pending_record.critical_pulsedive = 0
        apply_riskfactors_to_pending_record(
            report_pulsedive.get("riskfactors"),
            pending_record
        )

    return pending_record


def check_existing_ip_entry(pending_record, table, verdict):
    """
    Verifica se o IP está na Blacklist, Whitelist ou Suspect da API.
    Se estiver, remove da analysis e retorna os detalhes do IP.
    """
    logger = logging.getLogger(__name__)

    if table.objects.filter(ip_address=pending_record.ip_address).exists():
        logger.info(
            f"O IP {pending_record.ip_address} já existe na {table.__name__}. Removendo da analysis."
        )

        pending_record.delete()
        obj_model = table.objects.get(ip_address=pending_record.ip_address)

        return {
            "verdict": verdict,
            "ip_address": obj_model.ip_address,

            # Geolocalização
            "country_code": obj_model.country_code,
            "city": obj_model.city,
            "src_latitude": obj_model.src_latitude,
            "src_longitude": obj_model.src_longitude,

            # AbuseIPDB
            "abuseipdb_confidence_score": obj_model.abuseipdb_confidence_score,
            "abuseipdb_total_reports": obj_model.abuseipdb_total_reports,
            "abuseipdb_num_distinct_users": obj_model.abuseipdb_num_distinct_users,
            "abuseipdb_recent_reports_count": obj_model.abuseipdb_recent_reports_count,
            "abuseipdb_last_reported_at": obj_model.abuseipdb_last_reported_at,
            "abuseipdb_country_code": obj_model.abuseipdb_country_code,
            "abuseipdb_is_whitelisted": obj_model.abuseipdb_is_whitelisted,

            # VirusTotal
            "virustotal_reputation": obj_model.virustotal_reputation,
            "virustotal_harmless": obj_model.virustotal_harmless,
            "virustotal_malicious": obj_model.virustotal_malicious,
            "virustotal_suspicious": obj_model.virustotal_suspicious,
            "virustotal_undetected": obj_model.virustotal_undetected,
            "virustotal_last_modification_date": obj_model.virustotal_last_modification_date,

            # IPVoid
            "apivoid_risk_score": obj_model.apivoid_risk_score,
            "apivoid_blacklists_engines_count": obj_model.apivoid_blacklists_engines_count,
            "apivoid_blacklists_detection_rate": obj_model.apivoid_blacklists_detection_rate,
            "apivoid_country_name": obj_model.apivoid_country_name,

            # Pulsedive
            "risk_recommended_pulsedive": obj_model.risk_recommended_pulsedive,
            "stamp_updated_pulsedive": obj_model.stamp_updated_pulsedive,
            "unknown_pulsedive": obj_model.unknown_pulsedive,
        }

    return None


class IpClassificationService:
    @staticmethod
    def filter_and_classify_ip(ip_address):
        logger = setup_logging()

        try:
            # Pega o objeto da analysis pelo IP
            pending_record = Analysis.objects.get(ip_address=ip_address)

            # Verifica se o IP já está na Blacklist, Suspect ou Whitelist
            for table, verdict in [
                (Blacklist, "exists_in_api_blacklist"),
                (Suspect, "exists_in_api_suspect"),
                (Whitelist, "exists_in_api_whitelist"),
            ]:
                check_result = check_existing_ip_entry(pending_record, table, verdict)

                if check_result:
                    return check_result

            # Executando buscas paralelas para atualizar pending_record
            pending_record = fetch_and_update_ip_reputation_data(pending_record)

            if pending_record:
                logger.info(f"Iniciando filtragem do IP {pending_record.ip_address}")
                logger.info(f"--- Dados coletados para o IP {pending_record.ip_address} ---")
                data = pending_record.to_classification_dict()
                logger.info(json.dumps(data, indent=2, default=str))

                predictor = IPClassificationPredictor(
                    MODELS_DIR, SCALER_PARAMS_FILE, MODEL_NAME
                )

                results = predictor.predict_classification(data)

                # Preenche os dados completos antes da salvar
                data.update(
                    {
                        "country_code": pending_record.country_code,
                        "city": pending_record.city,
                        "abuseipdb_last_reported_at": pending_record.abuseipdb_last_reported_at,
                        "src_longitude": pending_record.src_longitude,
                        "src_latitude": pending_record.src_latitude,
                    }
                )

                pending_record.delete()

                classification = list(results.values())[0]["classification"]
                logger.info(f"Classificação final: {classification}")

                target_model = {
                    "denylist": Blacklist,
                    "suspicious": Suspect,
                    "allowlist": Whitelist,
                }.get(classification)

                if target_model:
                    orm_data = data.copy()

                    orm_data["ip_address"] = orm_data.pop("ip")

                    # Remove campos que não existem no model
                    orm_data.pop("verdict", None)

                    target_model.objects.create(**orm_data)

                    if classification == "allowlist":
                        data["verdict"] = "whitelist"
                    elif classification == "denylist":
                        data["verdict"] = "blacklist"
                    elif classification == "suspicious":
                        data["verdict"] = "suspect"

                    return data
                
            logger.error(f"Classificação desconhecida: {classification}")

            # Deleta o objeto da analysis
            Analysis.objects.filter(ip_address=ip_address).delete()

            return {"verdict": "error", "classification": classification}

        except Analysis.DoesNotExist:
            logger.warning("Nenhum registro encontrado na tabela analysis")
            return {"verdict": "none"}
