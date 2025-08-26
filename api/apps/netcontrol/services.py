import os
import logging
from datetime import datetime
from dotenv import load_dotenv
from django.db import IntegrityError
from .models import Blacklist, Whitelist, Analysis, Suspect
from .externals import SearchAbuse, SearchVirusTotal, SearchIPVoid, SearchPulsedive
from concurrent.futures import ThreadPoolExecutor
from apps.netcontrol.ia_model.ip_prediction import IPClassificationPredictor

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
                last_reported_at=formatted_date,
            )
            blacklist_entries.append(data)
            logger.info(f"O IP {ip_address} foi adicionado à lista para inserção.")

    if blacklist_entries:
        try:
            # Utilizando bulk_create para inserir todos de uma vez
            Blacklist.objects.bulk_create(blacklist_entries)
            logger.info(
                f"{len(blacklist_entries)} IPs foram inseridos no banco com sucesso."
            )
        except IntegrityError as e:
            logger.error(f"Erro de integridade ao tentar inserir os dados: {e}")


def fetch_and_update_ip_reputation_data(pending_record):
    logger = logging.getLogger(__name__)

    with ThreadPoolExecutor() as executor:
        # Faz as requisições para as APIs paralelamente
        futures = {
            "abuse": executor.submit(SearchAbuse.get_abuseipdb_report, pending_record),
            "virustotal": executor.submit(
                SearchVirusTotal.get_virustotal_report, pending_record
            ),
            "ipvoid": executor.submit(SearchIPVoid.get_ipvoid_report, pending_record),
            "pulsedive": executor.submit(
                SearchPulsedive.get_pulsedive_report, pending_record
            ),
        }

        responses = {}
        for key, future in futures.items():
            try:
                responses[key] = future.result()
            except Exception as e:
                logger.error(f"Erro ao buscar na API {key}: {e}")
                responses[key] = None

    # Processar as respostas e salvar no objeto
    if responses.get("abuse"):
        report_abuse = responses["abuse"].get("data", {})
        pending_record.abuseipdb_confidence_score = report_abuse.get(
            "abuseConfidenceScore"
        )
        pending_record.last_reported_at = report_abuse.get("lastReportedAt")
        pending_record.abuseipdb_total_reports = report_abuse.get("totalReports")
        pending_record.abuseipdb_num_distinct_users = report_abuse.get(
            "numDistinctUsers"
        )

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

    if responses.get("ipvoid"):
        report_ipvoid = (
            responses["ipvoid"].get("data", {}).get("report", {}).get("blacklists", {})
        )
        pending_record.ipvoid_detection_count = report_ipvoid.get("detections", 0)
    else:
        pending_record.ipvoid_detection_count = 0
        # Para quando as chaves estiverem funcionando
        # return None

    if responses.get("pulsedive"):
        report_pulsedive = responses["pulsedive"]
        pending_record.risk_recommended_pulsedive = report_pulsedive.get(
            "risk_recommended", "unknown"
        )
    else:
        pending_record.risk_recommended_pulsedive = "unknown"

    logger.info(f"IPVOID_DETECTION_COUNT = {pending_record.ipvoid_detection_count}")
    logger.info(
        f"RISK_RECOMMENDED_PULSEDIVE = {pending_record.risk_recommended_pulsedive}"
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
            "country_code": obj_model.country_code,
            "city": obj_model.city,
            "abuseipdb_confidence_score": obj_model.abuseipdb_confidence_score,
            "abuseipdb_total_reports": obj_model.abuseipdb_total_reports,
            "abuseipdb_num_distinct_users": obj_model.abuseipdb_num_distinct_users,
            "virustotal_reputation": obj_model.virustotal_reputation,
            "virustotal_harmless": obj_model.virustotal_harmless,
            "virustotal_malicious": obj_model.virustotal_malicious,
            "virustotal_suspicious": obj_model.virustotal_suspicious,
            "virustotal_undetected": obj_model.virustotal_undetected,
            "ipvoid_detection_count": obj_model.ipvoid_detection_count,
            "risk_recommended_pulsedive": obj_model.risk_recommended_pulsedive,
            "last_reported_at": obj_model.last_reported_at,
            "src_longitude": obj_model.src_longitude,
            "src_latitude": obj_model.src_latitude,
        }

    return None


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

            if pending_record:
                logger.info(
                    f"--- Dados coletados para o IP {pending_record.ip_address} ---"
                )
                logger.info(
                    f"abuseipdb_confidence_score: {pending_record.abuseipdb_confidence_score}"
                )
                logger.info(
                    f"abuseipdb_total_reports: {pending_record.abuseipdb_total_reports}"
                )
                logger.info(
                    f"abuseipdb_num_distinct_users: {pending_record.abuseipdb_num_distinct_users}"
                )
                logger.info(
                    f"ipvoid_detection_count: {pending_record.ipvoid_detection_count}"
                )
                logger.info(
                    f"risk_recommended_pulsedive: {pending_record.risk_recommended_pulsedive}"
                )
                logger.info(
                    f"virustotal_reputation: {pending_record.virustotal_reputation}"
                )
                logger.info(
                    f"virustotal_harmless: {pending_record.virustotal_harmless}"
                )
                logger.info(
                    f"virustotal_malicious: {pending_record.virustotal_malicious}"
                )
                logger.info(
                    f"virustotal_suspicious: {pending_record.virustotal_suspicious}"
                )
                logger.info(
                    f"virustotal_undetected: {pending_record.virustotal_undetected}"
                )
                logger.info("-------------------------------------------------------")

                data = {
                    "ip_address": pending_record.ip_address,
                    "abuseipdb_confidence_score": pending_record.abuseipdb_confidence_score,
                    "abuseipdb_total_reports": pending_record.abuseipdb_total_reports,
                    "abuseipdb_num_distinct_users": pending_record.abuseipdb_num_distinct_users,
                    "ipvoid_detection_count": pending_record.ipvoid_detection_count,
                    "risk_recommended_pulsedive": pending_record.risk_recommended_pulsedive,
                    "virustotal_malicious": pending_record.virustotal_malicious,
                    "virustotal_reputation": pending_record.virustotal_reputation,
                    "virustotal_suspicious": pending_record.virustotal_suspicious,
                    "virustotal_undetected": pending_record.virustotal_undetected,
                    "virustotal_harmless": pending_record.virustotal_harmless,
                }

            predictor = IPClassificationPredictor(
                MODELS_DIR, SCALER_PARAMS_FILE, MODEL_NAME
            )

            results = predictor.predict_classification(data)

            # Preenche os dados completos antes da salvar
            data.update(
                {
                    "country_code": pending_record.country_code,
                    "city": pending_record.city,
                    "last_reported_at": pending_record.last_reported_at,
                    "src_longitude": pending_record.src_longitude,
                    "src_latitude": pending_record.src_latitude,
                }
            )

            pending_record.delete()

            classification = list(results.values())[0]["classification"]
            print(classification)

            target_model = {
                "denylist": Blacklist,
                "suspicious": Suspect,
                "allowlist": Whitelist,
            }.get(classification)

            if target_model:
                target_model.objects.create(**data)
                if classification == "allowlist":
                    data["verdict"] = "whitelist"
                elif classification == "denylist":
                    data["verdict"] == "blacklist"
                elif classification == "suspicious":
                    data["verdict"] == "suspect"
                return data

        else:
            logger.warning(
                "Não foi possível checar a reputação do IP com as APIs externas."
            )
            logger.info(f"Movendo o IP {ip_address} para a Blacklist.")

            Blacklist.objects.create(ip_address=ip_address)

            # Deleta o objeto da analysis
            Analysis.objects.filter(ip_address=ip_address).delete()

            return {"verdict": "blacklist"}

    except Analysis.DoesNotExist:
        logger.warning("Nenhum registro encontrado na tabela analysis")
        return {"verdict": "none"}
