import logging
import time
import json
import os
from apps.netcontrol.models import Blacklist, Whitelist, Suspect, Analysis
from concurrent.futures import ThreadPoolExecutor
from apps.netcontrol.externals.abuseipdb import SearchAbuse
from apps.netcontrol.externals.virustotal import SearchVirusTotal
from apps.netcontrol.externals.apivoid import SearchIPVoid
from apps.netcontrol.externals.pulsedive import SearchPulsedive
from apps.netcontrol.ia_model.ip_prediction import IPClassificationPredictor
from utils.time import timed_call
from utils.convert_datetime import convert_unix_to_datetime
from utils.pulsedive_utils import apply_riskfactors_to_pending_record
from core import settings


logger = logging.getLogger(__name__)

EXISTING_TABLES = [
    (Blacklist, "exists_in_api_blacklist"),
    (Suspect, "exists_in_api_suspect"),
    (Whitelist, "exists_in_api_whitelist"),
]

MODEL_MAP = {
    "denylist": Blacklist,
    "allowlist": Whitelist,
    "suspicious": Suspect,
}

MODEL_NAME = "Decision Tree"

MODELS_DIR = os.path.join(
    settings.BASE_DIR,
    "apps/netcontrol/ia_model/data/models"
)

SCALER_PARAMS_FILE = os.path.join(
    settings.BASE_DIR,
    "apps/netcontrol/ia_model/scaler_params.pkl"
)


def check_existing_ip(ip_address):
    """
    Verifica se o IP já existe em alguma tabela final.
    """
    for table, verdict in EXISTING_TABLES:
        obj = table.objects.filter(ip_address=ip_address).first()
        if obj:
            logger.info(f"IP {ip_address} já existe em {table.__name__}")
            return verdict, obj
    
    return None, None


def enrich_ip(ip_address):
    timings = {}
    start_total = time.perf_counter()

    with ThreadPoolExecutor() as executor:
        futures = {
            "abuse": executor.submit(
                timed_call,
                "abuse",
                SearchAbuse.get_abuseipdb_report,
                ip_address,
                timings=timings,
            ),
            "virustotal": executor.submit(
                timed_call,
                "virustotal",
                SearchVirusTotal.get_virustotal_report,
                ip_address,
                timings=timings,
            ),
            "apivoid": executor.submit(
                timed_call,
                "apivoid",
                SearchIPVoid.get_ipvoid_report,
                ip_address,
                timings=timings,
            ),
            "pulsedive": executor.submit(
                timed_call,
                "pulsedive",
                SearchPulsedive.get_pulsedive_report,
                ip_address,
                timings=timings,
            ),
        }

        responses = {}
        for key, future in futures.items():
            try:
                responses[key] = future.result()
            except Exception:
                logger.exception(f"Erro ao consultar API {key}")
                responses[key] = None

    timings["external_apis_total"] = round((time.perf_counter() - start_total) * 1000, 3)

    logger.info(f"TIMINGS {ip_address}: {timings}")

    return responses, timings


def apply_reports(pending_record, responses):
    if responses.get("abuse"):
        abuse = responses["abuse"].get("data", {})
        pending_record.abuseipdb_confidence_score = abuse.get("abuseConfidenceScore")
        pending_record.abuseipdb_total_reports = abuse.get("totalReports")
        pending_record.abuseipdb_num_distinct_users = abuse.get("numDistinctUsers")
        pending_record.abuseipdb_last_reported_at = abuse.get("lastReportedAt")
        pending_record.abuseipdb_country_code = abuse.get("countryCode")
        pending_record.abuseipdb_is_whitelisted = abuse.get("isWhitelisted")

    if responses.get("virustotal"):
        vt = responses["virustotal"].get("data", {}).get("attributes", {})
        stats = vt.get("last_analysis_stats", {})

        pending_record.virustotal_reputation = vt.get("reputation")
        pending_record.virustotal_harmless = stats.get("harmless")
        pending_record.virustotal_malicious = stats.get("malicious")
        pending_record.virustotal_suspicious = stats.get("suspicious")
        pending_record.virustotal_undetected = stats.get("undetected")

        pending_record.virustotal_last_modification_date = convert_unix_to_datetime(
            vt.get("last_modification_date")
        )

    if responses.get("apivoid"):
        apv = responses["apivoid"]
        pending_record.apivoid_risk_score = apv["risk_score"]["result"]
        pending_record.apivoid_blacklists_engines_count = apv["blacklists"]["engines_count"]
        pending_record.apivoid_blacklists_detection_rate = float(
            apv["blacklists"]["detection_rate"].replace("%", "")
        )
        pending_record.apivoid_country_name = apv["information"]["country_name"]

    if responses.get("pulsedive"):
        pd = responses["pulsedive"]
        pending_record.risk_recommended_pulsedive = pd.get("risk_recommended", "unknown")
        pending_record.stamp_updated_pulsedive = pd.get("stamp_updated")
        pending_record.unknown_pulsedive = 0

        apply_riskfactors_to_pending_record(
            pd.get("riskfactors"),
            pending_record,
        )

    pending_record.save()
    return pending_record


def persist_classification(data, classification):
    model = MODEL_MAP.get(classification)
    if not model:
        raise ValueError(f"Classificação inválida: {classification}")

    orm_data = data.copy()
    orm_data["ip_address"] = orm_data.pop("ip")
    orm_data.pop("verdict", None)

    return model.objects.create(**orm_data)


class IpClassificationService:
    @staticmethod
    def filter_and_classify_ip(ip_address):
        logger.info(f"Iniciando classificação do IP {ip_address}")

        pending = Analysis.objects.filter(ip_address=ip_address).first()
        if not pending:
            logger.warning("IP não encontrado na tabela analysis")
            return {"verdict": "none"}

        verdict, existing_obj = check_existing_ip(ip_address)
        if verdict:
            pending.delete()
            return {"verdict": verdict, "ip_address": existing_obj.ip_address}

        service_start = time.perf_counter()

        responses, api_timings = enrich_ip(ip_address)
        pending = apply_reports(pending, responses)

        data = pending.to_classification_dict()
        logger.info(json.dumps(data, indent=2, default=str))

        predictor = IPClassificationPredictor(
            MODELS_DIR,
            SCALER_PARAMS_FILE,
            MODEL_NAME,
        )

        result = predictor.predict_classification(data)

        service_total = (time.perf_counter() - service_start) * 1000
        api_timings["service_total"] = round(service_total, 3)
        api_timings["internal_api_total"] = round(
            service_total - api_timings.get("external_apis_total", 0), 3
        )
        classification = list(result.values())[0]["classification"]

        pending.delete()
        persist_classification(data, classification)

        data["verdict"] = classification
        data["_timings"] = api_timings
        return data
