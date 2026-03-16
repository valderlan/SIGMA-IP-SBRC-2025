import requests
import logging
from core import settings

logger = logging.getLogger(__name__)


class SearchAbuse:
    @staticmethod
    def search_abuse_blacklist():
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        params = {"confidenceMinimum": 75, "limit": 9999999}

        for key in settings.API_KEY_ABUSE:
            headers = {"Key": key, "Accept": "application/json"}

            try:
                response = requests.get(url, headers=headers, params=params)
                logger.info(f"Response AbuseIPDB: {response}")

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(
                        f"Erro {response.status_code} com a chave do AbuseIPDB, tentando próxima..."
                    )
                    continue
                else:
                    logger.error(f"Erro inesperado AbuseIPDB: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta AbuseIPDB: {str(e)}")
                continue

        logger.error("Todas as chaves do AbuseIPDB falharam.")
        return None

    @staticmethod
    def get_abuseipdb_report(ip_address):
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip_address, "maxAgeInDays": 15, "verbose": ""}

        for key in settings.API_KEY_ABUSE:
            headers = {"Key": key, "Accept": "application/json"}

            try:
                response = requests.get(url, headers=headers, params=params)
                logger.info(f"Response AbuseIPDB: {response}")

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(
                        f"Erro {response.status_code} na chave do AbuseIPDB, tentando próxima..."
                    )
                    continue
                else:
                    logger.error(
                        f"Erro inesperado AbuseIPDB Check: {response.status_code}"
                    )
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta AbuseIPDB: {str(e)}")
                continue

        logger.error("Todas as chaves do AbuseIPDB falharam.")
        return None