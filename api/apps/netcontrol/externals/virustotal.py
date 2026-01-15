import requests
import logging
from core import settings

logger = logging.getLogger(__name__)


class SearchVirusTotal:
    @staticmethod
    def get_virustotal_report(ip_address):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

        for key in settings.API_KEY_VIRUSTOTAL:
            headers = {"Accept": "application/json", "x-apikey": key}

            try:
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(
                        f"Erro {response.status_code} na chave do VirusTotal, tentando próxima..."
                    )
                    continue
                else:
                    logger.error(f"Erro inesperado VirusTotal: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta VirusTotal: {str(e)}")
                continue

        logger.error("Todas as chaves do VirusTotal falharam.")
        return None
