import requests
import logging
from core import settings

logger = logging.getLogger(__name__)


class SearchIPVoid:
    @staticmethod
    def get_ipvoid_report(ip_address):
        url = "https://api.apivoid.com/v2/ip-reputation"

        for key in settings.API_KEY_APIVOID:
            headers = {"Content-Type": "application/json", "X-API-Key": key}
            data_to_send = {"ip": ip_address}

            try:
                response = requests.post(url, headers=headers, json=data_to_send)

                if response.status_code == 200:
                    data = response.json()
                    return data
                elif response.status_code in (429, 401):
                    logger.error(
                        f"Erro {response.status_code} na chave do APIVoid, tentando próxima..."
                    )
                    continue
                else:
                    logger.error(f"Erro inesperado APIVoid: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta APIVoid: {str(e)}")
                continue

        logger.error("Todas as chaves do APIVoid falharam.")
        return None