import requests
import logging
from core import settings

logger = logging.getLogger(__name__)


class SearchPulsedive:
    @staticmethod
    def get_pulsedive_report(ip_address):
        url = "https://pulsedive.com/api/info.php"

        for key in settings.API_KEY_PULSEDIVE:
            params = {"key": key, "indicator": ip_address, "pretty": 1}

            try:
                response = requests.get(url, params=params)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code in (429, 401):
                    logger.error(
                        f"Erro {response.status_code} na chave do Pulsedive, tentando próxima..."
                    )
                    continue
                else:
                    logger.error(f"Erro inesperado Pulsedive: {response.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Exceção na consulta Pulsedive: {str(e)}")
                continue

        logger.error("Todas as chaves do Pulsedive falharam.")
        return None