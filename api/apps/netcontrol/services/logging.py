import os
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_LOGS_PATH = os.path.join(BASE_DIR, "..", "api_outputs", "sigma_api.log")


def setup_logging():
    os.makedirs(os.path.dirname(API_LOGS_PATH), exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(API_LOGS_PATH),
            logging.StreamHandler(),
        ],
    )