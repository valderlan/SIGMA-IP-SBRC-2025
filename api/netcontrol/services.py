import os
from datetime import datetime
from dotenv import load_dotenv
from django.db import IntegrityError
from .models import Blacklist, Whitelist, Tarpit, Suspect
from .externals import SearchAbuse, SearchVirusTotal, SearchIPVoid, SearchPulsedive
from concurrent.futures import ThreadPoolExecutor
import json
import time
import csv
import ast
import logging
import pandas as pd
from netcontrol.ia_model.query import main as classificar_ip

load_dotenv()

API_KEY = json.loads(os.getenv("API_KEY", "[]"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, 'ia_model', 'datasets', 'Total_test1.csv')
CSV_RESULTS_FILE = os.path.join(BASE_DIR, 'ia_model', 'outputs', 'model_timing_results.csv')
API_LOGS_PATH = os.path.join(BASE_DIR, 'api_outputs', 'sigma_api.log')


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


def ip_ja_existe(ip_address):
    logger = logging.getLogger(__name__)

    logger.info(f"Verificando se o IP {ip_address} já existe no banco de dados.")
    requisicao = Blacklist.objects.filter(ip_address=ip_address)

    if requisicao.exists():
        logger.warning(f"O IP {ip_address} já existe na Blacklist.")
        return True
    else:
        return False
    
    
def inserir_dados_no_banco(dados):
    logger = logging.getLogger(__name__)

    # Lista pra inserir vários objetos na blacklist em uma única conexão com o banco
    objetos_para_inserir = []

    for registro in dados['data']:
        data_formatada = datetime.strptime(registro['lastReportedAt'], "%Y-%m-%dT%H:%M:%S+00:00").isoformat()

        ip_address = registro['ipAddress']

        if not ip_ja_existe(ip_address):
            data = Blacklist(
                ip_address=registro['ipAddress'],
                country_code=registro['countryCode'],
                abuseipdb_confidence_score=registro['abuseConfidenceScore'],
                last_reported_at=data_formatada
            )
            objetos_para_inserir.append(data)
            logger.info(f"O IP {ip_address} foi adicionado à lista para inserção.")

    if objetos_para_inserir:
        try:
            # Utilizando bulk_create para inserir todos de uma vez
            Blacklist.objects.bulk_create(objetos_para_inserir)
            logger.info(f"{len(objetos_para_inserir)} IPs foram inseridos no banco com sucesso.")
        except IntegrityError as e:
            logger.error(f"Erro de integridade ao tentar inserir os dados: {e}")


def realizar_buscas_paralelas(obj_tarpit):
    logger = logging.getLogger(__name__)

    with ThreadPoolExecutor() as executor:
        # Faz as requisições para as APIs paralelamente
        futures = {
            "abuse": executor.submit(SearchAbuse.buscar_dados_abuse, obj_tarpit),
            "virustotal": executor.submit(SearchVirusTotal.buscar_dados_virustotal, obj_tarpit),
            "ipvoid": executor.submit(SearchIPVoid.buscar_dados_ipvoid, obj_tarpit),
            "pulsedive": executor.submit(SearchPulsedive.buscar_dados_pulsedive, obj_tarpit),
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
        dados_abuse = responses["abuse"].get('data', {})
        obj_tarpit.abuseipdb_confidence_score = dados_abuse.get('abuseConfidenceScore')
        obj_tarpit.last_reported_at = dados_abuse.get('lastReportedAt')
        obj_tarpit.abuseipdb_total_reports = dados_abuse.get('totalReports')
        obj_tarpit.abuseipdb_num_distinct_users = dados_abuse.get('numDistinctUsers')

    if responses.get("virustotal"):
        dados_virus_total = responses["virustotal"].get('data', {}).get('attributes', {})
        dados_virus_total_meta = dados_virus_total.get('last_analysis_stats', {})
        obj_tarpit.virustotal_reputation = dados_virus_total.get('reputation')
        obj_tarpit.virustotal_harmless = dados_virus_total_meta.get('harmless')
        obj_tarpit.virustotal_malicious = dados_virus_total_meta.get('malicious')
        obj_tarpit.virustotal_suspicious = dados_virus_total_meta.get('suspicious')
        obj_tarpit.virustotal_undetected = dados_virus_total_meta.get('undetected')

    if responses.get("ipvoid"):
        dados_ipvoid = responses["ipvoid"].get('data', {}).get('report', {}).get('blacklists', {})
        obj_tarpit.ipvoid_detection_count = dados_ipvoid.get('detections', 0)
    else:
        obj_tarpit.ipvoid_detection_count = 0
        # Para quando as chaves estiverem funcionando
        # return None

    if responses.get("pulsedive"):
        dados_pulsedive = responses["pulsedive"]
        obj_tarpit.risk_recommended_pulsedive = dados_pulsedive.get('risk_recommended', 'unknown')
    else:
        obj_tarpit.risk_recommended_pulsedive = 'unknown'

    logger.info(f"IPVOID_DETECTION_COUNT = {obj_tarpit.ipvoid_detection_count}")
    logger.info(f"RISK_RECOMMENDED_PULSEDIVE = {obj_tarpit.risk_recommended_pulsedive}")

    return obj_tarpit


def verificar_ip_no_banco(obj_tarpit, tabela, status):
    """
    Verifica se o IP está na Blacklist, Whitelist ou Suspect da API.
    Se estiver, remove da Tarpit e retorna os detalhes do IP. 
    """
    logger = logging.getLogger(__name__)

    if tabela.objects.filter(ip_address=obj_tarpit.ip_address).exists():
        logger.info(f"O IP {obj_tarpit.ip_address} já existe na {tabela.__name__}. Removendo da Tarpit.")
        obj_tarpit.delete()

        obj_model = tabela.objects.get(ip_address=obj_tarpit.ip_address)

        return {
            'status': status,
            'ip_address': obj_model.ip_address,
            'country_code': obj_model.country_code,
            'city': obj_model.city,
            'abuseipdb_confidence_score': obj_model.abuseipdb_confidence_score,
            'abuseipdb_total_reports': obj_model.abuseipdb_total_reports,
            'abuseipdb_num_distinct_users': obj_model.abuseipdb_num_distinct_users,
            'virustotal_reputation': obj_model.virustotal_reputation,
            'virustotal_harmless': obj_model.virustotal_harmless,
            'virustotal_malicious': obj_model.virustotal_malicious,
            'virustotal_suspicious': obj_model.virustotal_suspicious,
            'virustotal_undetected': obj_model.virustotal_undetected,
            'ipvoid_detection_count': obj_model.ipvoid_detection_count,
            'risk_recommended_pulsedive': obj_model.risk_recommended_pulsedive,
            'last_reported_at': obj_model.last_reported_at,
            'src_longitude': obj_model.src_longitude,
            'src_latitude': obj_model.src_latitude,
        }
    
    return None


def write_to_csv(data, csv_file):
    with open(csv_file, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(data.keys())
        writer.writerow(data.values())


def get_class_distribution(csv_path):
    logger = logging.getLogger(__name__)

    df = pd.read_csv(csv_path)

    # Filtra a linha onde a coluna "Model" é o modelo que melhor se enquadra (tempo e acurácia)
    row = df[df["Model"] == "Decision Tree"]

    if row.empty:
        logger.error("Modelo 'Decision Tree' não encontrado.")
        return None

    # Pega a string do dicionário de distribuição de classes
    class_dist_str = row.iloc[0]["Class Distribution"]

    try:
        class_dist_dict = ast.literal_eval(class_dist_str)
        logger.info(f"Distribuição de classes do Decision Tree: {class_dist_dict}")
        # Retorna a classe mais comum
        return max(class_dist_dict, key=class_dist_dict.get)
    except Exception as e:
        logger.error(f"Erro ao converter a distribuição: {e}")
        return None


def filtrar_tarpit(ip_address):
    logger = setup_logging()

    try:
        # Começa temporizador
        start_time = time.time()
        
        # Pega o objeto da tarpit pelo IP
        obj_tarpit = Tarpit.objects.get(ip_address=ip_address)
        
        # Verifica se o IP já está na Blacklist, Suspect ou Whitelist
        for tabela, status in [(Blacklist, 'existente_blacklist'), (Suspect, 'existente_suspect'), (Whitelist, 'existente_whitelist')]:
            verificacao = verificar_ip_no_banco(obj_tarpit, tabela, status)
            execution_time = (time.time() - start_time) * 1000
            logger.info(f"Tempo para checar IP {obj_tarpit.ip_address} na {tabela.__name__}: {execution_time:.3f} milisegundos")
            if verificacao:
                return verificacao

        # Contagem do tempo de todas as requisições
        start_request = time.time()

        # Executando buscas paralelas para atualizar obj_tarpit
        obj_tarpit = realizar_buscas_paralelas(obj_tarpit)

        if obj_tarpit:
            logger.info(f"Iniciando filtragem do IP {obj_tarpit.ip_address}")

            if obj_tarpit:
                logger.info(f"--- Dados coletados para o IP {obj_tarpit.ip_address} ---")
                logger.info(f"abuseipdb_confidence_score: {obj_tarpit.abuseipdb_confidence_score}")
                logger.info(f"abuseipdb_total_reports: {obj_tarpit.abuseipdb_total_reports}")
                logger.info(f"abuseipdb_num_distinct_users: {obj_tarpit.abuseipdb_num_distinct_users}")
                logger.info(f"ipvoid_detection_count: {obj_tarpit.ipvoid_detection_count}")
                logger.info(f"risk_recommended_pulsedive: {obj_tarpit.risk_recommended_pulsedive}")
                logger.info(f"virustotal_reputation: {obj_tarpit.virustotal_reputation}")
                logger.info(f"virustotal_harmless: {obj_tarpit.virustotal_harmless}")
                logger.info(f"virustotal_malicious: {obj_tarpit.virustotal_malicious}")
                logger.info(f"virustotal_suspicious: {obj_tarpit.virustotal_suspicious}")
                logger.info(f"virustotal_undetected: {obj_tarpit.virustotal_undetected}")
                logger.info("-------------------------------------------------------")

                data = {
                    'ip_address': obj_tarpit.ip_address,
                    'abuseipdb_confidence_score': obj_tarpit.abuseipdb_confidence_score,
                    'abuseipdb_total_reports': obj_tarpit.abuseipdb_total_reports,
                    'abuseipdb_num_distinct_users': obj_tarpit.abuseipdb_num_distinct_users,
                    "ipvoid_detection_count": obj_tarpit.ipvoid_detection_count,
                    "risk_recommended_pulsedive": obj_tarpit.risk_recommended_pulsedive,
                    "virustotal_malicious": obj_tarpit.virustotal_malicious,
                    "virustotal_reputation": obj_tarpit.virustotal_reputation,
                    "virustotal_suspicious": obj_tarpit.virustotal_suspicious,
                    "virustotal_undetected": obj_tarpit.virustotal_undetected,
                    "virustotal_harmless": obj_tarpit.virustotal_harmless,
                }


            # Criando o CSV pra fazer a classificação do IP
            write_to_csv(data, CSV_FILE)

            # Classificação do modelo
            classificar_ip()

            # Obtendo a resposta do modelo
            classification = get_class_distribution(CSV_RESULTS_FILE).lower()
            logger.info(f"Classificação do modelo para IP {obj_tarpit.ip_address}: {classification}")

            # Preenche os dados completos antes da salvar
            data.update({
                'country_code': obj_tarpit.country_code,
                'city': obj_tarpit.city,
                'last_reported_at': obj_tarpit.last_reported_at,
                'src_longitude': obj_tarpit.src_longitude,
                'src_latitude': obj_tarpit.src_latitude
            })

            obj_tarpit.delete()

            # Salvando na tabela correspondente
            model = {
                "blacklist": Blacklist,
                "suspicious": Suspect,
                "whitelist": Whitelist
            }.get(classification)

            if model:
                model.objects.create(**data)
                data['status'] = classification
                return data
        
        else:
            logger.warning(f"Não foi possível checar a reputação do IP com as APIs externas.")
            logger.info(f"Movendo o IP {ip_address} para a Blacklist.")

            Blacklist.objects.create(ip_address=ip_address)

            # Deleta o objeto da tarpit
            Tarpit.objects.filter(ip_address=ip_address).delete()

            # Calcula o tempo para inserção na blacklist
            execution_time = (time.time() - start_request) * 1000
            logger.info(f"Tempo para inserir IP {ip_address} na Blacklist: {execution_time:.3f} milisegundos.")

            return {"status": "blacklist"}
        
    except Tarpit.DoesNotExist:
        logger.warning("Nenhum registro encontrado na tabela Tarpit")
        return {"status": "none"}


    
