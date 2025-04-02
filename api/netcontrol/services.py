import os
from datetime import datetime
from dotenv import load_dotenv
from django.db import IntegrityError
from .models import Blacklist, Whitelist, Tarpit, Suspect
from .externals import SearchAbuse, SearchVirusTotal, SearchIpVoid, SearchPulsedive
from concurrent.futures import ThreadPoolExecutor
import json
import time
import csv
import ast
from netcontrol.ia_model.query import main

load_dotenv()

API_KEY = json.loads(os.getenv("API_KEY", "[]"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, 'ia_model', 'datasets', 'Total_test1.csv')
CSV_RESULTS_FILE = os.path.join(BASE_DIR, 'ia_model', 'outputs', 'model_timing_results.csv')

class UpdateBlService:
    def ip_ja_existe(ip_address):
        requisicao = Blacklist.objects.filter(ip_address=ip_address)

        if requisicao.exists():
            print(f"O IP {ip_address} já existe no banco")
            return True
        else:
            return False
        
    def inserir_dados_no_banco(dados):
        # Lista pra inserir vários objetos na blacklist em uma única conexão com o banco
        objetos_para_inserir = []

        for registro in dados['data']:
            data_formatada = datetime.strptime(registro['lastReportedAt'], "%Y-%m-%dT%H:%M:%S+00:00").isoformat()

            ip_address = registro['ipAddress']

            if not UpdateBlService.ip_ja_existe(ip_address):
                data = Blacklist(
                    ip_address=registro['ipAddress'],
                    country_code=registro['countryCode'],
                    abuse_confidence_score=registro['abuseConfidenceScore'],
                    last_reported_at=data_formatada
                )
                objetos_para_inserir.append(data)
                print(f"O IP {ip_address} foi adicionado à lista para inserção.")

        if objetos_para_inserir:
            try:
                # Utilizando bulk_create para inserir todos de uma vez
                Blacklist.objects.bulk_create(objetos_para_inserir)
                print(f"{len(objetos_para_inserir)} IPs foram inseridos no banco com sucesso.")
            except IntegrityError as e:
                print(f"Erro de integridade ao tentar inserir os dados: {e}")


class ReputacaoService:
    def filtrar_tarpit(ip_address):
        try:
            # Começa temporizador
            start_time = time.time()
            print(CSV_FILE)

            # Pega o objeto da tarpit pelo IP
            obj_tarpit = Tarpit.objects.get(ip_address=ip_address)

            # Verifica se há um objeto na tabela Tarpit
            if obj_tarpit is None:
                print('Nada na TARPIT')
                return {"status": 'none'}

            # Checagem se o IP já está na blacklist (momentâneo antes da aplicação das regras do firewall)
            if Blacklist.objects.filter(ip_address=obj_tarpit.ip_address).exists():
                print(f"O IP {obj_tarpit.ip_address} já existe na blacklist")
                obj_tarpit.delete()

                obj_blacklist = Blacklist.objects.get(ip_address=obj_tarpit.ip_address)
                # Calcula o tempo de execução.
                data = {
                    'status': 'existente_blacklist',
                    'ip_address': obj_blacklist.ip_address,
                    'country_code': obj_blacklist.country_code,
                    'city': obj_blacklist.city,
                    'abuseipdb_confidence_score': obj_blacklist.abuseipdb_confidence_score,
                    'abuseipdb_total_reports': obj_blacklist.abuseipdb_total_reports,
                    'abuseipdb_num_distinct_users': obj_blacklist.abuseipdb_num_distinct_users,
                    "virustotal_reputation": obj_blacklist.virustotal_reputation,
                    "virustotal_harmless": obj_blacklist.virustotal_harmless,
                    "virustotal_malicious,": obj_blacklist.virustotal_malicious,
                    "virustotal_suspicious": obj_blacklist.virustotal_suspicious,
                    "virustotal_undetected": obj_blacklist.virustotal_undetected,
                    "ipvoid_detection_count": obj_blacklist.ipvoid_detection_count,
                    "risk_recommended_pulsedive": obj_blacklist.risk_recommended_pulsedive,
                    'last_reported_at': obj_blacklist.last_reported_at,
                    'src_longitude': obj_blacklist.src_longitude,
                    'src_latitude': obj_blacklist.src_latitude,
                }
                execution_time = (time.time() - start_time) * 1000
                print(f"Tempo para consultar se o IP coletado está na Blacklist do banco da API: {execution_time:.3f} milisegundos")
                return data
            
            # Checagem se o IP já está na whitelist
            if Whitelist.objects.filter(ip_address=obj_tarpit.ip_address).exists():
                print(f"O IP {obj_tarpit.ip_address} já existe na whitelist")
                obj_tarpit.delete()

                obj_whitelist = Whitelist.objects.get(ip_address=obj_tarpit.ip_address)
                # Calcula o tempo de execução.
                data = {
                    'status': 'existente_whitelist',
                    'ip_address': obj_whitelist.ip_address,
                    'country_code': obj_whitelist.country_code,
                    'city': obj_whitelist.city,
                    'abuseipdb_confidence_score': obj_whitelist.abuseipdb_confidence_score,
                    'abuseipdb_total_reports': obj_whitelist.abuseipdb_total_reports,
                    'abuseipdb_num_distinct_users': obj_whitelist.abuseipdb_num_distinct_users,
                    "virustotal_reputation": obj_whitelist.virustotal_reputation,
                    "virustotal_harmless": obj_whitelist.virustotal_harmless,
                    "virustotal_malicious,": obj_whitelist.virustotal_malicious,
                    "virustotal_suspicious": obj_whitelist.virustotal_suspicious,
                    "virustotal_undetected": obj_whitelist.virustotal_undetected,
                    "ipvoid_detection_count": obj_whitelist.ipvoid_detection_count,
                    "risk_recommended_pulsedive": obj_whitelist.risk_recommended_pulsedive,
                    'last_reported_at': obj_whitelist.last_reported_at,
                    'src_longitude': obj_whitelist.src_longitude,
                    'src_latitude': obj_whitelist.src_latitude,
                }
                execution_time = (time.time() - start_time) * 1000
                print(f"Tempo para consultar se o IP coletado está na Whitelist do banco da API: {execution_time:.3f} milisegundos")
                return data
            

            # Contagem do tempo de todas as requisições
            start_request = time.time()

            def realizar_buscas_paralelas(obj_tarpit):
                with ThreadPoolExecutor() as executor:
                    # Faz as requisições para as APIs paralelamente
                    futures = {
                        "abuse": executor.submit(SearchAbuse.buscar_score, obj_tarpit),
                        "virustotal": executor.submit(SearchVirusTotal.buscar_dados, obj_tarpit),
                        "ipvoid": executor.submit(SearchIpVoid.buscar_dados, obj_tarpit),
                        "pulsedive": executor.submit(SearchPulsedive.buscar_dados, obj_tarpit),
                    }

                    responses = {}
                    for key, future in futures.items():
                        try:
                            responses[key] = future.result()
                        except Exception as e:
                            print(f"Erro ao buscar na API {key}: {e}")
                            responses[key] = None

                # Processar as respostas e salvar no objeto
                if responses.get("abuse"):
                    dados_abuse = responses["abuse"].json().get('data', {})
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
                    print("Nenhuma chave funcional para consultar o IPVoid.")

                if responses.get("pulsedive"):
                    dados_pulsedive = responses["pulsedive"]
                    obj_tarpit.risk_recommended_pulsedive = dados_pulsedive.get('risk_recommended', 'unknown')
                else:
                    obj_tarpit.risk_recommended_pulsedive = 'unknown'

                return obj_tarpit


            # Checando se as buscas paralelas foram executadas com sucesso
            if realizar_buscas_paralelas(obj_tarpit):
                print(f"Iniciando filtragem do IP {obj_tarpit.ip_address}")

                data = {
                    'ip_address': obj_tarpit.ip_address,
                    # 'country_code': obj_tarpit.country_code,
                    # 'city': obj_tarpit.city,
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
                    # 'last_reported_at': obj_tarpit.last_reported_at,
                    # 'src_longitude': obj_tarpit.src_longitude,
                    # 'src_latitude': obj_tarpit.src_latitude,
                }

                # Criando o CSV para fazer checagem do IP
                ReputacaoService.write_to_csv(data, CSV_FILE)

                # Classificação do modelo
                main()

                # Obtendo a resposta do modelo
                classification = ReputacaoService.get_class_distribution(CSV_RESULTS_FILE, 3).lower()

                print(classification)

                # Completa os campos para enviar para a collect
                data['country_code'] = obj_tarpit.country_code
                data['city'] = obj_tarpit.city
                data['last_reported_at'] = obj_tarpit.last_reported_at
                data['src_longitude'] = obj_tarpit.src_longitude
                data['src_latitude'] = obj_tarpit.src_latitude

                obj_tarpit.delete()
                
                if classification == 'blacklist':
                    Blacklist.objects.create(**data)
                    data['status'] = 'blacklist'
                    return data
                elif classification == 'suspicious':
                    Suspect.objects.create(**data)
                    data['status'] = 'suspicious'
                    return data
                elif classification == 'whitelist':
                    Whitelist.objects.create(**data)
                    data['status'] = 'whitelist'
                    return data

            
            else:
                print(f"Não foi possível checar a reputação do IP {obj_tarpit.ip_address} com as APIs externas")
                print(f"Movendo o IP {obj_tarpit.ip_address} para a blacklist")

                Blacklist.objects.create(ip_address=obj_tarpit.ip_address)

                # Deleta o objeto da tarpit
                obj_tarpit.delete()

                # Calcula o tempo para inserir na blacklist da API.
                execution_time = (time.time() - start_request) * 1000
                print(f"Tempo para inserção na blacklist da API caso não encontre informações sobre o IP: {execution_time:.3f} milisegundos")

                return {"status": "blacklist"}

            execution_time = (time.time() - start_time) * 1000
            print(f'Tempo total de execução da tratativa do IP: {execution_time:.3f} milisegundos')
            
        except Tarpit.DoesNotExist:
            print("Nenhum registro encontrado na tabela Tarpit")
            return {"status": "none"}

    def write_to_csv(data, csv_file):
        with open(csv_file, 'w') as file:
            writer = csv.writer(file)
            writer.writerow(data.keys())
            writer.writerow(data.values())

    def get_class_distribution(csv_results, line_number):
        with open(csv_results, 'r', newline='') as file:
            reader = csv.DictReader(file)
            
            for i, row in enumerate(reader, start=1):
                if i == line_number:
                    class_dist_str = row.get("Class Distribution")
                    
                    if class_dist_str:
                        try:
                            class_dist_dict = ast.literal_eval(class_dist_str)  # Converte a string para dicionário
                            return next(iter(class_dist_dict))  # Retorna a primeira chave do dicionário
                        except (SyntaxError, ValueError):
                            return None  # Retorna None se não conseguir converter

        return None  # Retorna None se a linha não existir
    
