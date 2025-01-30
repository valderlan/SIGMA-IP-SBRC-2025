import os
from datetime import datetime
from dotenv import load_dotenv
from django.db import IntegrityError
from .models import Blacklist, Whitelist, Tarpit
from .externals import SearchAbuse, SearchVirusTotal, SearchIpVoid, SearchPulsedive
from concurrent.futures import ThreadPoolExecutor
import json
import time

load_dotenv()

API_KEY = json.loads(os.getenv("API_KEY", "[]"))

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
                    'abuse_confidence_score': obj_blacklist.abuse_confidence_score,
                    'total_reports': obj_blacklist.total_reports,
                    'num_distinct_users': obj_blacklist.num_distinct_users,
                    "virustotal_reputation": obj_blacklist.virustotal_reputation,
                    "harmless_virustotal": obj_blacklist.harmless_virustotal,
                    "malicious_virustotal": obj_blacklist.malicious_virustotal,
                    "suspicious_virustotal": obj_blacklist.suspicious_virustotal,
                    "undetected_virustotal": obj_blacklist.undetected_virustotal,
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
                    'abuse_confidence_score': obj_whitelist.abuse_confidence_score,
                    'total_reports': obj_whitelist.total_reports,
                    'num_distinct_users': obj_whitelist.num_distinct_users,
                    "virustotal_reputation": obj_whitelist.virustotal_reputation,
                    "harmless_virustotal": obj_whitelist.harmless_virustotal,
                    "malicious_virustotal": obj_whitelist.malicious_virustotal,
                    "suspicious_virustotal": obj_whitelist.suspicious_virustotal,
                    "undetected_virustotal": obj_whitelist.undetected_virustotal,
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
                    obj_tarpit.abuse_confidence_score = dados_abuse.get('abuseConfidenceScore')
                    obj_tarpit.last_reported_at = dados_abuse.get('lastReportedAt')
                    obj_tarpit.total_reports = dados_abuse.get('totalReports')
                    obj_tarpit.num_distinct_users = dados_abuse.get('numDistinctUsers')

                if responses.get("virustotal"):
                    dados_virus_total = responses["virustotal"].get('data', {}).get('attributes', {})
                    dados_virus_total_meta = dados_virus_total.get('last_analysis_stats', {})
                    obj_tarpit.virustotal_reputation = dados_virus_total.get('reputation')
                    obj_tarpit.harmless_virustotal = dados_virus_total_meta.get('harmless')
                    obj_tarpit.malicious_virustotal = dados_virus_total_meta.get('malicious')
                    obj_tarpit.suspicious_virustotal = dados_virus_total_meta.get('suspicious')
                    obj_tarpit.undetected_virustotal = dados_virus_total_meta.get('undetected')

                if responses.get("ipvoid"):
                    dados_ipvoid = responses["ipvoid"].get('data', {}).get('report', {}).get('blacklists', {})
                    obj_tarpit.ipvoid_detection_count = dados_ipvoid.get('detections', 0)
                else:
                    print("Nenhuma chave funcional para consultar o IPVoid.")

                if responses.get("pulsedive"):
                    dados_pulsedive = responses["pulsedive"]
                    obj_tarpit.risk_recommended_pulsedive = dados_pulsedive.get('risk_recommended', 'unknown')
                else:
                    obj_tarpit.risk_recommended_pulsedive = 'unknown'

                return obj_tarpit

            # # Separando as respostas
            # dados_abuse = response_abuse.json()['data']
            # dados_virus_total = response_virus['data']['attributes']
            # dados_virus_total_meta = response_virus['data']['attributes']['last_analysis_stats']
            # dados_ipvoid = response_ipvoid['data']['report']['blacklists']
            # dados_pulsedive = response_pulsedive

            # # Dados do abuse para colocar no banco
            # obj_tarpit.abuse_confidence_score = dados_abuse.get('abuseConfidenceScore')
            # obj_tarpit.last_reported_at = dados_abuse.get('lastReportedAt')
            # obj_tarpit.total_reports = dados_abuse.get('totalReports')
            # obj_tarpit.num_distinct_users = dados_abuse.get('numDistinctUsers')

            # # Dados do virustotal para colocar no banco
            # obj_tarpit.virustotal_reputation = dados_virus_total.get('reputation')
            # obj_tarpit.harmless_virustotal = dados_virus_total_meta.get('harmless')
            # obj_tarpit.malicious_virustotal = dados_virus_total_meta.get('malicious')
            # obj_tarpit.suspicious_virustotal = dados_virus_total_meta.get('suspicious')
            # obj_tarpit.undetected_virustotal = dados_virus_total_meta.get('undetected')

            # # Dados do IPVoid para colocar no banco
            # obj_tarpit.ipvoid_detection_count = dados_ipvoid.get('detections')

            # if response_ipvoid is not None:
            #     dados_ipvoid = response_ipvoid['data']['report']['blacklists']
            #     obj_tarpit.ipvoid_detection_count = dados_ipvoid.get('detections', 0)
            # else:
            #     print("Nenhuma chave funcional para consultar o IPVoid.")
                
            # # Dados do Pulsedive para colocar no banco
            # if response_pulsedive is not None:
            #     dados_pulsedive = response_pulsedive
            #     obj_tarpit.risk_recommended_pulsedive = dados_pulsedive.get('risk_recommended', 'unknown')
            # else:
            #     # Caso nenhuma resposta válida tenha sido retornada
            #     obj_tarpit.risk_recommended_pulsedive = 'unknown'

            # Checando se as buscas paralelas foram executadas com sucesso
            if realizar_buscas_paralelas(obj_tarpit):
                print(f"Iniciando filtragem do IP {obj_tarpit.ip_address}")

                data = {
                    'ip_address': obj_tarpit.ip_address,
                    'country_code': obj_tarpit.country_code,
                    'city': obj_tarpit.city,
                    'abuse_confidence_score': obj_tarpit.abuse_confidence_score,
                    'total_reports': obj_tarpit.total_reports,
                    'num_distinct_users': obj_tarpit.num_distinct_users,
                    "virustotal_reputation": obj_tarpit.virustotal_reputation,
                    "harmless_virustotal": obj_tarpit.harmless_virustotal,
                    "malicious_virustotal": obj_tarpit.malicious_virustotal,
                    "suspicious_virustotal": obj_tarpit.suspicious_virustotal,
                    "undetected_virustotal": obj_tarpit.undetected_virustotal,
                    "ipvoid_detection_count": obj_tarpit.ipvoid_detection_count,
                    "risk_recommended_pulsedive": obj_tarpit.risk_recommended_pulsedive,
                    'last_reported_at': obj_tarpit.last_reported_at,
                    'src_longitude': obj_tarpit.src_longitude,
                    'src_latitude': obj_tarpit.src_latitude,
                }

                # Move para a blacklist caso o score seja maior ou igual a 50
                if obj_tarpit.abuse_confidence_score >= 50:
                    print(f"O IP {obj_tarpit.ip_address} possui score {obj_tarpit.abuse_confidence_score} e será movido para a blacklist")
                    Blacklist.objects.create(**data)
                    obj_tarpit.delete()

                    # adição do status
                    data["status"] = "blacklist"

                    # Calcula o tempo para inserir na blacklist da API.
                    execution_time = (time.time() - start_request) * 1000
                    print(f"Tempo para inserção na blacklist da API: {execution_time:.3f} milisegundos")
                    return data
                
                # Move para a whitelist caso o score seja inferior a 50
                elif obj_tarpit.abuse_confidence_score < 50:
                    # Caso não esteja, será colocado na whitelist da API e na whitelist do banco local
                    print(f"O IP {obj_tarpit.ip_address} possui score {obj_tarpit.abuse_confidence_score} e será movido para a whitelist")
                    Whitelist.objects.create(**data)
                    obj_tarpit.delete()

                    # adição do status
                    data["status"] = "whitelist"

                    # Calcula o tempo para inserir na blacklist da API.
                    execution_time = (time.time() - start_request) * 1000
                    print(f"Tempo para inserção na whitelist da API: {execution_time:.3f} milisegundos")
                    return data

                # Inserir na blacklist caso o score seja nulo
                elif obj_tarpit.abuse_confidence_score is None:
                    print(f"O IP {obj_tarpit.ip_address} possui score null, e será movido para a blacklist")
                    Blacklist.objects.create(**data)
                    obj_tarpit.delete()

                    # adição do status
                    data["status"] = "blacklist"

                    # Calcula o tempo para inserir na blacklist da API.
                    execution_time = (time.time() - start_request) * 1000
                    print(f"Tempo para inserção na blacklist da API no caso score None: {execution_time:.3f} milisegundos")
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

    
