from .externals import SearchAbuse
from .services import UpdateBlService, ReputacaoService
from .models import Blacklist, Whitelist, Tarpit
from django.utils.timezone import now
from datetime import timedelta
from dotenv import load_dotenv
import psycopg2
import os

load_dotenv()

# Configurações do banco local
db_host = os.environ.get('PG_HOST')
db_name = os.environ.get('PG_DB_LOCAL')
db_user = os.environ.get('PG_USER')
db_password = os.environ.get('PG_PASSWORD')
db_port = os.environ.get('PG_PORT')

# Função pra requisitar novos dados pra blacklist
def update_blacklist():
    print("Buscando dados para atualizar a Blacklist...")
    dados = SearchAbuse.buscar_dados()
    if dados:
        UpdateBlService.inserir_dados_no_banco(dados)

# Função pra verificar IPs antigos da whitelist 
def verificar_ips_antigos_wl():
    tres_dias_atras = now() - timedelta(days=3) # pegando o tempo de 3 dias

    # pega todos os objetos da whitelist que tiveram a última filtragem mais de 3 dias atrás
    queryset = Whitelist.objects.filter(timestamp_added__lt=tres_dias_atras)

    # pegando novamente os dados dos ips que estão na whitelist para inserí-los na tarpit
    for obj_whitelist in queryset:
        data = {
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

        try:
            conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_password, port=db_port)
            cur = conn.cursor()
            cur.execute("SET TIMEZONE TO 'America/Fortaleza';")


            query = """
                DELETE FROM wl_address_local WHERE ip_address = %s
            """
            values = (
                data['ip_address'],
            )

            cur.execute(query, values)
            conn.commit()
            print(f"IP {data['ip_address']}")

            # Cria o objeto na tarpit para ser filtrado novamente
            obj_tarpit = Tarpit.objects.create(**data)
            print(f"Objeto inserido na tarpit: {data['ip_address']}")

            # deleta o objeto da whitelist da API
            obj_whitelist.delete()

            # Faz o processo de filtragem do IP
            ReputacaoService.filtrar_tarpit(obj_tarpit.ip_address)

        except Exception as e:
            print(f"Erro ao inserir {data['ip_address']} na tarpit: {e}")

# Função pra verificar IPs antigos da blacklist
def verificar_blacklist():
    # Pegando o tempo de 3 dias atrás
    tres_dias_atras = now() - timedelta(days=3)

    # Filtrando os IPs da blacklist com mais de 3 dias no banco
    queryset = Blacklist.objects.filter(timestamp_added__lt=tres_dias_atras)

    for obj_blacklist in queryset:
        data = {
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

        # Cria o objeto na tarpit para ser reanalisado
        obj_tarpit = Tarpit.objects.create(**data)
        
        # Deleta o objeto da blacklist
        obj_blacklist.delete()

        # Faz o processo de filtragem do IP
        ReputacaoService.filtrar_tarpit(obj_tarpit.ip_address)