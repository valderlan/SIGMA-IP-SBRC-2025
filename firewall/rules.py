import subprocess
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.getcwd(), "api", ".env"))

# Configurações do PostgreSQL
db_host = os.environ.get('PG_HOST')
db_name = os.environ.get('PG_DB')
db_user = os.environ.get('PG_USER')
db_password = os.environ.get('PG_PASSWORD')
db_port = os.environ.get('PG_PORT')

print(f"host: {db_host}, name: {db_name}, user: {db_user}, password: {db_password}, port: {db_port}")


print(f"teste: {os.getcwd()}")

def run_iptables_command(command):
    try:
        subprocess.run(command, check=True, shell=True, capture_output=True)
        print("Comando executado com sucesso:", command)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando:", command, "Erro:", e.stderr.decode())

def create_or_flush_chain(chain_name):
    # Tenta criar a chain; se já existe, limpa suas regras
    subprocess.run(f'sudo iptables -N {chain_name} 2>/dev/null || sudo iptables -F {chain_name}', shell=True)
    print(f"Chain {chain_name} criada ou limpa.")

def setup_tarpit_and_blacklist_chains():
    # Configurações específicas para as chains TARPIT e BLACKLIST
    run_iptables_command(f'sudo iptables -A TARPIT -m limit --limit 60/min -j ACCEPT')
    run_iptables_command(f'sudo iptables -A TARPIT -j DROP')
    print("Regras de limitação de taxa configuradas na chain TARPIT.")

    run_iptables_command(f'sudo iptables -A BLACKLIST -p tcp -j REJECT --reject-with tcp-reset')
    run_iptables_command(f'sudo iptables -A BLACKLIST -j DROP')
    print("Chain BLACKLIST configurada com regra de REJECT.")

def setup_whitelist_chain():
    # Aceitar todo o tráfego que chega �|  chain WHITELIST
    run_iptables_command(f'sudo iptables -A WHITELIST -j ACCEPT')
    print("Chain WHITELIST configurada para aceitar todo o tráfego.")

def apply_whitelist_rules():
    try:
        conn = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host, port=db_port)
        cur = conn.cursor()

        # Processar endereços WP
        cur.execute("SELECT ip_address FROM whitelist")
        ips = cur.fetchall()
        for ip in ips:
            # Aplicar regras para FORWARD e INPUT direcionando para WHITELIST
            for chain in ["FORWARD", "INPUT"]:
                run_iptables_command(f'sudo iptables -I {chain} -s {ip[0]} -j WHITELIST')
            print(f"Regras de WHITELIST aplicadas para o IP {ip[0]} em FORWARD e INPUT.")

        cur.close()
        conn.close()
    except psycopg2.DatabaseError as e:
        print("Erro de banco de dados:", e)
    except Exception as e:
        print("Ocorreu um erro:", e)

def main():
    # Criar ou limpar as chains necessárias
    for chain_name in ["TARPIT", "BLACKLIST", "WHITELIST"]:
        create_or_flush_chain(chain_name)

    setup_tarpit_and_blacklist_chains()  # Configuração inicial para TARPIT e BLACKLIST
    setup_whitelist_chain()  # Configura a nova chain WHITELIST

    apply_whitelist_rules()  # Aplica as novas regras para WHITELIST

    # Nota: As funções para aplicar regras a TARPIT e BLACKLIST foram mencionadas no seu script original.
    # Você pode chamar essas funções aqui também, se necessário.

    # Para remover as chains e suas regras, descomente a linha abaixo
    # remove_chains(["TARPIT", "BLACKLIST", "WHITELIST"])

if __name__ == "__main__":
    main()