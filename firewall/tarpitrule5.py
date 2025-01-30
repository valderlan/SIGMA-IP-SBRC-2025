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

def run_iptables_command(command, capture_output=False):
    try:
        result = subprocess.run(command, check=True, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE if capture_output else None)
        return result.stdout.decode() if capture_output else None
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando:", command, "Erro:", e.stderr.decode())
        return None

def remove_rules_for_custom_chains():
    for chain in ['INPUT', 'FORWARD']:
        # Listar as regras com números de linha
        rules = run_iptables_command(f'sudo iptables -L {chain} --line-numbers -n', capture_output=True)

        if rules:
            lines_to_remove = []
            for line in rules.split('\n'):
                if 'TARPIT' in line or 'BLACKLIST' in line:
                    # Obter o número da linha da regra que direciona para a chain personalizada
                    line_number = line.split()[0]
                    lines_to_remove.append(line_number)

            # Remover as regras de trás para frente para evitar confusão com a numeração
            for line_number in reversed(lines_to_remove):
                run_iptables_command(f'sudo iptables -D {chain} {line_number}')
            print(f"Regras removidas da chain {chain}.")

remove_rules_for_custom_chains()


def run_iptables_command(command):
    try:
        subprocess.run(command, check=True, shell=True, stderr=subprocess.PIPE)
        print("Comando executado com sucesso:", command)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando:", command, "Erro:", e.stderr.decode())

def create_or_flush_chain(chain_name):
    subprocess.run(f'sudo iptables -N {chain_name} || sudo iptables -F {chain_name}', shell=True)
    print(f"Chain {chain_name} criada ou limpa.")

def setup_tarpit_chain():
    run_iptables_command(f'sudo iptables -A TARPIT -m limit --limit 60/min -j ACCEPT')
    run_iptables_command(f'sudo iptables -A TARPIT -j DROP')
    print("Regras de limitação de taxa configuradas na chain TARPIT.")

def setup_blacklist_chain():
    # Aplicar regra genérica de rejeição com tcp-reset na chain BLACKLIST
    run_iptables_command(f'sudo iptables -A BLACKLIST -p tcp -j REJECT --reject-with tcp-reset')
    run_iptables_command(f'sudo iptables -A BLACKLIST -j DROP')
    print("Chain BLACKLIST configurada com regra de REJECT.")

def apply_rules_to_ips():
    try:
        conn = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host, port=db_port)
        cur = conn.cursor()

        # Processar endereços TP
        cur.execute("SELECT ip_address FROM tarpit")
        ips = cur.fetchall()
        for ip in ips:
            # Aplicar regras para FORWARD e INPUT direcionando para TARPIT
            for chain in ["FORWARD", "INPUT"]:
                run_iptables_command(f'sudo iptables -I {chain} -s {ip[0]} -j TARPIT')
            print(f"Regras de TARPIT aplicadas para o IP {ip[0]} em FORWARD e INPUT.")

        # Processar endereços BL
        cur.execute("SELECT ip_address FROM blacklist")
        ips = cur.fetchall()
        for ip in ips:
            # Aplicar regras para FORWARD e INPUT direcionando para BLACKLIST
            for chain in ["FORWARD", "INPUT"]:
                run_iptables_command(f'sudo iptables -I {chain} -s {ip[0]} -j BLACKLIST')
            print(f"Regras de BLACKLIST aplicadas para o IP {ip[0]} em FORWARD e INPUT.")

        cur.close()
        conn.close()
    except psycopg2.DatabaseError as e:
        print("Erro de banco de dados:", e)
    except Exception as e:
        print("Ocorreu um erro:", e)

def remove_chains(chain_names=["TARPIT", "BLACKLIST"]):
    for chain_name in chain_names:
        run_iptables_command(f'sudo iptables -F {chain_name}')
        run_iptables_command(f'sudo iptables -X {chain_name}')
        print(f"Chain {chain_name} removida.")

def main():
    for chain_name in ["TARPIT", "BLACKLIST"]:
        create_or_flush_chain(chain_name)
    setup_tarpit_chain()
    setup_blacklist_chain()
    apply_rules_to_ips()
    # Para remover as chains e suas regras, descomente a linha abaixo
    # remove_chains()

if __name__ == "__main__":
    main()