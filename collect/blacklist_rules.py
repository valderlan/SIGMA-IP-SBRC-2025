import subprocess

def run_iptables_command(command):
    try:
        subprocess.run(command, check=True, shell=True, stderr=subprocess.PIPE)
        print("Comando executado com sucesso:", command)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando:", command, "Erro:", e.stderr.decode())

def create_or_flush_chain():
    # Cria ou limpa a chain BLACKLIST no iptables.
    subprocess.run(f'sudo iptables -N BLACKLIST || sudo iptables -F BLACKLIST', shell=True)
    print(f"Chain BLACKLIST criada ou limpa.")

def setup_blacklist_chain():
    # Configura regras específicas para a chain BLACKLIST.
    run_iptables_command(f'sudo iptables -A BLACKLIST -p tcp -j REJECT --reject-with tcp-reset')
    run_iptables_command(f'sudo iptables -A BLACKLIST -j DROP')
    print("Chain BLACKLIST configurada com regra de REJECT.")
def apply_blacklist_rules(ip):
    # Aplica as regras de BLACKLIST para os IPs configurados no banco de dados
    print('chegou aqui')
    for chain in ["FORWARD", "INPUT"]:
        run_iptables_command(f'sudo iptables -I {chain} -s {ip} -j BLACKLIST')
    print(f"Regras de BLACKLIST aplicadas para o IP {ip} em FORWARD e INPUT.")

def remove_blacklist_chain():
    # Remove a chain BLACKLIST e suas regras
    run_iptables_command('sudo iptables -F BLACKLIST')
    run_iptables_command('sudo iptables -X BLACKLIST')
    print("Chain blacklist removida.")

def configurar_chain_blacklist():
    # Configura e aplica as regras para a BLACKLIST
    create_or_flush_chain()
    setup_blacklist_chain()
