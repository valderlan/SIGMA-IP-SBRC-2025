import subprocess

def run_iptables_command(command):
    try:
        subprocess.run(command, check=True, shell=True, capture_output=True)
        print("Comando executado com sucesso:", command)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando:", command, "Erro:", e.stderr.decode())

def create_or_flush_chain():
    # Cria ou limpa a chain WHITELIST no iptables.

    subprocess.run(f'sudo iptables -N WHITELIST|| sudo iptables -F WHITELIST', shell=True)
    print(f"Chain WHITELIST criada ou limpa.")

def setup_whitelist_chain():
    # Aceitar todo o tráfego que chega �|  chain WHITELIST
    run_iptables_command(f'sudo iptables -A WHITELIST -j ACCEPT')
    print("Chain WHITELIST configurada para aceitar todo o tráfego.")

def apply_whitelist_rules(ip):
    for chain in ["FORWARD", "INPUT"]:
        run_iptables_command(f'sudo iptables -I {chain} -s {ip} -j WHITELIST')
    print(f"Regras de WHITELIST aplicadas para o IP {ip} em FORWARD e INPUT.")

def remove_ip_from_iptables_whitelist(ip):
    run_iptables_command(f'sudo iptables -D INPUT -s {ip} -j WHITELIST')
    run_iptables_command(f'sudo iptables -D FORWARD -s {ip} -j WHITELIST')
    print(f'O IP {ip} foi deletado da chain WHITELIST do iptables')

def configurar_chain_whitelist():
    # Criar ou limpar as chains necessárias
    create_or_flush_chain()
    setup_whitelist_chain()