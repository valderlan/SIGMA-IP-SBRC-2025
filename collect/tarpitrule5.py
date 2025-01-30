import subprocess

def run_iptables_command(command):
    """
    Executa um comando iptables via subprocess.
    """
    try:
        subprocess.run(command, check=True, shell=True, stderr=subprocess.PIPE)
        print("Comando executado com sucesso:", command)
    except subprocess.CalledProcessError as e:
        print("Erro ao executar o comando:", command, "Erro:", e.stderr.decode())

def create_or_flush_tarpit_chain():
    """
    Cria ou limpa a chain TARPIT no iptables.
    """
    subprocess.run('sudo iptables -N TARPIT || sudo iptables -F TARPIT', shell=True)
    print("Chain TARPIT criada ou limpa.")

def setup_tarpit_chain():
    """
    Configura as regras de limitação e drop na chain TARPIT.
    """
    run_iptables_command('sudo iptables -A TARPIT -m limit --limit 60/min -j ACCEPT')
    run_iptables_command('sudo iptables -A TARPIT -j DROP')
    print("Regras configuradas na chain TARPIT.")

def apply_tarpit_rules(ip):
    """
    Aplica regras para redirecionar IPs para a chain TARPIT.

    :param ips: Lista de endereços IP a serem adicionados à chain TARPIT.
    """
    for chain in ["FORWARD", "INPUT"]:
        run_iptables_command(f'sudo iptables -I {chain} -s {ip} -j TARPIT')
    print(f"Regras de TARPIT aplicadas para o IP {ip} em FORWARD e INPUT.")

def remove_tarpit_chain():
    """
    Remove a chain TARPIT e suas regras.
    """
    run_iptables_command('sudo iptables -F TARPIT')
    run_iptables_command('sudo iptables -X TARPIT')
    print("Chain TARPIT removida.")

def configurar_chain_tarpit():
    """
    Função principal para configurar e aplicar regras na chain TARPIT.

    :param ips: Lista de endereços IP a serem redirecionados para TARPIT.
    """
    create_or_flush_tarpit_chain()
    setup_tarpit_chain()

def deletar_ip_tarpit(ip):
    run_iptables_command(f'sudo iptables -D INPUT -s {ip} -j TARPIT')
    run_iptables_command(f'sudo iptables -D FORWARD -s {ip} -j TARPIT')
    print(f'O IP {ip} foi deletado da tarpit do iptables')
