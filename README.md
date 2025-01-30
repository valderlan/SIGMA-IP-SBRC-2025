# Dissertação FIBRA-UECE 📕

Repositório dos códigos para dissertação do tema de Firewall automatizado.

O objetivo dessa ferramenta é aumentar o nível de segurança de um firewall de borda evitando a negação inicial do serviço, enquanto é efetuada a análise do tráfego registrado.

## Dicas e Considerações de "Preflight"

Como a execução foi validada em um ambiente em nuvem pública, usando uma distribuição Linux específica, algumas considerações são necessárias:

- A distribuição usada para replicação desse guia foi a **Debian/Linux**. Caso utilize outra distribuição, alguns passos podem precisar de ajustes.

## Preparação do Ambiente

### Atualizando o Sistema
```sh
apt update -y
```

### Instalando o Git
```sh
apt install git -y
```

### Clonando o Repositório
```sh
git clone https://github.com/LarcesUece/FIBRA-Larces.git
```

### Instalando Pacotes Necessários
```sh
apt install vim wget bash-completion \
    tcpdump net-tools curl telnet \
    nmap zip unzip cron python3-pip python3-venv -y
```

### Criando Ambiente Virtual
```sh
python3 -m venv /opt/FIBRA-Larces/python/
```

### Instalando Docker
```sh
curl -fsSL https://get.docker.com | bash
```

## Instalando GeoIP Update
```sh
wget https://github.com/maxmind/geoipupdate/releases/download/v6.1.0/geoipupdate_6.1.0_linux_amd64.deb

dpkg -i geoipupdate_6.1.0_linux_amd64.deb
```

### Configurando GeoIP Update
Editar o arquivo de configuração:
```sh
nano /usr/share/doc/geoipupdate/GeoIP.conf
```
Exemplo de configuração:
```ini
AccountID 1042771
LicenseKey 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
EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
```
Após a configuração, execute:
```sh
geoipupdate -f /usr/share/doc/geoipupdate/GeoIP.conf
```

## Instalando Bibliotecas no Ambiente Virtual
```sh
source /opt/FIBRA-Larces/python/bin/activate
pip install geoip2 scapy requests datetime psycopg2-binary
```

## Criando e Executando Containers
### Postgres API
```sh
docker run --name sigmaip -e POSTGRES_PASSWORD=admin -e POSTGRES_USER=Q1w2e3r4 -e POSTGRES_DB=firewall -p 5433:5432 -d postgres
```

### Postgres Local
```sh
docker exec sigmaip psql -U admin -d postgres -c "CREATE DATABASE fibra_local;"
```

### Recriando o Banco
```sh
docker exec sigmaip psql -U admin -d postgres -c "DROP DATABASE firewall;" -c "CREATE DATABASE firewall;"
docker exec sigmaip psql -U admin -d postgres -c "DROP DATABASE fibra_local;" -c "CREATE DATABASE fibra_local;"
```

## Criando a Estrutura da Base de Dados
(Adicionar comandos específicos)

## Rodando a API
(Adicionar comandos específicos)

## Executando o Sniffer de Rede
```sh
/opt/FIBRA-Larces/python/bin/python3 /opt/FIBRA-Larces/collect/collect-pgsql-ipv4-tcp-syn.py > /dev/null &
```

## Ativando Regras de Firewall
```sh
python3 /FIBRA-Larces/firewall/rules.py
python3 /FIBRA-Larces/firewall/tarpitrule5.py
```

---

Este documento pode ser atualizado conforme necessário para refletir mudanças no sistema.

