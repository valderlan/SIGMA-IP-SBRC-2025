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
