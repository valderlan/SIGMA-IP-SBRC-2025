sudo apt update

sudo apt install -y vim wget bash-completion \
    tcpdump net-tools curl telnet \
    nmap zip unzip cron

echo "Instalação de pacotes concluída."

set -e  # Para o script se qualquer comando falhar

# Variáveis de configuração
GEOIP_DEB="geoipupdate_6.1.0_linux_amd64.deb"
GEOIP_URL="https://github.com/maxmind/geoipupdate/releases/download/v6.1.0/$GEOIP_DEB"
GEOIP_CONF="/usr/share/doc/geoipupdate/GeoIP.conf"

# Baixa o pacote .deb
echo "Baixando geoipupdate..."
wget -O "$GEOIP_DEB" "$GEOIP_URL"

# Instala o pacote
echo "Instalando geoipupdate..."
sudo dpkg -i "$GEOIP_DEB"

# Cria o arquivo de configuração
echo "Configurando GeoIP.conf..."
sudo tee "$GEOIP_CONF" > /dev/null <<EOL
# GeoIP.conf file for \`geoipupdate\` program, for versions >= 3.1.1.
# Used to update GeoIP databases from https://www.maxmind.com.
# For more information about this config file, visit the docs at
# https://dev.maxmind.com/geoip/updating-databases.

# \`AccountID\` is from your MaxMind account.
AccountID 1042771

# Replace YOUR_LICENSE_KEY_HERE with an active license key associated
# with your MaxMind account.
LicenseKey 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

# \`EditionIDs\` is from your MaxMind account.
EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
EOL

# Mensagem final
echo "Instalação e configuração do geoipupdate concluída."

# Roda o geoipupdate para baixar os bancos de dados
echo "Atualizando bancos de dados GeoIP..."
sudo geoipupdate -f /usr/share/doc/geoipupdate/GeoIP.conf

echo "Bancos de dados GeoIP atualizados com sucesso."
