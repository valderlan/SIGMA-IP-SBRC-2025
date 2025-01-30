#!/bin/bash

# Script de checagem de serviço.

# Nome do processo a ser verificado
PROCESS_NAME="FIBRA"

# Caminho do comando para iniciar o processo
START_COMMAND="/opt/FIBRA-UECE/python/bin/python3 /opt/FIBRA-UECE/collect/collect-pgsql-ipv4-tcp-syn.py"

# Caminho do arquivo de log
LOG_FILE="/var/log/fibra-err.log"

# Função para verificar se o processo está em execução
is_process_running() {
    pgrep -f "$PROCESS_NAME" > /dev/null 2>&1
    return $?
}

# Verifica se o processo está em execução
is_process_running

if [ $? -ne 0 ]; then
    # O processo não está em execução, então inicie-o
    echo "Processo $PROCESS_NAME não encontrado. Iniciando processo."
    $START_COMMAND > /dev/null 2>&1
    echo "$(date +%Y/%m/%d) -- $(date +%H:%M) -- Serviço $PROCESS_NAME iniciado" >> $LOG_FILE
else
    echo "Processo $PROCESS_NAME já está em execução."
fi