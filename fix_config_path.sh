#!/bin/bash

# Script para corrigir caminho de configuração após instalação

echo "fixing cspnetwork configuration path..."

# Criar diretório /etc/cspnetwork se não existir
sudo mkdir -p /etc/cspnetwork
sudo mkdir -p /etc/cspnetwork/examples

# Copiar configuração do local atual para o local correto
if [ -f "/usr/local/etc/cspnetwork/config.yaml" ]; then
    echo "copying config from /usr/local/etc/cspnetwork/ to /etc/cspnetwork/"
    sudo cp /usr/local/etc/cspnetwork/config.yaml /etc/cspnetwork/
    sudo cp /usr/local/etc/cspnetwork/examples/* /etc/cspnetwork/examples/ 2>/dev/null || true
fi

# Definir permissões corretas
sudo chown -R cspnetwork:cspnetwork /etc/cspnetwork 2>/dev/null || echo "user cspnetwork not found, skipping ownership"
sudo chmod 755 /etc/cspnetwork
sudo chmod 640 /etc/cspnetwork/config.yaml 2>/dev/null || echo "config file not found"

# Reiniciar serviço
echo "restarting cspnetwork service..."
sudo systemctl restart cspnetwork

echo "configuration path fixed successfully"
echo "config location: /etc/cspnetwork/config.yaml"
echo "service status:"
sudo systemctl status cspnetwork --no-pager -l
