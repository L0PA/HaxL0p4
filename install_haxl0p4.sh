#!/bin/bash

# Elenco delle librerie Python richieste
required_libraries=("os" "scapy" "requests" "json" "colorama")

# Verifica ed installazione delle librerie Python
for library in "${required_libraries[@]}"
do
    if ! python3 -c "import $library"; then
        echo "Installing $library..."
        pip3 install $library
    fi
done

# Verifica ed installazione di proxychains
if ! command -v proxychains >/dev/null; then
    echo "Installing proxychains..."
    sudo apt-get install proxychains -y
fi

# Aggiorna la cache dei repository
sudo apt-get update

# Verifica ed installazione di arp-scan
if ! command -v arp-scan >/dev/null; then
    echo "Installing arp-scan..."
    sudo apt-get install arp-scan -y
fi

# Esegui il programma Python
python3 haxlopa.py
