#!/bin/bash

# Verifica ed installazione di Python3 e pip
if ! command -v python3 >/dev/null || ! command -v pip3 >/dev/null; then
    echo "Installing Python3 and pip..."
    sudo apt-get install python3 python3-pip -y
fi

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

# Verifica ed installazione di arp-scan
if ! command -v arp-scan >/dev/null; then
    echo "Installing arp-scan..."
    sudo apt-get install arp-scan -y
fi

# Verifica ed installazione di msfconsole e msfvenom
if ! command -v msfconsole >/dev/null || ! command -v msfvenom >/dev/null; then
    # Importa la chiave pubblica di Metasploit
    sudo apt-key adv --keyserver hkp://pool.sks-keyservers.net --recv-keys CDFB5FA52007B954

    # Aggiorna la cache dei repository
    sudo apt-get update

    # Installa Metasploit Framework
    echo "deb http://apt.metasploit.com/ lucid main" | sudo tee /etc/apt/sources.list.d/metasploit-framework.list
    sudo apt-get update
    sudo apt-get install metasploit-framework -y
fi

# Verifica ed installazione di python-nmap
if ! python3 -c "import nmap"; then
    echo "Installing python-nmap..."
    sudo apt-get install python3-nmap -y
fi

# Verifica ed installazione di nslookup
if ! command -v nslookup >/dev/null; then
    echo "Installing nslookup..."
    sudo apt-get install dnsutils -y
fi

# Esegui il programma Python
python3 haxlopa.py
