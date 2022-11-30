import pyinotify
import os


pid = ""


class EventProcessor(pyinotify.ProcessEvent):
    _methods = [
        "IN_CREATE",
        "IN_OPEN",
        "IN_ACCESS",
        "IN_ATTRIB",
        "IN_CLOSE_NOWRITE",
        "IN_CLOSE_WRITE",
        "IN_DELETE",
        "IN_DELETE_SELF",
        "IN_IGNORED",
        "IN_MODIFY",
        "IN_MOVE_SELF",
        "IN_MOVED_FROM",
        "IN_MOVED_TO",
        "IN_Q_OVERFLOW",
        "IN_UNMOUNT",
        "default"
    ]


def process_generator(cls, method):
    def _method_name(self, event):
        print("Method name: process_{}()\n"
               "Path name: {}\n"
               "Event Name: {}\n".format(method, event.pathname, event.maskname))
    _method_name.__name__ = "process_{}".format(method)
    setattr(cls, _method_name.__name__, _method_name)


def start_watchfile(filename):
    global pid
    pid = os.getpid()

    for _method in EventProcessor._methods:
        process_generator(EventProcessor, _method)

    watch_manager = pyinotify.WatchManager()
    event_notifier = pyinotify.ThreadedNotifier(watch_manager, EventProcessor())

    watch_manager.add_watch(filename, pyinotify.ALL_EVENTS)
    event_notifier.start()
