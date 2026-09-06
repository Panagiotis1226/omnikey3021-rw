"""Minimal door controller: grant -> pulse a relay (replace `open_door`)."""

import subprocess
import time

from omnikey3021 import OmnikeyReader
from omnikey3021.access import AccessController, AccessStore, load_or_create_key

SITE_CODE = 7


def open_door(decision):
    print(time.strftime("%H:%M:%S"), decision.summary())
    if decision.granted:
        # e.g. Raspberry Pi relay on GPIO 17 for 3 seconds
        subprocess.run("gpioset gpiochip0 17=1 && sleep 3 && gpioset gpiochip0 17=0", shell=True, check=False)


store = AccessStore("access.sqlite3")
controller = AccessController(store, load_or_create_key("site.key", create=False), SITE_CODE)
with OmnikeyReader() as reader:
    controller.monitor(reader, open_door)
