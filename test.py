# -*- coding: utf-8 -*-

import sys
import subprocess
import os
import tempfile
import shutil
import atexit
import re
import codecs
import socket
import pathlib
import time
from datetime import datetime
import collections
import statistics
import csv
from pathlib import Path
from typing import Dict
from colors import *

def main():
    banner()
    check_root()
    check_airmon()
    check_reaver()
    check_pixiewps()
    check_wash()

    while True:
        print(f"{G}1.{W} Quét WiFi hỗ trợ WPS")
        print(f"{G}2.{W} Tính PIN WPS theo MAC")
        print(f"{G}3.{W} Tấn công Brute-force")
        print(f"{G}4.{W} Tấn công Pixie Dust")
        print(f"{G}5.{W} Kết nối WiFi bằng wpa_supplicant")
        print(f"{G}6.{W} Ngắt kết nối WiFi")
        print(f"{G}0.{W} Thoát")

        choice = input(f"\n{G}[>>]{W} Nhập lựa chọn: ")

        if choice == '1':
            scan_wps()
        elif choice == '2':
            calc_pin()
        elif choice == '3':
            brute_force()
        elif choice == '4':
            pixie_attack()
        elif choice == '5':
            connect_wpa()
        elif choice == '6':
            disconnect_wpa()
        elif choice == '0':
            print(f"{G}Tạm biệt!")
            sys.exit(0)
        else:
            print(f"{R}Lựa chọn không hợp lệ. Hãy thử lại.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[!!]{W} Dừng chương trình.")
        sys.exit(0)
