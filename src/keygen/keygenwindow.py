from PyQt6.QtWidgets import QMainWindow, QWidget, QComboBox, QLabel, QVBoxLayout, QHBoxLayout, QTabWidget
from PyQt6 import QtCore
import sys
import os
from common import genericwindow

usb_location = "/run/media/doppie/"

class KeygenWindow(genericwindow.GenericWindow):
    def __init__(self):
        super().__init__()
        