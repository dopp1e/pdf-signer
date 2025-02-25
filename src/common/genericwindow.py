from PyQt6.QtWidgets import QMainWindow, QWidget, QComboBox, QLabel, QVBoxLayout, QHBoxLayout, QTabWidget
from PyQt6 import QtCore
import sys
import os

usb_location = "/run/media/doppie/"

class GenericWindow(QMainWindow):
    """
    A window template class for both of the applications to use.
    """
    def scan_pendrives(self):
        """
        Scans the specified folder for connected usb devices to use.
        """
        subfolders = [f for f in os.scandir(usb_location) if f.is_dir()]
        new_pendrives = []
        for folder in subfolders:
            pendrive_name = os.path.basename(folder)
            new_pendrives.append(pendrive_name)
            pass

        new_index = -1
        if self.pendrive_selector.currentIndex() != -1:
            print(self.pendrive_selector.currentIndex())
            current_item = self.pendrives[self.pendrive_selector.currentIndex()]
            new_index = new_pendrives.index(current_item) if current_item in new_pendrives else -1

        self.pendrive_selector.clear()
        for pendrive in new_pendrives:
            self.pendrive_selector.addItem(pendrive)
        
        self.pendrive_selector.setCurrentIndex(new_index)
        self.pendrives = new_pendrives

    @QtCore.pyqtSlot(str)
    def directory_changed(self, path):
        print("Directory changed, updating pendrive list.")
        self.scan_pendrives()

    def __init__(self):
        super().__init__()
        self.pendrives = []
        # self.setGeometry(50, 50, 500, 500)
        self.setWindowTitle("UwU")

        self.filewatcher = QtCore.QFileSystemWatcher([usb_location])
        self.filewatcher.directoryChanged.connect(self.directory_changed)

        self.pendrive_label = QLabel("Select your pendrive...")
        self.pendrive_selector = QComboBox()
        
        self.lower_layout = QTabWidget()

        self.inner_layout = QVBoxLayout()
        self.inner_layout.addStretch()
        self.inner_layout.addWidget(self.pendrive_label)
        self.inner_layout.addWidget(self.pendrive_selector)
        self.inner_layout.addWidget(self.lower_layout)
        self.inner_layout.addStretch()

        self.outer_layout = QHBoxLayout()
        self.outer_layout.addStretch(1)
        self.outer_layout.addLayout(self.inner_layout, 2)
        self.outer_layout.addStretch(1)

        self.container = QWidget()
        self.container.setLayout(self.outer_layout)

        self.setCentralWidget(self.container)
        self.scan_pendrives()
        self.lower_layout.hide()