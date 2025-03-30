from PyQt6.QtWidgets import QMainWindow, QWidget, QComboBox, QLabel, QVBoxLayout, QHBoxLayout, QTabWidget, QLineEdit, QMessageBox
from PyQt6 import QtCore
import sys
import os

usb_location = "/run/media/doppie"

class GenericWindow(QMainWindow):
    """
    A window template class for both of the applications to use.
    """
    def scan_pendrives(self):
        """
        Scans the specified folder for connected USB devices to use.
        """
        if not os.path.exists(self.location):
            return
        
        subfolders = [f for f in os.scandir(self.location) if f.is_dir()]
        #print(subfolders)
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
        self.pendrive_selected = new_index != -1
        self.pendrives = new_pendrives

    def directory_changed(self):
        print("Directory changed, updating pendrive list.")
        self.scan_pendrives()

    def location_confirm(self):
        self.scan_pendrives()
        pass

    def location_changed(self):
        if os.path.exists(self.directory_picker.text()):
            self.directory_hint.setText("")
        else:
            self.directory_hint.setText("Path doesn't seem to exist. Please ensure it's a correct path.")

    def get_pendrive_name(self) -> str:
        return self.pendrive_selector.currentText()
    
    def get_watch_folder(self) -> str:
        return self.directory_picker.text()
    
    def show_message(self, text: str):
        message_box = QMessageBox()
        message_box.setText(text)
        message_box.exec()

    def is_pendrive_selected(self) -> bool:
        self.pendrive_selected = self.pendrive_selector.currentIndex() != -1
        return self.pendrive_selected

    def __init__(self):
        super().__init__()
        self.pendrives = []
        # self.setGeometry(50, 50, 500, 500)
        self.setWindowTitle("UwU")
        self.location = usb_location
        self.pendrive_selected = False

        self.directory_hint = QLabel("")
        self.filewatcher = QtCore.QFileSystemWatcher([self.location])
        self.filewatcher.directoryChanged.connect(self.directory_changed)
        self.directory_label = QLabel("Choose the media location...")
        self.directory_picker = QLineEdit()
        self.directory_picker.textChanged.connect(self.location_changed)
        self.directory_picker.textEdited.connect(self.location_confirm)
        self.directory_picker.setText(self.location)

        self.pendrive_label = QLabel("Select your pendrive...")
        self.pendrive_selector = QComboBox()
        
        self.lower_layout = QTabWidget()

        self.inner_layout = QVBoxLayout()
        self.inner_layout.addWidget(self.directory_label)
        self.inner_layout.addWidget(self.directory_picker)
        self.inner_layout.addWidget(self.directory_hint)
        self.inner_layout.addWidget(self.pendrive_label)
        self.inner_layout.addWidget(self.pendrive_selector)
        self.inner_layout.addWidget(self.lower_layout)
        
        self.middle_layout = QVBoxLayout()
        self.middle_layout.addStretch(1)
        self.middle_layout.addLayout(self.inner_layout, 3)
        self.middle_layout.addStretch(1)

        self.outer_layout = QHBoxLayout()
        self.outer_layout.addStretch(1)
        self.outer_layout.addLayout(self.middle_layout, 3)
        self.outer_layout.addStretch(1)

        self.container = QWidget()
        self.container.setLayout(self.outer_layout)

        self.setCentralWidget(self.container)
        self.scan_pendrives()
        self.lower_layout.hide()
        self.lower_layout.tabBar().setExpanding(True)
