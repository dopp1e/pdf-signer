from PyQt6.QtWidgets import QMainWindow, QWidget, QComboBox, QLabel, QVBoxLayout, QHBoxLayout, QTabWidget, QLineEdit, QMessageBox
from PyQt6 import QtCore
import sys
import os

usb_location = "/run/media/doppie"

class GenericWindow(QMainWindow):
    """
    A window template class for both of the applications to use.
    """
    def scan_pendrives(self) -> None:
        """
        Scans the specified folder for connected USB devices to use.
        The folder is specified in the usb_location variable.
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
        self.pendrive_selector.addItems(new_pendrives)
        
        if (len(new_pendrives) > 0):
            new_index = 0

        self.pendrive_selector.setCurrentIndex(new_index)
        self.pendrive_selected = new_index != -1
        self.pendrives = new_pendrives

    def directory_changed(self) -> None:
        """
        Called when the directory changes.
        It updates the pendrive list and the directory picker.
        """
        print("Directory changed, updating pendrive list.")
        self.scan_pendrives()

    def location_confirm(self) -> None:
        """
        Called when the directory picker changes are confirmed.
        It updates the pendrive list and the directory picker.
        """
        self.scan_pendrives()

    def location_changed(self) -> None:
        """
        Called when the directory picker is edited.
        It updates the directory hint label.
        """
        if os.path.exists(self.directory_picker.text()):
            self.directory_hint.setText("")
        else:
            self.directory_hint.setText("Path doesn't seem to exist. Please ensure it's a correct path.")

    def get_pendrive_name(self) -> str:
        """
        Returns the name of the selected pendrive.
        If no pendrive is selected, it returns an empty string.

        Returns:
            str: The name of the selected pendrive.
        """
        return self.pendrive_selector.currentText()
    
    def get_watch_folder(self) -> str:
        """
        Returns the path of the selected folder to watch.
        If no folder is selected, it returns an empty string.
        
        Returns:
            str: The path of the selected folder.
        """
        return self.directory_picker.text()
    
    def show_message(self, text: str) -> None:
        """
        Shows a message box with the specified text.
        """
        message_box = QMessageBox()
        message_box.setText(text)
        message_box.exec()

    def is_pendrive_selected(self) -> bool:
        """
        Returns whether a pendrive is selected or not.
        """
        self.pendrive_selected = self.pendrive_selector.currentIndex() != -1
        return self.pendrive_selected
    
    def reload_window(self) -> None:
        """
        Reloads the window, forcing it to redraw.
        This is a workaround for a bug where the text in the window doesn't display correctly.
        """
        # absolutely insane workaround to make the text display
        loop = QtCore.QEventLoop()
        QtCore.QTimer.singleShot(0, loop.quit)
        loop.exec()
        # end of the workaround

    def __init__(self):
        """
        Initializes the GenericWindow class.
        It sets up the window layout, pendrive selector, and directory picker.
        """
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
        self.middle_layout.addLayout(self.inner_layout, 6)
        self.middle_layout.addStretch(1)

        self.outer_layout = QHBoxLayout()
        self.outer_layout.addStretch(1)
        self.outer_layout.addLayout(self.middle_layout, 6)
        self.outer_layout.addStretch(1)

        self.container = QWidget()
        self.container.setLayout(self.outer_layout)

        self.setCentralWidget(self.container)
        self.scan_pendrives()
        self.lower_layout.hide()
        self.lower_layout.tabBar().setExpanding(True)
