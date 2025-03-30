from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit, QPushButton, QScrollArea
from PyQt6 import QtCore
import time

from common import genericwindow
from common import password_input
from common.main import represents_int, does_key_exist, prepare_location, make_key, make_key_location, is_divisible, list_keys, load_private_key, delete_key

class KeygenWindow(genericwindow.GenericWindow):
    def switch_custom_input(self):
        enabled = self.is_custom_enabled()
        self.custom_pk_input.setEnabled(enabled)
        self.custom_pk_label.setEnabled(enabled)
        self.update_button()

    def get_key_name(self):
        return self.key_name_input.text()
    
    def get_key_password(self):
        return self.password_input.text()
    
    def is_custom_enabled(self):
        return self.custom_settings_check.checkState() == QtCore.Qt.CheckState.Checked

    def is_key_name_ok(self):
        name = self.key_name_input.text()
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = make_key_location(watch_folder, pendrive_name)
        if (name == ""):
            return 1
        elif (does_key_exist(location, name)):
            return 2
        else:
            return 0
        
    def is_password_set(self):
        password = self.password_input.text()
        return password != ""

    def name_updated(self):
        code = self.is_key_name_ok()
        if (code == 1):
            self.key_name_hint.setText("Your key must have a name!")
        elif (code == 2):
            self.key_name_hint.setText("Key with this name already exists!")
        elif (code == 0):
            self.key_name_hint.setText("")
        self.update_button()
    
    def password_updated(self):
        is_set = self.is_password_set()
        if (not is_set):
            self.key_password_hint.setText("It is recommended to set a password!")
        else:
            self.key_password_hint.setText("")
        self.update_button()

    def custom_settings_updated(self):
        if (self.is_custom_enabled()):
            message_string = ""
            key_value = represents_int(self.custom_pk_input.text())
            if (not key_value):
                message_string += "The public key should be an integer!\n"
            else:
                key_size = int(key_value)
                if (not is_divisible(key_size, 512)):
                    message_string += "The key size must be divisible by 512!\n"
            self.custom_settings_hint.setText(message_string)
        else:
            self.custom_settings_hint.setText("")
        self.update_button()

    def pendrive_selection_changed(self):
        self.update_key_list()
        self.is_pendrive_selected()
        self.update_button()

    def update_button(self):
        custom = bool(represents_int(self.custom_pk_input.text())) if self.is_custom_enabled() else True
        divisible = True
        if (bool(represents_int(self.custom_pk_input.text()))):
            divisible = is_divisible(int(self.custom_pk_input.text()), 512)
        enabled = (self.is_key_name_ok() == 0 and custom and self.is_pendrive_selected() and divisible)
        self.generate_button.setEnabled(enabled)

    def generate_key(self):
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        prepare_location(watch_folder, pendrive_name)
        location = make_key_location(watch_folder, pendrive_name)
        if (not self.is_pendrive_selected()):
            self.show_message("You must select a pendrive first!")
            return False
        
        key_name = self.get_key_name()
        if (key_name == ""):
            self.show_message("Key must not have an empty name!")
            return False
        
        if (does_key_exist(location, key_name)):
            self.show_message("Key already exists, please use a different name!")
            return False
        
        password = self.get_key_password() 
        
        key_size = 4096
        if (self.is_custom_enabled()):
            custom_key_size = self.custom_pk_input.text()
            if (not represents_int(custom_key_size)):
                self.show_message("Custom key size must be an integer!")
                return False
            key_size = int(custom_key_size)
            
        if (not is_divisible(key_size, 512)):
            self.show_message("Key size must be divisible by 512!")

        make_key(key_size, password, location, key_name)
        return True

    def generate_key_wrapper(self):
        self.key_generated_hint.setText("Your key is being generated, please wait...")
        # absolutely insane workaround to make the text display
        loop = QtCore.QEventLoop()
        QtCore.QTimer.singleShot(0, loop.quit)
        loop.exec()
        # end of the workaround
        result = self.generate_key()
        if result:
            self.update_key_list()
            self.show_message("Key generated successfully!")
        self.key_generated_hint.setText("")
        self.name_updated()

    def check_password(self, key: str):
        input = password_input.PasswordInput()
        result = input.exec()
        if (result == 0):
            return
        
        password = input.getPassword()
        loaded = load_private_key(password, make_key_location(self.get_watch_folder(), self.get_pendrive_name()), key)
        if (loaded):
            self.show_message("Password correct!")
        else:
            self.show_message("Password not correct!")

    def delete_key(self, key: str):
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = make_key_location(watch_folder, pendrive_name)
        delete_key(location, key)
        self.update_key_list()

    def update_key_list(self):
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = make_key_location(watch_folder, pendrive_name)
        keys = list_keys(location)
        self.keys_layout = QVBoxLayout()
        self.keys_layout.setSpacing(4)
        self.keys_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        self.keys_widget = QWidget()
        self.keys_widget.setLayout(self.keys_layout)
        self.keys_scroll.setWidget(self.keys_widget)
        for key in keys:
            key_container = QWidget()
            key_box = QHBoxLayout(key_container)
            key_box.setContentsMargins(0, 0, 0, 0)
            key_box.setSpacing(0)
            key_label = QLabel(key)
            key_delete_button = QPushButton("Delete")
            key_delete_button.released.connect(lambda key=key: self.delete_key(key))
            key_check_pass_button = QPushButton("Check Password")
            key_check_pass_button.released.connect(lambda key=key: self.check_password(key))
            key_box.addWidget(key_label)
            key_box.addStretch()
            key_box.addWidget(key_check_pass_button)
            key_box.addWidget(key_delete_button)
            self.keys_layout.addWidget(key_container)

    def __init__(self):
        super().__init__()
        self.lower_layout.show()
        
        self.keygeneration = QWidget()
        self.keygenlayout = QVBoxLayout(self.keygeneration)
        self.keymanagement = QWidget()

        # Key Generation:

        self.lower_layout.tabBar().setExpanding(True)
        self.lower_layout.tabBar().setDocumentMode(True)
        self.lower_layout.addTab(self.keygeneration, "Key Generation")
        self.lower_layout.addTab(self.keymanagement, "Key Management")

        self.key_name_input = QLineEdit()
        self.key_name_input.textChanged.connect(self.name_updated)
        self.key_name_label = QLabel()
        self.key_name_label.setText("Key Name")
        self.key_name_box = QHBoxLayout()
        self.key_name_box.addWidget(self.key_name_label)
        self.key_name_box.addStretch()
        self.key_name_box.addWidget(self.key_name_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.password_updated)
        self.password_label = QLabel()
        self.password_label.setText("Key Password")
        self.password_box = QHBoxLayout()
        self.password_box.addWidget(self.password_label)
        self.password_box.addStretch()
        self.password_box.addWidget(self.password_input)
        
        self.custom_settings_check = QCheckBox()
        self.custom_settings_check.checkStateChanged.connect(self.switch_custom_input)
        self.custom_settings_check.checkStateChanged.connect(self.custom_settings_updated)
        self.custom_settings_label = QLabel()
        self.custom_settings_label.setText("Use custom settings")
        self.custom_settings_box = QHBoxLayout()
        self.custom_settings_box.addWidget(self.custom_settings_check)
        self.custom_settings_box.addWidget(self.custom_settings_label)
        self.custom_settings_box.addStretch()

        self.custom_pk_input = QLineEdit()
        self.custom_pk_input.textChanged.connect(self.custom_settings_updated)
        self.custom_pk_label = QLabel()
        self.custom_pk_box = QHBoxLayout()
        self.custom_pk_input.setEnabled(False)
        self.custom_pk_label.setText("Key Size")
        self.custom_pk_box.addWidget(self.custom_pk_label)
        self.custom_pk_box.addStretch()
        self.custom_pk_box.addWidget(self.custom_pk_input)

        self.key_name_hint = QLabel()
        self.key_password_hint = QLabel()
        self.custom_settings_hint = QLabel()
        self.custom_settings_hint.setFixedHeight(40)
        self.key_generated_hint = QLabel()
        self.key_generated_hint.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        self.generate_button = QPushButton()
        self.generate_button.setText("Generate Key")
        self.generate_button.released.connect(self.generate_key_wrapper)

        self.keygenlayout.addSpacing(8) # for better separation from the tabs
        self.keygenlayout.addLayout(self.key_name_box)
        self.keygenlayout.addWidget(self.key_name_hint)
        self.keygenlayout.addLayout(self.password_box)
        self.keygenlayout.addWidget(self.key_password_hint)
        self.keygenlayout.addSpacing(8) # for better separation of topics
        self.keygenlayout.addLayout(self.custom_settings_box)
        self.keygenlayout.addLayout(self.custom_pk_box)
        self.keygenlayout.addSpacing(4) 
        self.keygenlayout.addWidget(self.custom_settings_hint)
        self.keygenlayout.addSpacing(4) 
        self.keygenlayout.addWidget(self.generate_button)
        self.keygenlayout.addSpacing(4)
        self.keygenlayout.addWidget(self.key_generated_hint)
        self.keygenlayout.addStretch()

        # Key Management:

        self.keys_outer_layout = QVBoxLayout()
        self.keys_scroll = QScrollArea()
        self.keys_scroll.setWidgetResizable(True)
        self.keys_widget = QWidget()
        self.keys_layout = QVBoxLayout()
        self.keys_layout.setSpacing(4)
        self.keys_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)


        self.keys_widget.setLayout(self.keys_layout)
        self.keys_scroll.setWidget(self.keys_widget)
        self.keys_outer_layout.addWidget(self.keys_scroll)

        self.keymanagement.setLayout(self.keys_outer_layout)

        # Initialization:

        self.pendrive_selector.currentIndexChanged.connect(self.pendrive_selection_changed)
        self.password_updated()
        self.name_updated()
        self.switch_custom_input()
        self.update_button()