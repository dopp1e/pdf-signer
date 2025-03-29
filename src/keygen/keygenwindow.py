from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QTabWidget, QCheckBox, QLineEdit, QPushButton, QScrollArea
from PyQt6 import QtCore
import sys
import os
from common import genericwindow

from common.main import represents_int

class KeygenWindow(genericwindow.GenericWindow):
    def switch_custom_input(self):
        enabled = self.custom_settings_check.checkState() == QtCore.Qt.CheckState.Checked
        self.custom_exponent_input.setEnabled(enabled)
        self.custom_pk_input.setEnabled(enabled)
    
    def password_updated(self):
        password = self.password_input.text()
        if (password == ""):
            self.key_password_hint.setText("It is recommended to set a password!")
        else:
            self.key_password_hint.setText("")

    def custom_settings_updated(self):
        if (self.custom_settings_check.checkState() == QtCore.Qt.CheckState.Checked):
            message_string = ""
            exponent_value = represents_int(self.custom_exponent_input.text())
            key_value = represents_int(self.custom_pk_input.text())
            if (exponent_value == False):
                message_string += "The exponent should be an integer!\n"
            if (key_value == False):
                message_string += "The public key should be an integer!\n"
            self.custom_settings_hint.setText(message_string)
        else:
            self.custom_settings_hint.setText("")

    def generate_key():
        pass

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

        self.custom_exponent_input = QLineEdit()
        self.custom_exponent_input.textChanged.connect(self.custom_settings_updated)
        self.custom_exponent_label = QLabel()
        self.custom_exponent_box = QHBoxLayout()
        self.custom_exponent_input.setEnabled(False)
        self.custom_exponent_label.setText("Public Exponent")
        self.custom_exponent_box.addWidget(self.custom_exponent_label)
        self.custom_exponent_box.addStretch()
        self.custom_exponent_box.addWidget(self.custom_exponent_input)

        self.custom_pk_input = QLineEdit()
        self.custom_pk_input.textChanged.connect(self.custom_settings_updated)
        self.custom_pk_label = QLabel()
        self.custom_pk_box = QHBoxLayout()
        self.custom_pk_input.setEnabled(False)
        self.custom_pk_label.setText("Private Key")
        self.custom_pk_box.addWidget(self.custom_pk_label)
        self.custom_pk_box.addStretch()
        self.custom_pk_box.addWidget(self.custom_pk_input)

        self.key_password_hint = QLabel()
        self.custom_settings_hint = QLabel()
        self.custom_settings_hint.setFixedHeight(40)

        self.generate_button = QPushButton()
        self.generate_button.setText("Generate Key")
        self.generate_button.released.connect(self.generate_key)

        self.keygenlayout.addSpacing(8) # for better separation from the tabs
        self.keygenlayout.addLayout(self.key_name_box)
        self.keygenlayout.addLayout(self.password_box)
        self.keygenlayout.addWidget(self.key_password_hint)
        self.keygenlayout.addSpacing(8) # for better separation of topics
        self.keygenlayout.addLayout(self.custom_settings_box)
        self.keygenlayout.addLayout(self.custom_exponent_box)
        self.keygenlayout.addLayout(self.custom_pk_box)
        self.keygenlayout.addSpacing(4) 
        self.keygenlayout.addWidget(self.custom_settings_hint)
        self.keygenlayout.addSpacing(4) 
        self.keygenlayout.addWidget(self.generate_button)
        self.keygenlayout.addStretch()

        # Key Management:

        self.keys_outer_layout = QVBoxLayout()
        self.keys_scroll = QScrollArea()
        self.keys_widget = QWidget()
        self.keys_layout = QVBoxLayout()

        self.keys_widget.setLayout(self.keys_layout)
        self.keys_scroll.setWidget(self.keys_widget)
        self.keys_outer_layout.addWidget(self.keys_scroll)

        self.keymanagement.setLayout(self.keys_outer_layout)

        # Initialization:

        self.password_updated()