from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit, QPushButton, QScrollArea, QFileDialog
from PyQt6 import QtCore

from common import genericwindow
from common import password_input
from common.main import Logic

class KeygenWindow(genericwindow.GenericWindow):
    """
    A window for generating and managing keys.
    Inherits from the GenericWindow class.
    """
    def switch_custom_input(self) -> None:
        """
        Switches the custom key size input on or off based on the checkbox state.
        """
        enabled = self.is_custom_enabled()
        self.custom_pk_input.setEnabled(enabled)
        self.custom_pk_label.setEnabled(enabled)
        self.update_button()

    def get_key_name(self) -> str:
        """
        Returns the key name entered by the user.

        Returns:
            str: The key name entered by the user.
        """
        return self.key_name_input.text()
    
    def get_key_password(self) -> str:
        """
        Returns the key password entered by the user.

        Returns:
            str: The key password entered by the user.
        """
        return self.password_input.text()
    
    def is_custom_enabled(self) -> bool:
        """
        Returns whether the custom key size input is enabled or not.
        
        Returns:
            bool: True if the custom key size input is enabled, False otherwise.
        """
        return self.custom_settings_check.checkState() == QtCore.Qt.CheckState.Checked

    def is_key_name_ok(self) -> int:
        """
        Checks if the key name is valid.
        
        Returns:
            int: 0 if the key name is valid, 1 if it is empty, 2 if it already exists.
        """
        name = self.key_name_input.text()
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = Logic.make_key_location(watch_folder, pendrive_name)
        if (name == ""):
            return 1
        elif (Logic.does_key_exist(location, name)):
            return 2
        else:
            return 0
        
    def is_password_set(self) -> bool:
        """
        Checks if the password is set.

        Returns:
            bool: True if the password is set, False otherwise.
        """
        password = self.password_input.text()
        return password != ""

    def name_updated(self) -> None:
        """
        Called when the key name is updated.
        It checks if the key name is valid and updates the hint label accordingly.
        """
        code = self.is_key_name_ok()
        if (code == 1):
            self.key_name_hint.setText("Your key must have a name!")
        elif (code == 2):
            self.key_name_hint.setText("Key with this name already exists!")
        elif (code == 0):
            self.key_name_hint.setText("")
        self.update_button()
    
    def password_updated(self) -> None:
        """
        Called when the password is updated.
        It checks if the password is set and updates the hint label accordingly.
        """
        is_set = self.is_password_set()
        if (not is_set):
            self.key_password_hint.setText("You must set a password!")
        elif (len(self.password_input.text()) < 8):
            self.key_password_hint.setText("Your password must be at least 8 characters or longer!")
        else:
            self.key_password_hint.setText("")
        self.update_button()

    def custom_settings_updated(self) -> None:
        """
        Called when the custom settings are updated.
        It checks if the custom key size is valid and updates the hint label accordingly.
        """
        if (self.is_custom_enabled()):
            message_string = ""
            key_value = Logic.represents_int(self.custom_pk_input.text())
            if (not key_value):
                message_string += "The public key should be an integer!\n"
            else:
                key_size = int(key_value)
                if (not Logic.is_divisible(key_size, 512)):
                    message_string += "The key size must be divisible by 512!\n"
            self.custom_settings_hint.setText(message_string)
        else:
            self.custom_settings_hint.setText("")
        self.update_button()

    def pendrive_selection_changed(self) -> None:
        """
        Called when the pendrive selection is changed.
        It updates the pendrive name and the key list.
        """
        self.update_key_list()
        self.is_pendrive_selected()
        self.update_button()

    def update_button(self) -> None:
        """
        Updates the state of the generate button based on the current input values.
        """
        custom = bool(Logic.represents_int(self.custom_pk_input.text())) if self.is_custom_enabled() else True
        divisible = True
        if (bool(Logic.represents_int(self.custom_pk_input.text()))):
            divisible = Logic.is_divisible(int(self.custom_pk_input.text()), 512)
        enabled = (self.is_key_name_ok() == 0 and custom and self.is_pendrive_selected() and divisible and len(self.password_input.text()) >= 8)
        self.generate_button.setEnabled(enabled)

    def generate_key(self) -> bool:
        """
        Generates a key based on the user input.
        It checks if the pendrive is selected, if the key name is valid,
        if the key size is valid, and if the password is set.
        
        Returns:
            bool: True if the key is generated successfully, False otherwise.
        """
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        Logic.prepare_location(watch_folder, pendrive_name)
        location = Logic.make_key_location(watch_folder, pendrive_name)
        if (not self.is_pendrive_selected()):
            self.show_message("You must select a pendrive first!")
            return False
        
        key_name = self.get_key_name()
        if (key_name == ""):
            self.show_message("Key must not have an empty name!")
            return False
        
        if (Logic.does_key_exist(location, key_name)):
            self.show_message("Key already exists, please use a different name!")
            return False
        
        password = self.get_key_password() 
        
        key_size = 4096
        if (self.is_custom_enabled()):
            custom_key_size = self.custom_pk_input.text()
            if (not Logic.represents_int(custom_key_size)):
                self.show_message("Custom key size must be an integer!")
                return False
            key_size = int(custom_key_size)
            
        if (not Logic.is_divisible(key_size, 512)):
            self.show_message("Key size must be divisible by 512!")

        Logic.make_key(key_size, password, location, key_name)
        return True

    def generate_key_wrapper(self) -> None:
        """
        Wrapper function for generating a key.
        It shows a message while the key is being generated and updates the key list.
        """
        self.key_generated_hint.setText("Your key is being generated, please wait...")
        self.reload_window()
        result = self.generate_key()
        if result:
            self.update_key_list()
            self.show_message("Key generated successfully!")
        self.key_generated_hint.setText("")
        self.name_updated()

    def check_password(self, key: str) -> None:
        """
        Checks if the password the user provides for the given key is correct.
        """
        input = password_input.PasswordInput()
        result = input.exec()
        if (result == 0):
            return
        
        password = input.getPassword()
        result = Logic.load_private_key(password, Logic.make_key_location(self.get_watch_folder(), self.get_pendrive_name()), key)
        if (result[0]):
            self.show_message("Password correct!")
        else:
            self.show_message("Password not correct!")

    def delete_key(self, key: str) -> None:
        """
        Deletes the key with the given name.
        """
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = Logic.make_key_location(watch_folder, pendrive_name)
        Logic.delete_key(location, key)
        self.update_key_list()

    def export_public_key(self, key: str) -> None:
        """
        Exports the public key to a file, as chosen by the user.
        It opens a file dialog to choose the location and filename for the key.
        """
        filename = QFileDialog.getSaveFileName(caption="Choose key file location",directory=QtCore.QDir.homePath())
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        if Logic.copy_public_key(watch_folder, pendrive_name, key, filename[0]):
            self.show_message("Public key saved!")
        else:
            self.show_message("Saving failed.")

    def update_key_list(self) -> None:
        """
        Updates the key list in the Key Management tab.
        It retrieves the keys from the selected pendrive and displays them in the UI.
        """
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = Logic.make_key_location(watch_folder, pendrive_name)
        keys = Logic.list_keys(location)
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
            key_export_button = QPushButton("Export Public Key")
            key_export_button.released.connect(lambda key=key: self.export_public_key(key))
            key_box.addWidget(key_label)
            key_box.addStretch()
            key_box.addWidget(key_export_button)
            key_box.addWidget(key_check_pass_button)
            key_box.addWidget(key_delete_button)
            self.keys_layout.addWidget(key_container)

    def __init__(self):
        """
        Initializes the KeygenWindow class.
        It sets up the layout, widgets, and connections for the key generation and management.
        """
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
        self.pendrive_selection_changed()
        self.password_updated()
        self.name_updated()
        self.switch_custom_input()
        self.update_button()