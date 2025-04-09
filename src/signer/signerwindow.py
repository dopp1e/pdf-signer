from PyQt6.QtWidgets import QFileDialog, QPushButton, QWidget, QLineEdit, QVBoxLayout, QComboBox, QLabel, QHBoxLayout, QRadioButton
from PyQt6 import QtCore

from common import genericwindow
from common.main import Logic
from common.password_input import PasswordInput

class SignerWindow(genericwindow.GenericWindow):
    """
    A window for signing and verifying the signatures of PDF files.
    Based on the GenericWindow class.
    """
    def select_signage_pdf_file(self) -> None:
        """
        Opens a file dialog to select a PDF file to sign.
        """
        filename = QFileDialog.getOpenFileName(None, "Choose a PDF file", QtCore.QDir.homePath(), "PDF Files (*.pdf)")
        if (filename[0] == ""):
            return
        
        self.signage_file_picked_path.setText(filename[0])

    def select_verification_key(self) -> None:
        """
        Opens a file dialog to select a public key file for verification.
        """
        filename = QFileDialog.getOpenFileName(None, "Choose a Key File", QtCore.QDir.homePath())
        if (filename[0] == ""):
            return
        
        self.verification_public_key_path.setText(filename[0])
        self.verification_inputs_updated()

    def select_verification_pdf_file(self) -> None:
        """
        Opens a file dialog to select a PDF file to verify.
        """
        filename = QFileDialog.getOpenFileName(None, "Choose a PDF file", QtCore.QDir.homePath(), "PDF Files (*.pdf)")
        if (filename[0] == ""):
            return
        
        self.verification_pdf_file_path.setText(filename[0])
        self.verification_inputs_updated()

    def sign_pdf_file(self) -> None:
        """
        Signs the selected PDF file with the selected key,
        prompting the user for a password.
        If the signing is successful, the signed PDF is saved
        in the `self.signed_pdf` variable.
        """
        self.signage_save_button.setEnabled(False)
        pdf_file_path = self.signage_file_picked_path.text()
        self.signage_status_label.setText("Awaiting password input...")
        input = PasswordInput()
        result = input.exec()
        if result == 0:
            return
        
        password = input.getPassword()
        self.signage_status_label.setText("Signing the file...")
        self.reload_window()
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = Logic.make_key_location(watch_folder, pendrive_name)
        key = self.key_picker.currentText()

        self.reload_window()
        result = Logic.make_signed_pdf(pdf_file_path, password, location, key)
        if not result:
            self.signage_status_label.setText("Signing failed - please ensure you used the correct password.")
            return
        self.signed_pdf = result
        file = Logic.filename(pdf_file_path)
        self.signage_status_label.setText(f"'{file}' is signed and ready to be saved.")
        self.signage_save_button.setEnabled(True)

    def save_signed_pdf_file(self) -> None:
        """
        Opens a file dialog to select a location to save the signed PDF file.
        """
        if (self.signed_pdf == None):
            self.show_message("You need to have a PDF file ready to be saved!")
            return
        
        file_path = QFileDialog.getSaveFileName(None, "Choose where to save your signed PDF", QtCore.QDir.homePath())
        if Logic.save_file(file_path[0], self.signed_pdf):
            self.show_message("File saccessfully saved!")
        else:
            self.show_message("Something went wrong, please make sure there is no such file, that the path exists, and try again.")

    def pendrive_selection_changed(self) -> None:
        """
        Called when the pendrive selection changes.
        It updates the key list and enables/disables the key picker.
        """
        self.update_key_list()
        self.key_picker.setEnabled(self.is_pendrive_selected())

    def update_key_list(self) -> None:
        """
        Updates the list of keys available on the selected pendrive.
        It clears the current key picker and adds the new keys.
        """
        watch_folder = self.get_watch_folder()
        pendrive_name = self.get_pendrive_name()
        location = Logic.make_key_location(watch_folder, pendrive_name)
        keys = Logic.list_keys(location)
        self.key_picker.clear()
        self.key_picker.addItems(keys)
        self.verification_key_pendrive_picker.clear()
        self.verification_key_pendrive_picker.addItems(keys)

    def signage_inputs_updated(self) -> None:
        """
        Called when the inputs for signing a PDF are updated.
        It enables/disables the signage confirm button based on the inputs.
        """
        has_path = self.signage_file_picked_path.text() != ""
        has_key = self.key_picker.currentText() != ""
        self.signage_confirm_button.setEnabled(has_path and has_key)

    def verification_radio_toggled(self) -> None:
        """
        Called when the radio buttons for verification are toggled.
        It enables/disables the public key and pendrive key inputs based on the selection.
        """
        if (self.verification_public_key_radio_file.isChecked()):
            self.verification_public_key_label.setEnabled(True)
            self.verification_public_key_pick_button.setEnabled(True)
            self.verification_key_pendrive_label.setEnabled(False)
            self.verification_key_pendrive_picker.setEnabled(False)
        elif (self.verification_public_key_radio_pendrive.isChecked()):
            self.verification_public_key_label.setEnabled(False)
            self.verification_public_key_pick_button.setEnabled(False)
            self.verification_key_pendrive_label.setEnabled(True)
            self.verification_key_pendrive_picker.setEnabled(True)
        self.verification_inputs_updated()

    def verification_inputs_updated(self) -> None:
        """
        Called when the inputs for verifying a PDF are updated.
        It enables/disables the verification submit button based on the inputs.
        """
        has_key = False
        if (self.verification_public_key_radio_file.isChecked()):
            has_key = self.verification_public_key_path.text() != ""
        if (self.verification_public_key_radio_pendrive.isChecked()):
            has_key = self.verification_key_pendrive_picker.currentText() != ""
        has_path = self.verification_pdf_file_path.text() != ""
        self.verification_submit_button.setEnabled(has_path and has_key)

    def verify_pdf_signature(self) -> None:
        """
        Verifies the signature of the selected PDF file with the selected key.
        It shows a message indicating whether the signature is valid or not.
        """
        pdf_to_check = self.verification_pdf_file_path.text()
        if pdf_to_check == "":
            self.show_message("You need to select a PDF file to verify!")
            return
        
        if (self.verification_public_key_radio_file.isChecked()):
            public_key_path = self.verification_public_key_path.text()
        
        result = Logic.verify_pdf(pdf_to_check, public_key_path)
        if result == 0:
            self.show_message("The PDF signature is valid.")
        elif result == 1:
            self.show_message("No signature matched the chosen key.")
        elif result == 2:
            self.show_message("The public key could not be loaded - are you sure it's a valid key?")
        elif result == 3:
            self.show_message("The PDF file has no signatures to check against.")
        elif result == 4:
            self.show_message("An unknown error occured, please try again.")

    def __init__(self):
        """
        Initializes the SignerWindow.
        It sets up the UI components for signing and verifying PDF files.
        """
        super().__init__()
        self.lower_layout.show()

        self.signed_pdf = None
        self.signage = QWidget()
        self.verification = QWidget()
        self.signage_layout = QVBoxLayout(self.signage)
        self.verification_layout = QVBoxLayout(self.verification)
        
        self.lower_layout.tabBar().setExpanding(True)
        self.lower_layout.tabBar().setDocumentMode(True)
        self.lower_layout.addTab(self.signage, "Sign a PDF")
        self.lower_layout.addTab(self.verification, "Verify a Signature")

        # Signage layout

        self.key_picker_label = QLabel("Pick the key to use")
        self.key_picker = QComboBox()
        self.key_picker.setEnabled(False)
        self.key_picker.currentIndexChanged.connect(self.signage_inputs_updated)

        self.signage_file_picked_label = QLabel("Pick the file to sign")
        self.signage_file_picked_box = QHBoxLayout()
        self.signage_file_picked_path = QLineEdit()
        self.signage_file_picked_path.setEnabled(False)
        self.signage_file_picked_path.textChanged.connect(self.signage_inputs_updated)
        self.signage_file_picked_button = QPushButton()
        self.signage_file_picked_button.released.connect(self.select_signage_pdf_file)
        self.signage_file_picked_button.setText(" ... ")
        self.signage_file_picked_box.addWidget(self.signage_file_picked_path, 9)
        self.signage_file_picked_box.addSpacing(4)
        self.signage_file_picked_box.addWidget(self.signage_file_picked_button, 1)

        self.signage_confirm_button = QPushButton("Sign the PDF")
        self.signage_confirm_button.setEnabled(False)
        self.signage_confirm_button.released.connect(self.sign_pdf_file)

        self.signage_save_button = QPushButton("Save the PDF")
        self.signage_save_button.setEnabled(False)
        self.signage_save_button.released.connect(self.save_signed_pdf_file)

        self.signage_status_label = QLabel("No PDF signed yet.")
        self.signage_status_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        self.signage_layout.addSpacing(8)
        self.signage_layout.addWidget(self.key_picker_label)
        self.signage_layout.addWidget(self.key_picker)
        self.signage_layout.addSpacing(8)
        self.signage_layout.addWidget(self.signage_file_picked_label)
        self.signage_layout.addLayout(self.signage_file_picked_box)
        self.signage_layout.addWidget(self.signage_confirm_button)
        self.signage_layout.addWidget(self.signage_save_button)
        self.signage_layout.addWidget(self.signage_status_label)
        self.signage_layout.addStretch()

        # Verification

        self.verification_key_pendrive_box = QHBoxLayout()
        self.verification_key_pendrive_label = QLabel("Pendrive Key to Verify With")
        self.verification_key_pendrive_picker = QComboBox()
        self.verification_key_pendrive_picker.currentIndexChanged.connect(self.verification_inputs_updated)
        self.verification_key_pendrive_box.addWidget(self.verification_key_pendrive_label)
        self.verification_key_pendrive_box.addWidget(self.verification_key_pendrive_picker)

        self.verification_public_key_box = QHBoxLayout()
        self.verification_public_key_label = QLabel("Public Key to Verify With")
        self.verification_public_key_path = QLineEdit()
        self.verification_public_key_path.setEnabled(False)
        self.verification_public_key_pick_button = QPushButton(" ... ")
        self.verification_public_key_pick_button.released.connect(self.select_verification_key)
        self.verification_public_key_box.addWidget(self.verification_public_key_label)
        self.verification_public_key_box.addSpacing(4)
        self.verification_public_key_box.addWidget(self.verification_public_key_path)
        self.verification_public_key_box.addSpacing(4)
        self.verification_public_key_box.addWidget(self.verification_public_key_pick_button)

        self.verification_public_key_type_choice_box = QHBoxLayout()
        self.verification_public_key_radio_pendrive = QRadioButton("Choose Public Key From Pendrive")
        self.verification_public_key_radio_file = QRadioButton("Choose Public Key From File")
        self.verification_public_key_radio_file.setChecked(True)
        self.verification_public_key_radio_file.toggled.connect(self.verification_radio_toggled)
        self.verification_public_key_radio_pendrive.toggled.connect(self.verification_radio_toggled)
        self.verification_public_key_type_choice_box.addStretch(1)
        self.verification_public_key_type_choice_box.addWidget(self.verification_public_key_radio_pendrive, 3)
        self.verification_public_key_type_choice_box.addStretch(1)
        self.verification_public_key_type_choice_box.addWidget(self.verification_public_key_radio_file, 3)
        self.verification_public_key_type_choice_box.addStretch(1)

        self.verification_public_key_outer_box = QHBoxLayout()
        self.verification_public_key_outer_box.addLayout(self.verification_key_pendrive_box, 1)
        self.verification_public_key_outer_box.addSpacing(16)
        self.verification_public_key_outer_box.addLayout(self.verification_public_key_box, 1)

        self.verification_pdf_file_label = QLabel("PDF File to Verify")
        self.verification_pdf_file_path = QLineEdit()
        self.verification_pdf_file_path.setEnabled(False)
        self.verification_pdf_file_button = QPushButton(" ... ")
        self.verification_pdf_file_button.released.connect(self.select_verification_pdf_file)
        self.verification_pdf_file_box = QHBoxLayout()
        self.verification_pdf_file_box.addWidget(self.verification_pdf_file_label)
        self.verification_pdf_file_box.addSpacing(8)
        self.verification_pdf_file_box.addWidget(self.verification_pdf_file_path)
        self.verification_pdf_file_box.addSpacing(4)
        self.verification_pdf_file_box.addWidget(self.verification_pdf_file_button)

        self.verification_submit_button = QPushButton("Verify")
        self.verification_submit_button.setEnabled(False)
        self.verification_submit_button.released.connect(self.verify_pdf_signature)

        self.verification_layout.addSpacing(8)
        self.verification_layout.addLayout(self.verification_public_key_type_choice_box)
        self.verification_layout.addLayout(self.verification_public_key_outer_box)
        self.verification_layout.addLayout(self.verification_pdf_file_box)
        self.verification_layout.addWidget(self.verification_submit_button)
        self.verification_layout.addStretch()

        # Connection set-up

        self.pendrive_selector.currentIndexChanged.connect(self.pendrive_selection_changed)
        self.pendrive_selection_changed()
        self.verification_radio_toggled()