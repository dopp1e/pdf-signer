from PyQt6.QtWidgets import QDialog, QLabel, QLineEdit, QDialogButtonBox, QGridLayout
from PyQt6 import QtCore

class PasswordInput(QDialog):
    """
    A dialog to ask the user for a password.
    """
    def getPassword(self) -> str:
        """
        Returns the password entered by the user.
        
        Returns:
            str: The password entered by the user.
        """
        return self.password_edit.text()

    def keyPressEvent(self, a0):
        """
        Overrides the keyPressEvent to handle Enter and Escape keys.
        """
        if (a0 == QtCore.Qt.Key.Key_Enter):
            return self.done(1)
        elif (a0 == QtCore.Qt.Key.Key_Escape):
            return self.done(0)
        else:
            return super().keyPressEvent(a0)

    def __init__(self):
        """
        Initializes the PasswordInput dialog.
        """
        super().__init__()
        self.label = QLabel("Enter password to check.")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.button_box = QDialogButtonBox()
        self.button_box.addButton(QDialogButtonBox.StandardButton.Ok)
        self.button_box.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setText("Test")
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).released.connect(lambda: self.done(1))
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancel")
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).released.connect(lambda: self.done(0))

        self.form_grid_layout = QGridLayout()
        self.form_grid_layout.addWidget(self.label, 0, 0, 1, 1)
        self.form_grid_layout.addWidget(self.password_edit, 1, 0, 1, 1)
        self.form_grid_layout.addWidget(self.button_box, 2, 0, 1, 1)

        self.setLayout(self.form_grid_layout)

        