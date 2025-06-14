"""
This module defines a PasswordInput class that creates a dialog for the user to input a password.
It inherits from QDialog and contains a label, a password input field, and buttons for testing or canceling the input.
It also handles key press events for Enter and Escape keys.
"""
from PyQt6.QtWidgets import QDialog, QLabel, QLineEdit, QDialogButtonBox, QHBoxLayout, QVBoxLayout
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
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).released.connect(lambda: self.done(1))
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancel")
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).released.connect(lambda: self.done(0))

        self.inner_box = QVBoxLayout()
        self.inner_box.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.inner_box.addWidget(self.label)
        self.inner_box.addWidget(self.password_edit)
        self.inner_box.addWidget(self.button_box)

        self.hbox = QVBoxLayout()
        self.hbox.addStretch(1)
        self.hbox.addLayout(self.inner_box, 5)
        self.hbox.addStretch(1)

        self.vbox = QHBoxLayout()
        self.vbox.addStretch(1)
        self.vbox.addLayout(self.hbox, 5)
        self.vbox.addStretch(1)

        self.setLayout(self.vbox)

    ## @var label
    # The label for the password input field.
    # @var password_edit
    # The QLineEdit widget for entering the password.
    # @var button_box
    # The QDialogButtonBox containing OK and Cancel buttons.
    # @var inner_box
    # The inner vertical layout for the label, password input field, and button box.
    # @var hbox
    # The main vertical layout for the dialog.
    # @var vbox
    # The main horizontal layout for the dialog.