from PyQt6.QtWidgets import QApplication
from signer.signerwindow import SignerWindow
import sys

def main():
    app = QApplication(sys.argv)
    w = SignerWindow()
    w.show()
    sys.exit(app.exec())

main()