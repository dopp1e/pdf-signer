from PyQt6.QtWidgets import QApplication
from keygen.keygenwindow import KeygenWindow
import sys

def main():
    app = QApplication(sys.argv)
    w = KeygenWindow()
    w.show()
    sys.exit(app.exec())

main()