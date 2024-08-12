import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox, QVBoxLayout, QComboBox
from PyQt5.QtCore import Qt
from Crypto import Random
from Crypto.Cipher import AES
import random
import string
key = b'32BYTESECRETKEYSTRINGWITHMOREBYTES'


class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if fname != 'script.py' and fname != 'password.txt.enc':
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()
        self.key = None
        self.enc = None

    def initUI(self):
        self.setWindowTitle('AES Encryption and Decryption Tool')
        layout = QVBoxLayout()

        # Password input
        self.passwordLabel = QLabel('Enter password:')
        self.passwordInput = QLineEdit()
        self.passwordInput.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.passwordLabel)
        layout.addWidget(self.passwordInput)

        # Dropdown for encryption/decryption choice
        self.choiceLabel = QLabel('Choose an option:')
        self.choiceBox = QComboBox()
        self.choiceBox.addItems(['Encrypt a file', 'Decrypt a file', 'Encrypt all files', 'Decrypt all files'])
        layout.addWidget(self.choiceLabel)
        layout.addWidget(self.choiceBox)

        # Button to proceed
        self.proceedButton = QPushButton('Proceed')
        self.proceedButton.clicked.connect(self.proceed)
        layout.addWidget(self.proceedButton)

        # Set layout and window properties
        self.setLayout(layout)
        self.setGeometry(300, 300, 350, 200)
        self.show()

    def proceed(self):
        password = self.passwordInput.text()
        if not password:
            QMessageBox.warning(self, 'Error', 'Please enter a password!')
            return

        self.key = password.encode('utf-8')
        self.enc = Encryptor(self.key)

        choice = self.choiceBox.currentText()
        if choice == 'Encrypt a file':
            self.encrypt_file()
        elif choice == 'Decrypt a file':
            self.decrypt_file()
        elif choice == 'Encrypt all files':
            self.enc.encrypt_all_files()
            QMessageBox.information(self, 'Success', 'All files encrypted successfully!')
        elif choice == 'Decrypt all files':
            self.enc.decrypt_all_files()
            QMessageBox.information(self, 'Success', 'All files decrypted successfully!')

    def encrypt_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Select file to encrypt')
        if file_name:
            self.enc.encrypt_file(file_name)
            QMessageBox.information(self, 'Success', 'File encrypted successfully!')

    def decrypt_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Select file to decrypt')
        if file_name:
            self.enc.decrypt_file(file_name)
            QMessageBox.information(self, 'Success', 'File decrypted successfully!')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWin = MainWindow()
    sys.exit(app.exec_())
