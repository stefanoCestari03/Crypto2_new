# exercise 
# import chiper modules:
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes

# exaple of graphic
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk


# import of other modules 
#import lec2
import sys 
import getpass
import os


# class of exceptions
class EncryptingError(Exception): 
    '''Error, problems with encryption'''
class DecryptingError(Exception): 
    '''Error, problems with decription'''
class AutenticationError(Exception):
    '''Error, Autentication file failed! '''
class ReadingFileError(Exception):
    '''Error, during read of the file'''
class WritingFileError(Exception):
    '''Error, during read of the file'''
class KeyGenerationError(Exception):
    '''Error during generation of the key'''

# unpadding text

def unpad(data):
    length = 8 * ((len(data) + 7) // 8)
    return data[:length]

# key generating 
def unpad(data):
    length = 16 * ((len(data) + 15) // 16)
    return data[:length]

def generate_key(key_file):
    try:
        key = get_random_bytes(32)
        with open(key_file, 'wb') as file:
            file.write(key)
    except KeyGenerationError as err:
        print(err)
    return key

def generate_iv():
    return get_random_bytes(16)

def encrypt_file(in_file, out_file, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            with open(in_file, 'rb') as file:
                plain_text = file.read()
        except ReadingFileError as err:
            err += " in encrypting situation"
            print(err)
        padded_text = pad(plain_text, 16)
        cipher_text = cipher.encrypt(padded_text)
        try:
            with open(out_file + '.enc', 'wb') as file:
                file.write(iv + cipher_text)
        except WritingFileError as err:
            err += " in encrypting situation"
            print(err)
    except EncryptingError as err:
        print(err)

def decrypt_file(in_file, out_file, key):
    try:
        try:
            with open(in_file, 'rb') as file:
                iv = file.read(16)
                text_to_decrypt = file.read()
            cipher = AES.new(key, AES.MODE_CBC, iv)
        except ReadingFileError as err:
            err += " in encrypting situation"
            print(err)
        cipher_text = cipher.decrypt(text_to_decrypt)
        plain_text = unpad(cipher_text)
        try:
            with open(out_file + '.dec', 'wb') as file:
                file.write(plain_text)
        except WritingFileError as err:
            err += " in encrypting situation"
            print(err)
    except DecryptingError as err:
        print(err)
# main


# def main():
#     prompt = '''Welcome to  Crypto lab chose a way to Chiper:\n
#     1. Encrypt 3DES\n
#     2. Decrypt 3DES\n
#     \n\ninsert your choice: '''
#     # key initialization
#     key = ""
#     while True:
#         choice = input(prompt)
#         if choice == '1':
#             in_file = input("insert path of the file to encrypt: ")
#             out_file = input("insert path of the file in output: ")
#             key_file = input("insert path of the keyfile: ")
#             key = generate_key(key_file)
#             encrypt_file(in_file, out_file, key)
#             #encrypt_file(in_file, out_file, key_file)
#         elif choice == '2':
#             in_file = input("insert path of the file to decrypt: ")
#             out_file = input("inserte path of the file in output: ")
#             decrypt_file(in_file, out_file, key)
#             #decrypt_file(in_file, out_file, key_file)
#         else:
#             sys.exit()
        
# if __name__ == "__main__":
#     main()





class CryptoApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Crypto Lab")

        self.master.geometry("600x400")
        
        self.key = ""

        self.create_widgets()
        

    def create_widgets(self):
        # self.label = tk.Label(self.master, text="Welcome to Crypto Lab")
        # self.label.pack(pady=10)

        # self.encrypt_button = tk.Button(self.master, text="Encrypt ", command=self.encrypt)
        # self.encrypt_button.pack()

        # self.decrypt_button = tk.Button(self.master, text="Decrypt ", command=self.decrypt)
        # self.decrypt_button.pack()
        style = ttk.Style()
        style.configure('TButton', padding=5, font=('Helvetica', 12))

        self.label = tk.Label(self.master, text="Welcome to Crypto lab chose what to do:", font=('Helvetica', 16))
        self.label.pack(pady=10)

        self.encrypt_button = ttk.Button(self.master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = ttk.Button(self.master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

    def encrypt(self):
        in_file = filedialog.askopenfilename(title="SELECT FILE TO ENCRYPT")
        out_file = filedialog.asksaveasfilename(title="TYPE THE NAME OF THE (enc) FILE AND CLICK SAVE")
        key_file = filedialog.askopenfilename(title="SELECT FILE WERE WE ARE GOING TO GENERATE KEY (key.txt)")
        self.key = generate_key(key_file)
        encrypt_file(in_file, out_file, self.key, generate_iv())

    def decrypt(self):
        if not self.key:
            print("Please encrypt a file first to obtain the key.")
            return

        in_file = filedialog.askopenfilename(title="SELECT FILE TO DECRYPT")
        out_file = filedialog.asksaveasfilename(title="TYPE THE NAME OF THE (dec) FILE AND CLICK SAVE")
        decrypt_file(in_file, out_file, self.key)


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
