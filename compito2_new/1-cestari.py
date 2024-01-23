# exercise 
# import chiper modules:
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes


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
def generate_key(key_file):
    try:
        key =get_random_bytes(16)
        with open(key_file, 'wb') as file:
                file.write(key)
    except KeyGenerationError as err:
        print(err)
        
    return key
# encrypt func
def encrypt_file(in_file,out_file,key):
    try:
        iv = get_random_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        try:
            with open(in_file, 'rb') as file:
                iv = file.read(8)
                plain_text = file.read()
        except ReadingFileError as err:
            err += " in encrypting situation"
            print(err)
        # padding data
        padded_text = pad(plain_text, 8)
        cipher_text = cipher.encrypt(padded_text)
        try:
            with open(out_file + '.enc', 'wb') as file:
                file.write(iv + cipher_text)
        except WritingFileError as err:
            err += " in encrypting situation"
            print(err)
    except EncryptingError as err:
        print(err)

def decrypt_file(in_file,out_file,key):
    try:
        iv = get_random_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        try:
            with open(in_file, 'rb') as file:
                iv = file.read(8)
                text_to_decrypt = file.read()
        except ReadingFileError as err:
            err += " in encrypting situation"
            print(err)
        # padding data
        cipher_text = cipher.decrypt(text_to_decrypt)
        # unpadding text at least 
        plain_text = unpad(cipher_text)
        try:
            with open(out_file + '.dec', 'wb') as file:
                file.write(iv + plain_text)
        except WritingFileError as err:
            err += " in encrypting situation"
            print(err)
    except EncryptingError as err:
        print(err)
# main


def main():
    prompt = '''Welcome to  Crypto lab chose a way to Chiper:\n
    1. Encrypt 3DES\n
    2. Decrypt 3DES\n
    \n\ninsert your choice: '''
    while True:
        key = ""
        choice = input(prompt)
        if choice == '1':
            in_file = input("insert path of the file to encrypt: ")
            out_file = input("insert path of the file in output: ")
            key_file = input("insert path of the keyfile: ")
            key = generate_key(key_file)
            encrypt_file(in_file, out_file, key)
        elif choice == '2':
            in_file = input("insert path of the file to decrypt: ")
            out_file = input("inserte path of the file in output: ")
            decrypt_file(in_file, out_file, key)
        else:
            sys.exit()
        
if __name__ == "__main__":
    main()