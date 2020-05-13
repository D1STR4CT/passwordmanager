#!/usr/bin/env python3

import hashlib
import binascii
import os
import time
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64


# pwddatabase.txt
# salt.txt

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_master_password_from_user():
    while True:
        pass1 = getpass('Please enter your password: ')
        pass2 = getpass('Please confirm your password: ')
        if pass1 == pass2:
            return pass1
        else:
            print('The passwords didn\'t match, try again please. ')

def create_salt():
    return os.urandom(16)

def get_user_salt():
    f = open('salt.txt', 'rb')
    salt = f.read()
    f.close()
    return salt

def create_encryption_key(password: str, salt: str):
    password = password.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_database_file(key: str):
    password_database_file = open('pwddatabase.txt', 'rb')
    password_database = password_database_file.read()
    password_database_file.close()

    fernet = Fernet(key)
    encrypted_password_database = fernet.encrypt(password_database)

    password_database_file = open('pwddatabase.txt', 'wb')
    password_database_file.write(encrypted_password_database)
    password_database_file.close()

def get_decrypted_database(key: str):
    password_database_file = open('pwddatabase.txt', 'rb')
    password_database = password_database_file.read()
    password_database_file.close()

    fernet = Fernet(key)
    decrypted_password_database = fernet.decrypt(password_database)

    return decrypted_password_database

def save_database_encrypted(database_content: str, key: str):
    password_database_file = open('pwddatabase.txt', 'wb')
    password_database_file.write(database_content)
    password_database_file.close()
    encrypt_database_file(key)

def setup():
    print('Starting the setup...')
    print('Enter the password you would like to use. ')
    print('This password will be used to login and encrypt/decrypt the database. ')
    global master_password
    master_password = get_master_password_from_user()
    print('master_password: {}'.format(master_password))
    salt_file = open('salt.txt', 'wb')
    salt_file.write(create_salt())
    salt_file.close()
    password_database_file = open('pwddatabase.txt', 'w')
    password_database_file.write("Passwords will be saved in the format: \n" + "Username : Passwords \n")
    password_database_file.close()
    encrypt_database_file(create_encryption_key(master_password, get_user_salt()))

def main():
    clear_screen()
    if os.path.exists('pwddatabase.txt') == False or os.path.exists('salt.txt') == False:
        # At least one of the important files is missing so start the setup mode
        setup()

    # Start the passwordmanager, or the setup ran or everything was already set-up
    while True:
        print("Welcome to my password manager.")
        # User should authenticate here
        provided_password = getpass("Please enter your masterpassword: ")
        print("Please choose what you want to do.")
        print("[1] View passwords")
        print("[2] Add password")
        print("[3] Change masterpassword")
        print("[x] Exit")
        menu_choice = input("Choice: ")
        if menu_choice == '1':
            clear_screen()
            view_passwords()
        elif menu_choice == '2':
            clear_screen()
            save_password()
        elif menu_choice == '3':
            clear_screen()
            change_master_password()
        elif menu_choice == 'x':
            exit()

if __name__ == '__main__':
    main()
