# Passwordmanager

import os
import time
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import base64



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

    return decrypted_password_database.decode()


def save_database_encrypted(database_content: str, key: str):
    password_database_file = open('pwddatabase.txt', 'wb')
    password_database_file.write(database_content.encode())
    password_database_file.close()
    encrypt_database_file(key)


def setup():
    print('Starting the setup...')
    print('Enter the password you would like to use. ')
    print('This password will be used to login and encrypt/decrypt the database. ')
    global master_password
    master_password = get_master_password_from_user()
    salt_file = open('salt.txt', 'wb')
    salt_file.write(create_salt())
    salt_file.close()
    password_database_file = open('pwddatabase.txt', 'w')
    password_database_file.write("Passwords will be saved in the format: \n" + "Username : Passwords \n")
    password_database_file.close()
    encrypt_database_file(create_encryption_key(master_password, get_user_salt()))
    input('Setup complete \nPress enter to continue')
    clear_screen() 


def authenticate_user(failed = False):
    if failed:
        print('The entered password is incorrect, try again please')

    provided_password = getpass("Please enter your masterpassword: ")
    database_decrypted = None
    try:
        database_decrypted = get_decrypted_database(create_encryption_key(provided_password, get_user_salt()))
        global master_password
        master_password = provided_password
    except InvalidToken:
        authenticate_user(True)


def save_password():
    key = create_encryption_key(master_password, get_user_salt())
    database = get_decrypted_database(key)
    username = input("Input username: ")
    while True: 
        password = getpass("Enter password: ")
        password_check = getpass("Please confirm password")
        if password == password_check:
            database += f'{username} : {pasword}\n'
            save_database_encrypted(database, key)
            break
        else: 
            print("Passwords dit not match, please try again.")

def view_passwords():
    database = get_decrypted_database(create_encryption_key(master_password, get_user_salt()))
    print(database)
    print("Press a key to continue...")
    input()


def change_master_password():
    new_master_password = getpass('Please enter your new password: ')
    database = get_decrypted_database(create_encryption_key(master_password, get_user_salt()))
    new_salt = create_salt()
    salt_file = open('salt.txt', 'wb')
    salt_file.write(new_salt)
    salt_file.close()
    save_database_encrypted(database, create_encryption_key(new_master_password, new_salt))
    print('The password has been changed!')
    time.sleep(1)


def main():
    clear_screen()
    if os.path.exists('pwddatabase.txt') == False or os.path.exists('salt.txt') == False:
        # At least one of the important files is missing so start the setup mode
        setup()

    # Start the passwordmanager, or the setup ran or everything was already set-up
    print("Welcome to my password manager.")
    # User should authenticate here
    authenticate_user()
    while True:
        print("Please choose what you want to do.")
        print("[1] View passwords")
        print("[2] Add password")
        print("[3] Change masterpassword")
        print("[x] Exit")
        menu_choice = input("Choice: ")
        if menu_choice == '1':
            clear_screen()
            view_passwords()
            clear_screen()
        elif menu_choice == '2':
            clear_screen()
            save_password()
            clear_screen()
        elif menu_choice == '3':
            clear_screen()
            change_master_password()
            clear_screen()
        elif menu_choice == 'x':
            exit()


if __name__ == '__main__':
    main()
