# Password manager

import os
import time
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import base64
import random
import typing
import math


def generate_password(length=10, uppercase_len=2, special_len=2, numbers=2):
    # Function to generate a random password using strings of characters and a random number generator
    lower = 'abcdefghijklmnopqrstuvwxyz'
    upper = lower.upper()
    special_chars = '!@#$%^&*()_+-=~/?\\[]{}'
    generated_password = ''

    # Generates i random capital letter where i is amount specified for the password
    for _ in range(0, uppercase_len):
        generated_password += upper[random.randint(0, len(upper) - 1)]

    # Generates i random special characters special-chars where i is the amount specified for the password
    for _ in range(0, special_len):
        generated_password += special_chars[random.randint(0, len(special_chars) - 1)]

    # Generates i random numbers where i is the amount specified for the password
    for _ in range(0, numbers):
        generated_password += random.randint(0,9)

    # Generates random letter for the remainder of the password
    for _ in range(0, length - len(generated_password)):
        generated_password += lower[random.randint(0, len(lower) - 1)]

    # Shuffle the password so it is randomised and return it
    pwd = list(generated_password)
    random.shuffle(pwd)
    return ''.join(pwd)


def clear_screen(): # Checks what operation system command should be used when clearing the screen
    os.system("cls" if os.name == "nt" else "clear")


# Get masterpassword from user, confirm it and then pass the masterpassword on
def get_master_password_from_user():
    while True:
        pass1 = getpass("Please enter your password: ")
        pass2 = getpass("Please confirm your password: ")
        if pass1 == pass2:
            return pass1
        else:
            print("The passwords didn\'t match, try again please. ")


# Create a random salt used to hash the password
def create_salt():
    return os.urandom(16)


# Get the user salt from file and return it
def get_user_salt():
    f = open("salt.txt", "rb")
    salt = f.read()
    f.close()
    return salt


# Create an encryption key to encrypt/decrypt using the password and salt
def create_encryption_key(password: str, salt: str):
    password = password.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password))


# Encrypt database using the encryption key
def encrypt_database_file(key: str):
    password_database_file = open("pwddatabase.txt", "rb")
    password_database = password_database_file.read()
    password_database_file.close()

    fernet = Fernet(key)
    encrypted_password_database = fernet.encrypt(password_database)

    password_database_file = open("pwddatabase.txt", "wb")
    password_database_file.write(encrypted_password_database)
    password_database_file.close()


# Fetch database and decrypt it using the encryption key and return content
def get_decrypted_database(key: str):
    password_database_file = open("pwddatabase.txt", "rb")
    password_database = password_database_file.read()
    password_database_file.close()

    fernet = Fernet(key)
    decrypted_password_database = fernet.decrypt(password_database)

    return decrypted_password_database.decode()


# Encrypt the database content with the encryption key
def save_database_encrypted(database_content: str, key: str):
    password_database_file = open("pwddatabase.txt", "wb")
    password_database_file.write(database_content.encode())
    password_database_file.close()
    encrypt_database_file(key)


# Create the files necessary for the program to function
def setup():
    print("Starting the setup...")
    print("Enter the password you would like to use. ")
    print("This password will be used to login and encrypt/decrypt the database. ")
    global master_password
    master_password = get_master_password_from_user()
    salt_file = open("salt.txt", "wb")
    salt_file.write(create_salt())
    salt_file.close()
    password_database_file = open("pwddatabase.txt", "w")
    password_database_file.write("MyPasswordVault: \n" + "Domain : Username : Passwords \n")
    password_database_file.close()
    encrypt_database_file(create_encryption_key(master_password, get_user_salt()))
    input("Setup complete \nPress enter to continue")
    clear_screen()


# Authenticate user with masterpassword and if authenticated safe password in variable
def authenticate_user(failed=False):
    if failed:
        print("The entered password is incorrect, try again please")

    provided_password = getpass("Please enter your masterpassword: ")
    database_decrypted = None
    try:
        database_decrypted = get_decrypted_database(create_encryption_key(provided_password, get_user_salt()))
        global master_password
        master_password = provided_password
    except InvalidToken:
        authenticate_user(True)


# Create credentials and save to database
def save_password():
    key = create_encryption_key(master_password, get_user_salt())
    database = get_decrypted_database(key)
    domain = input("What are these credentials for?: ")
    username = input("Input username: ")
    print("\nEnter \"random\" for random password. \nEnter \"random edit\" to edit the settings.")
    password_input = input("Enter password: ")
    if password_input == "random":
        password = generate_password()
        print(f"Generated password = {password}")
        input("\nPress enter key to continue...")
    elif password_input == "random edit":
        length = input("Password length: ")
        uppercase_len: typing.Union[int, str] = input("Amount of uppercase characters: ")
        special_len: typing.Union[int, str] = input("Amount of special characters: ")
        if isinstance(uppercase_len, str):
            uppercase_len = int(round(int(length)/5))
        if isinstance(special_len, str):
            special_len = int(round(int(length)/5))
        password = generate_password(int(length), int(uppercase_len), int(special_len), )
        print(f"Generated password = {password}")
        input("\nPress enter key to continue...")
    else:
        password = password_input
    database += f"{domain} : {username} : {password}\n"
    save_database_encrypted(database, key)


# Print the decrypted contents of the database
def view_passwords():
    database = get_decrypted_database(create_encryption_key(master_password, get_user_salt()))
    print(database)
    print("Press enter key to continue...")
    input()


# Get the new masterpassword from user, decrypt with old one, encrypt with new one and restart
def change_master_password():
    print("Please note that the program will close after changing the password. You have to manualy reopen it.\n")
    while True:
        new_master_password = getpass("Please enter your new password: ")
        new_master_password_check = getpass("Please confirm your password: ")
        # Check if passwords match and then sets new password
        if new_master_password == new_master_password_check:
            database = get_decrypted_database(create_encryption_key(master_password, get_user_salt()))
            new_salt = create_salt()
            salt_file = open("salt.txt", "wb")
            salt_file.write(new_salt)
            salt_file.close()
            save_database_encrypted(database, create_encryption_key(new_master_password, new_salt))
            print("The password has been changed!")
            time.sleep(1)
            exit() # Because the masterpassword is stored as a value and can not be changed the program will need to be restarted or it will throw an error when the database is decrypted.
            break
        else:
            print("Password don\'t match, please try again.")


# Check for all necessary files and run either the setup or the program
def main():
    clear_screen()
    if os.path.exists("pwddatabase.txt") == False or os.path.exists("salt.txt") == False:
        # At least one of the important files is missing so start the setup mode
        setup()

    # Start the password manager, or the setup ran or everything was already set-up
    print("Welcome to my password manager.")
    # User should authenticate here
    authenticate_user()
    while True:
        clear_screen()
        print("Welcome to the menu.")
        print("Please choose what you want to do.")
        print("[1] View passwords")
        print("[2] Add password")
        print("[3] Change masterpassword")
        print("[x] Exit")
        menu_choice = input("Choice: ")
        if menu_choice == "1":
            clear_screen()
            view_passwords()
            clear_screen()
        elif menu_choice == "2":
            clear_screen()
            save_password()
            clear_screen()
        elif menu_choice == "3":
            clear_screen()
            change_master_password()
            clear_screen()
        elif menu_choice == "x":
            clear_screen()
            exit()


if __name__ == "__main__":
    main()
