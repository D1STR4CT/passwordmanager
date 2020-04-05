import hashlib
import binascii
import os
import time
from getpass import getpass
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64


def createsalt():
    salty = os.urandom(16)
    f = open('salt.txt', 'wb')
    f.write(salty)
    f.close()


def saltyretrieve():
    f = open('salt.txt', 'rb')
    salty = f.read()
    f.close()
    return salty


def encryption_key(providedPWD, salty):
    password = providedPWD.encode()
    salt = salty
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def change_keyword():
    while True:
        providedPWD1 = getpass("Enter new keyword: ")
        providedPWD2 = getpass("Confirm password: ")
        if providedPWD1 == providedPWD2:
            providedPWD = providedPWD1
        else:
            print("Keywords don\'t match, please try again")
    createsalt()
    salty = saltyretrieve()
    key = encryption_key(providedPWD, salty)
    encrypt_database(key)
    exit()


def encrypt_database(key):
    input_file = 'pwddatabase.txt'
    output_file = 'pwddatabase.txt'

    f = open(input_file, 'rb')
    data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    f.close()

    f = open(output_file, 'wb')
    f.write(encrypted)

    f.close()


def decrypt_database(key):
    input_file = 'pwddatabase.txt'
    output_file = 'pwddatabase.txt'

    f = open(input_file, 'rb')
    data = f.read()

    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)

    f.close()

    f = open(output_file, 'wb')
    f.write(decrypted)

    f.close()


def save_password():
    f = open('pwddatabase.txt', 'a')
    username = input("Input username: ")
    new_password = getpass("Enter password: ")
    enter_string = username + ' | ' + new_password + ' \n'
    f.write(enter_string)
    f.close()


def view_passwords():
    f = open('pwddatabase.txt', 'r')
    print(f.read())
    f.close()
    print("Press [x] and hit enter to close")
    input()
    os.system('cls')


def verify_password(stored_Password, provided_password):
    # verify a stored password against one provided by user
    salt = stored_Password[:64]
    stored_Password = stored_Password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  10000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_Password


def Passwordquery():
    # prompt user to imput password
    provided_password = getpass("Please enter your password: ")
    global password
    password = provided_password
    return provided_password


def new_Passwordquery():
    # ask for password to encode in file
    while True:
        passInput1 = getpass("Please enter your new password: ")
        passInput2 = getpass("Please confirm your new password: ")
        if passInput1 == passInput2:
            new_Password = passInput1
            os.system('cls')
            return new_Password
        else:
            print("Passwords do not match, please try again.")


def check_Password():
    for i in range(1, 3):
        f = open('mPassword.txt', 'r')
        if verify_password(f.readline(), Passwordquery()):
            f.close()
            os.system('cls')
            return True
        else:
            print("Wrong password, please try again")
            i += 1


def hash_new_Password(new_Password):
    # hash password for storing
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', new_Password.encode('utf-8'),
                                  salt, 10000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def change_Password():
    # print("Only change your masterpassword if you are sure you can remember it.")
    if check_Password():
        f = open('mPassword.txt', 'w')
        new_Password = new_Passwordquery()
        f.write(str(hash_new_Password(new_Password)))
        f.close()
        print("Password saved succesfully!")
        print("Returning to menu.")
        time.sleep(1)
        os.system('cls')


def mainMenu():
    while True:
        print("Welcome to my password manager.")
        print("Please choose what you want to do.")
        print("[1] View passwords")
        print("[2] Add password")
        print("[3] Change masterpassword")
        print("[4] Change keypassword")
        print("[x] Exit")
        menu_choice = input("Choice: ")
        if menu_choice == '1':
            os.system('cls')
            view_passwords()
        elif menu_choice == '2':
            os.system('cls')
            save_password()
        elif menu_choice == '3':
            os.system('cls')
            if check_Password():
                change_Password()
            else:
                print("An error occured, please try again later.")
        elif menu_choice == '4':
            if check_Password():
                change_keyword()
            else:
                print("An error occurred, please try again later.")
        elif menu_choice == 'x':
            encrypt_database(key)
            exit()


os.system('cls')
print(
    '''WARNING: This password manager works differently than normal password managers.
    -You have two passwords:
        Your masterpassword and your keypassword.
    -Your keypassword is used when logging to acces your saved passwords.
    -Your master password is set sepperatly and can be used to change your keypassword.
    Note that if you change your keypassword the programm will shut down and you need to reopen it.
    ''')
salty = saltyretrieve()
providedPWD = getpass("Please enter key to decrypt database: ")
key = encryption_key(providedPWD, salty)
decrypt_database(key)
mainMenu()
