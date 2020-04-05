# set password for file

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


def hash_password(password):
    # hash password for storing
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 10000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def passwordquery():
    # ask for password to encode in file
    while True:
        passInput1 = getpass("Please enter your password: ")
        passInput2 = getpass("Please confirm your password: ")
        if passInput1 == passInput2:
            password = passInput1
            return password
        else:
            print("Passwords do not match, please try again.")


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


def encryption_key(password, salty):
    password = password.encode()
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


def change_keyword(password, key):
    key = encryption_key(password, saltyretrieve())
    encrypt_database(key)
    exit()


os.system('cls')
print("""
This script is used to setup your password manager.
Enter the password you would like to use as keyword.
The keyword is used to login, and encrypt/decrypt the database.
The default is that your masterpassword and keyword are the same.
If you want to be able to let people access your passwords but not edit them you can 
change the keyword. Your keyword can only be changed using your masterpassword.""")
password = passwordquery()
f = open('mPassword.txt', 'w')
f.write(str(hash_password(password)))
f.close()
print("Password should be saved succesfully.")
time.sleep(3)
os.system('cls')
createsalt()
salty = saltyretrieve()
key = encryption_key(password, salty)
f = open('pwddatabase.txt', 'w')
f.write("Passwords will be saved in the format: \n" + "Username : Passwords \n")
f.close()
encrypt_database(key)
print("Creating encryption key...")
time.sleep(5)
print("Encryption key created!")
print("Please delete setup.py after closing.")
input("Press [enter] to close setup...")
