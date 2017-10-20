#!/usr/bin/python3

import sqlite3 as db
import getopt
import getpass
import time
import pathlib
import sys
import pyperclip as pc
import os.path
import hashlib #sha256, pdkdf2_hmac.
import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#TODO: High importance - security! some form of encryption and user authentication is necessary.
#      Otherwise, general use can likely be improved a bit.
# Perhaps use the cryptography package (available on pip) for both the encryption of passwords and
# for the hashing of database password?
#
# Ensure master password input is at most 16 characters

#Hash master password securely, and use to verify it. Use unhashed master password as key to en/decrypt
#passwords in database. This is independent of verification so a hacked db achieves nothing but annoyance
#from the perspective of an attacker. Not exactly convinced this is perfect, but certainly something
#usable for most threats. 

#adds things and encrypts key with master password and generates specific salt for this. Retrieving a password
#gets the relevant salt and decodes successfully. Half-way-ish to a working basic program with not-awful security.
#will need to research the security side of things more to be sure this isn't a waste of time. 


#Defines a decorator to control db access - provides a cursor to use, and closes data after function.
def provide_database_cursor(function):
    def wrapper(*args, **kwargs):
        data = get_db_connection()
        cursor = data.cursor()
        return_value = function(*args, cursor, **kwargs)
        data.commit()
        data.close()
        return return_value
    return wrapper
        

def get_db_connection():
    pathvar = pathlib.Path().home()
    pathvar = pathlib.Path(pathvar/'.passman')
    if not pathvar.exists():
        pathvar.mkdir()
        init_database()
        return 
    if not os.path.isfile(str(pathvar)+'/pass.db'):
        init_database()
        return
    return db.connect(str(pathvar)+'/pass.db')


def init_database():
    pathvar = pathlib.Path().home()
    pathvar = pathlib.Path(pathvar/'.passman')
    data = db.connect(str(pathvar)+'/pass.db')

    cursor = data.cursor()
    cursor.execute("create table logins (account text, username text, password text)")

    initial_password = getpass.getpass("Enter a master password for the database (Up to 16 characters): ")
    verification = getpass.getpass("Again for verification: ")

    if initial_password != verification:
        print("Password did not match verification, aborting")
        sys.exit(2)

    #store hash of password in table for authenticating the user
    values = {}
    values['password'] = hashlib.sha256(initial_password.encode('UTF-8')).hexdigest()
    cursor.execute("create table hidden (password text)")
    cursor.execute("insert into hidden values (:password)", values)
    cursor.execute("create table salts (account text primary key, salt text)")
    data.commit()
    data.close()
    print("Database created")
    exit(0)

@provide_database_cursor
def get_salt(account, cursor):
    cursor.execute("select salt from salts where account=?", (account,))
    return cursor.fetchone()

def encrypt_password(account, master_password, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 256000,
        backend = default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('UTF-8')))
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode('UTF-8'))
    return encrypted_password, salt
    
@provide_database_cursor
def decrypt_password(account, master_password, cursor):
    cursor.execute("select password from logins where account=?", (account,))
    password = cursor.fetchone()
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = get_salt(account)[0],
        iterations = 256000,
        backend = default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('UTF-8')))
    f = Fernet(key)
    password = f.decrypt(password[0]).decode('UTF-8')
    return password


def get_password(account, master_password, user=None):
    password = decrypt_password(account, master_password)
    pc.copy(password)
    print("Password for {} now in clipboard".format(account))
    time.sleep(10)
    pc.copy("VOID")

        
@provide_database_cursor
def get_username(account, cursor):
    cursor.execute("select username from logins where account=?", (account,))
    result = cursor.fetchall()
    if len(result) == 0:
        print("No such account")
        exit(0)
    if len(result) == 1:
        pc.copy(result[0][0]) #learn more about how sqlite returns results!!
        print("Username for {} now in clipboard".format(account))
        time.sleep(10)
        pc.copy("VOID")
        return

    #if non-unique username, list options.
    for row in result:
        print(row[0])


@provide_database_cursor
def add_new_record(master_password, cursor):
    record = {}
    record['account'] = input("Account: ")
    record['username'] = input("Username: ")
    password = getpass.getpass()
    password2 = getpass.getpass('Verify password:')

    if password != password2:
        print("ERROR: Password and Validation did not match")
        return
    
    record['password'], record['salt'] = encrypt_password(record['account'], master_password, password)
    
    cursor.execute("insert into logins values (:account, :username, :password)", record)
    cursor.execute("insert into salts values (:account, :salt)", record)

    print("Database updated - Added account {}".format(record['account']))


@provide_database_cursor
def delete_record(account, cursor):
    confirmation = input("Confirm deletion of account {} (y/n): ".format(account))

    if confirmation == 'y':
        cursor.execute("delete from logins where account=?", (account,))
        cursor.execute("delete from salts where account=?", (account,))
        print("Database updated - Deleted account {}".format(account))
    else:
        print("Deletion aborted")

    
@provide_database_cursor
def list_accounts(cursor):
    result = cursor.execute("select account from logins")
    for row in result:
        print(row[0])
    

def check_args(args, n):
    if len(args) != n:
        print("ERROR: Too many args")
        usage()
        sys.exit(2)


@provide_database_cursor
def authenticate_user(cursor):
    user_pass = getpass.getpass("Enter master password: ")

    cursor.execute("select password from hidden")
    result = cursor.fetchone()

    #if hash of user input is not the same as hash in database
    if hashlib.sha256(user_pass.encode('UTF-8')).hexdigest() != result[0]:
        print("user hash = {}, db data = {}".format(hashlib.sha256(user_pass.encode('UTF-8')).hexdigest(),result[0]))
        print("Wrong password")
        sys.exit(2)

    return user_pass
    
        
@provide_database_cursor
def get_login(account, master_password, cursor):
    cursor.execute("select username from logins where account=?", (account,))
    result = cursor.fetchall()

    if len(result) == 1:
        pc.copy(result[0][0])
    else:
        print("Non-unique username for this account type!")
        sys.exit(2)

    input("Username for {} in clipboard. Press Enter for password...".format(account))

    password = decrypt_password(account, master_password)

    pc.copy(password)
    print("Password for {} in clipboard. Clipboard will expire in 10 seconds.".format(account))
    time.sleep(10)
    pc.copy("VOID")
    
    
@provide_database_cursor
def change_master_password(cursor):
    new_password = getpass.getpass("Enter new master password: ")
    verification = getpass.getpass("Enter again: ")

    if new_password != verification:
        print("Passwords do not match! Aborting")
        sys.exit(0)

    cursor.execute("update hidden set password=?", (hashlib.sha256(new_password.encode('UTF-8')).hexdigest(),))
    #after this will need to re-encrypt database with new AES key based on master password.. once the
    # encryption is in place.



def parse_args():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "l:p:u:d:",
                                   ["login=","password=","username=", "list", "delete=", "change-master"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    master_password = authenticate_user()

    if len(opts) == 0:
        check_args(args,1)
        if args[0] == "add":
            add_new_record(master_password)
            exit(0)
        else:
            get_login(args[0])
            exit(0)

    for opt, arg in opts: #really there should only be one opt!
        if opt in ("-l", "--login"):
            get_login(arg)
            print("Clipboard expired")
            exit(0)

        if opt in ("-u", "--username"):
            get_username(arg)
            print("Clipboard expired")
            exit(0)

        if opt in ("-p", "--password"):
            get_password(arg, master_password)
            print("Clipboard expired")
            exit(0)

        if opt in ("-d", "--delete"):
            delete_record(arg)
            exit(0)

        if opt in ("--list"):
            list_accounts()
            exit(0)

        if opt in ("--change-master"):
            change_master_password()
            print("Master password updated.")
            exit(0)

if __name__ == "__main__":
    parse_args()
