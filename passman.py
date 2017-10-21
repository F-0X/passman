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

#Seems like a good idea to maybe switch away from sha256 (though it *is* good) to something else so that
#weaker passwords form less of an attacking advantage (probably to pbkdf or some other slowed-hash function.)

#Defines a decorator to control db access - provides a cursor to use, and closes data after function.
def provide_database_cursor(function):
    def wrapper(*args, **kwargs):
        data = get_db_connection()
        data.row_factory = db.Row #this allows accessing data in rows as if row is a dict.
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
    return db.connect(str(pathvar)+'/pass.db', timeout=10)


def init_database():
    pathvar = pathlib.Path().home()
    pathvar = pathlib.Path(pathvar/'.passman')
    data = db.connect(str(pathvar)+'/pass.db')

    cursor = data.cursor()
    cursor.execute("create table logins (account text, username text, password text)")

    master_password = getpass.getpass("Enter a master password for the database (Ensure it is strong, 10+ characters): ")
    verification = getpass.getpass("Again for verification: ")

    if master_password != verification:
        print("Password did not match verification, aborting")
        sys.exit(2)

    #store hash of password in table for authenticating the user
    values = {}
    values['account'] = "master_password"
    values['salt'] = os.urandom(64)
    values['password'] = hashlib.pbkdf2_hmac('sha256', master_password.encode('UTF-8'),
                                             values['salt'], 256000)
    #values['password'] = hashlib.sha256(initial_password.encode('UTF-8')).hexdigest()

    cursor.execute("create table hidden (password text)")
    cursor.execute("insert into hidden values (:password)", values)

    cursor.execute("create table salts (account text primary key, salt blob)")
    cursor.execute("insert into salts values (:account, :salt)", values)

    data.commit()
    data.close()

    print("Database created")
    exit(0)

@provide_database_cursor
def get_salt(account, cursor, user=None):
    if user:
        cursor.execute("select salt from salts where account=? and username=?", (account, user,))
    else:
        cursor.execute("select salt from salts where account=?", (account,))
    row = cursor.fetchone()
    return row['salt']

def encrypt_password(master_password, password):
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
def decrypt_password(account, master_password, cursor, user=None):
    if user:
        cursor.execute("select password from logins where account=? and username=?", (account, user,))
    else:
        cursor.execute("select password from logins where account=?", (account,))
    row = cursor.fetchone()
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = get_salt(account),
        iterations = 256000,
        backend = default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('UTF-8')))
    f = Fernet(key)
    password = f.decrypt(row['password']).decode('UTF-8')
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
    row = cursor.fetchone()
    pc.copy(row['username']) #learn more about how sqlite returns results!!
    print("Username for {} now in clipboard".format(account))
    time.sleep(10)
    pc.copy("VOID")
    return


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
    
    record['password'], record['salt'] = encrypt_password(master_password, password)
    
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
    rows = cursor.execute("select account from logins")
    for row in rows:
        print(row['account'])
    

def check_args(args, n):
    if len(args) > n:
        print("ERROR: Too many args")
        sys.exit(2)
    elif len(args) < n:
        print("ERROR: Too few args")
        sys.exit(2)


@provide_database_cursor
def authenticate_user(cursor):
    user_pass = getpass.getpass("Enter master password: ")

    cursor.execute("select salt from salts where account='master_password'")
    salt = cursor.fetchone()['salt']

    cursor.execute("select password from hidden")
    hashed_master = cursor.fetchone()['password']

    #if hash of user input is not the same as hash in database
    if hashlib.pbkdf2_hmac('sha256',
                           user_pass.encode('UTF-8'),
                           salt,
                           256000) != hashed_master:
        print("Wrong password")
        sys.exit(2)
        
    #if hashlib.sha256(user_pass.encode('UTF-8')).hexdigest() != hashed_master:
    #    print("user hash = {}, db data = {}".format(hashlib.sha256(user_pass.encode('UTF-8')).hexdigest(),hashed_master))
    #    print("Wrong password")
    #    sys.exit(2)

    return user_pass
    
        
@provide_database_cursor
def get_login(account, master_password, cursor, user=None):
    cursor.execute("select username from logins where account=?", (account,))
    result = cursor.fetchall()

    if len(result) == 1:
        pc.copy(result[0]['username'])
    else:
        print("Non-unique username for this account type!")
        sys.exit(2)

    input("Username for {} in clipboard. Press Enter for password...".format(account))

    password = decrypt_password(account, master_password, user) if user else decrypt_password(account, master_password)

    pc.copy(password)
    print("Password for {} in clipboard. Clipboard will expire in 10 seconds.".format(account))
    time.sleep(10)
    pc.copy("VOID")
    
@provide_database_cursor
def update_password(account, master_password, new_password, cursor):
    print("updating password for {}".format(account))
    encrypted_password, salt = encrypt_password(master_password, new_password)
    row = {'password' : encrypted_password, 
           'account' : account,
           'salt' : salt}
    cursor.execute("update logins set password=(:password) where account=(:account)", row)
    cursor.execute("update salts set salt=(:salt) where account=(:account)", row)
    print("done")
    
    
@provide_database_cursor
def change_master_password(master_password, cursor):
    new_password = getpass.getpass("Enter new master password: ")
    verification = getpass.getpass("Enter again: ")

    if new_password != verification:
        print("Passwords do not match! Aborting")
        sys.exit(0)

    data = {'salt' : os.urandom(64),
            'new_pass_hashed' : hashlib.pbkdf2_hmac('sha256',
                                                    new_password.encode('UTF-8'),
                                                    data['salt'],
                                                    256000)}

    #update hash and salt to those for new password
    cursor.execute("update hidden set password=(:new_pass_hashed)", data)
    cursor.execute("update salts set salt=(:salt) where account='master_password'", data)
    cursor.connection.commit() #without this, get db locked error. Commits needed between functions with transactions
    
    #update all passwords in db to use new master_password as key
    cursor.execute("select * from logins")
    rows = cursor.fetchall()
    for row in rows:
        update_password(row['account'],
                        new_password,
                        decrypt_password(row['account'], master_password))
    

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
            get_login(args[0], master_password)
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
            change_master_password(master_password)
            print("Master password updated.")
            exit(0)

if __name__ == "__main__":
    parse_args()
