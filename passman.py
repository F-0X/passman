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

#TODO: High importance - security! some form of encryption and user authentication is necessary.
#      Otherwise, general use can likely be improved a bit.
# Perhaps use the cryptography package (available on pip) for both the encryption of passwords and
# for the hashing of database password?
#
# Ensure master password input is at most 16 characters


#Defines a decorator to control db access - provides a cursor to use, and closes data after function.
def database_access(function):
    def wrapper(*args, **kwargs):
        data = get_db_connection()
        cursor = data.cursor()
        function(*args, cursor, **kwargs)
        data.commit()
        data.close()
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
    data.commit()
    data.close()
    print("Database created")
    exit(0)


@database_access
def get_password(account, cursor, user=None):
    cursor.execute("select password from logins where account=?", (account,))
    result = cursor.fetchall()

    if len(result) == 0:
        print("No such account")
        exit(0)
    if len(result) == 1:
        pc.copy(result[0][0])
        print("Password for {} now in clipboard".format(account))
        time.sleep(10)
        pc.copy("VOID")

        
@database_access
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


@database_access
def add_new_record(cursor):
    record = {}
    record['account'] = input("Account: ")
    record['username'] = input("Username: ")
    password = getpass.getpass()
    password2 = getpass.getpass('Verify password:')

    if password != password2:
        print("ERROR: Password and Validation did not match")
        return
    
    record['password'] = password
    
    cursor.execute("insert into logins values (:account, :username, :password)", record)
    print("Database updated - Added account {}".format(record['account']))


@database_access
def delete_record(account, cursor):
    confirmation = input("Confirm deletion of account {} (y/n): ".format(account))

    if confirmation == 'y':
        cursor.execute("delete from logins where account=?", (account,))
        print("Database updated - Deleted account {}".format(account))
    else:
        print("Deletion aborted")

    
@database_access
def list_accounts(cursor):
    result = cursor.execute("select account from logins")
    for row in result:
        print(row[0])
    

def check_args(args, n):
    if len(args) != n:
        print("ERROR: Too many args")
        usage()
        sys.exit(2)


@database_access
def authenticate_user(cursor):
    user_pass = getpass.getpass("Enter master password: ")

    cursor.execute("select password from hidden")
    result = cursor.fetchone()

    #if hash of user input is not the same as hash in database
    if hashlib.sha256(user_pass.encode('UTF-8')).hexdigest() != result[0]:
        print("user hash = {}, db data = {}".format(hashlib.sha256(user_pass.encode('UTF-8')).hexdigest(),result[0]))
        print("Wrong password")
        sys.exit(2)
    
        
@database_access
def get_login(account, cursor):
    cursor.execute("select username from logins where account=?", (account,))
    result = cursor.fetchall()

    if len(result) == 1:
        pc.copy(result[0][0])
    else:
        print("Non-unique username for this account type!")
        sys.exit(2)

    input("Username for {} in clipboard. Press Enter for password...".format(account))

    cursor.execute("select password from logins where account=?", (account,))
    result = cursor.fetchone()

    pc.copy(result[0])
    print("Password for {} in clipboard. Clipboard will expire in 10 seconds.".format(account))
    time.sleep(10)
    pc.copy("VOID")
    
    
@database_access
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

    authenticate_user()

    if len(opts) == 0:
        check_args(args,1)
        if args[0] == "add":
            add_new_record()
            exit(0)
        else:
            get_login(args[0])
            exit(0)

    for opt, arg in opts:
        if opt in ("-l", "--login"):
            get_login(arg)
            print("Clipboard expired")
            exit(0)

        if opt in ("-u", "--username"):
            get_username(arg)
            print("Clipboard expired")
            exit(0)

        if opt in ("-p", "--password"):
            get_password(arg)
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
