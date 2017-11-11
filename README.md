# passman
Passman is a simple cli password manager written in Python. It's aim is to be fast and minimal - store and provide you with login details, and that's it. Ask for a login, and it will put your username in the clipboard, and when you're ready it will put your password in the clipboard for 5 seconds.

## Dependencies
Passman uses *[pyperclip](https://pyperclip.readthedocs.io/en/latest/introduction.html)* to put usernames and passwords into the system clipboard, and [*Cryptography*](https://cryptography.io/en/latest/) for the Fernet cipher to encrypt passwords securely. Both are of course available through pip.

## Details about security
At the moment, only passwords are encrypted. This means anybody that can access the database can see what you have accounts for, and what your usernames are. The option to also encrypt these will change in the future, I just wasn't concerned about it for myself.
On its first run, passman creates a database and asks the user for a master password. This password is required for passman to do anything, and is used as part of the procedure to derive the keys for the passwords.
So for secure use, you should obviously choose a strong master password. Of course, the master password may be changed.

The master password is hashed with hashlib's (from the standard library) pbkdf2_hmac, where the hmac calculation uses the SHA256 hash. This is a standard method of hashing passwords. This hash is then stored in the database for authenticating the user.

Passwords are encrypted with the [Cryptography](https://cryptography.io/en/latest/)'s Fernet cipher. First a random salt is generated, and then cryptography's pbkdf2hmac function uses this salt and the master password to derive a secure key for the Fernet cipher.
The use of a salt effectively means each password gets its own key-derivation function. This prevents the weaknesses associated with encrypting lots of (potentially similar) data using the same key.
The salts are stored in the database to be recovered for recreating the cipher for decryption (salts are not meant to be secret - just unique). [Here](https://github.com/fernet/spec/blob/master/Spec.md) is a description of the Fernet cipher.
