#!/bin/python3
from pwn import *
import sys

if len(sys.argv) != 3:  # Making sure that we always get the appropriate argument in the CLI
    print("Please enter an md5 hash and a password file respectively.")
    exit()

wanted_hash = sys.argv[1]  # Here, we are making sure that we are accepting our hash as the first argument

password_file = sys.argv[2]  # We accept the password file as the second argument
attempts = 0  # This will count our tally when we're doing our cracking

try:
    with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as prog:  # This is how we will keep track of
        # our progress
        with open(password_file, "r", encoding="latin-1") as password_file:
            for passwords in password_file:
                password = passwords.strip("\n").encode("latin-1")
                password_hash = md5sumhex(password)
                prog.status("[*] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
                if password_hash == wanted_hash:
                    prog.success(
                        "Hash found! The password for {} is {}".format(wanted_hash, password.decode('latin-1')))
                    print("Operation successful after {} attempts.".format(attempts))
                    exit()
                attempts += 1
            prog.failure("The password for {} was not found.".format(wanted_hash))
except FileNotFoundError:
    print("The password file entered in the argument was not found.")
