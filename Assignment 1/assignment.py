#!/usr/bin/python2.7
# -*- coding: latin-1 -*-
import hashlib
import argparse

from datetime import datetime

TARGET_DIFFICULTY = 6  # No of preceding zeros required

# Define Values from arguments passed
parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description="""
    Blockchain Assignment:

    Hi There! This is a simple assignment to showcase how Blockchain mining works.
    So let's get started!
    Lets assume a blockchain for Attendance. Every Block consists of the userid, timestamp and nonce.
    So this is a Proof of Work based Blockchain where to get your attendance you need to compute the 
    nonce such that the hash of the block(it's string representation) meet certain criteria.
    In our case the hexadecimal representation of the hash needs to have atleast 6 preceding zeros to pass!

    Do note that the timestamp is taken automatically so ensure that you calculate the nonce 
    for the block that will be created on the day you have to submit the assignment!

    For calculating the nonce you can try anything you want. You can manually try different values for nonce
    (highly encouraged :P) or write a script to do it for you, 
    The only thing that matters is that you get the first 6 hex values of the hash to be zero.

    The Block string representation is as follows: "Block: ['timestamp':{}, 'userid':{}, 'nonce':{}]"
    Timestamp is in the format 'YYYY:MM:DD'
    For calculating the hash we use SHA256 algorithm.(https://emn178.github.io/online-tools/sha256.html)
    
    One Solved Example:
    For 1st September 2019, Id: 160000000 the nonce is 51383180. Try running:
    python mining_assignment.py -id 160000000 -n 51383180 -d 2019:09:01

    So your task is to calculate the nonce(a integer value) for your Registration ID 
    for the given submission date to complete this assignment!
    """,
    epilog="PS: Extra Credits for those who can exceed the passing criteria! :P",
)
parser.add_argument(
    "-id",
    "--user-id",
    required=True,
    type=int,
    help="Your Registration ID (ex: 160000000)",
    default=16000000,
)
parser.add_argument(
    "-n",
    "--nonce",
    required=True,
    type=int,
    help="Nonce that you have calculated (has to be a integer)",
    default=0,
)
parser.add_argument(
    "-d",
    "--date",
    type=str,
    help="Date in the format 'YYYY:MM:DD'",
    default=datetime.now().strftime("%Y:%m:%d"),
)
args = parser.parse_args()


class Block:
    """ The header of a block """

    def __init__(self, timestamp, userid, nonce):
        # The user ID of the person creating the block (Format: "1610x00xx")
        self.userid = str(userid)

        # The approximate creation time of this block (date in format "YYYY:MM:DD")
        self.timestamp = str(timestamp)

        # The value of nonce
        self.nonce = int(nonce)

    def __str__(self):
        return "Block: ['timestamp':{}, 'userid':{}, 'nonce':{}]".format(
            self.timestamp, self.userid, self.nonce
        )


def dhash(s):
    """ sha256 hash """
    if not isinstance(s, str):
        s = str(s)
    s = s.encode()
    return hashlib.sha256(s).hexdigest()


def is_proper_difficulty(target_difficulty, blockhash):
    pow = 0
    for c in blockhash:
        if not c == "0":
            break
        else:
            pow += 1
    if pow < target_difficulty:
        return False
    return True


if __name__ == "__main__":
    block = Block(args.date, args.user_id, args.nonce)

    print(
        hashlib.sha256(
            "Block: ['timestamp':2019:09:01, 'userid':160000000, 'nonce':12345678]".encode()
        ).hexdigest()
    )

    print(block)
    print("Hash:", dhash(block))
    if is_proper_difficulty(TARGET_DIFFICULTY + 2, dhash(block)):
        print("============= Awesome! Extra marks for extra effort! :P =============")
    elif is_proper_difficulty(TARGET_DIFFICULTY, dhash(block)):
        print("++++++++++ Assignment Done! ++++++++++")
    else:
        print("Does not meet criteria, Keep Trying!")
