# Edel Altares 1009872 Tutorial 2

import select
import socket
import os
import sys
import queue
import argparse
import time
import datetime
import uuid
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Client:
    """ Class for the client """

    IP_ADDR = "0.0.0.0"
    PORT = 0
    SECRET_KEY = None
    OPERATION = None
    FILENAME = None
    CIPHER = None
    NONCE = None

    def parse(self):
        """ Parse the arguments """

        parser = argparse.ArgumentParser()

        # required arguments
        parser.add_argument('port', type=int)
        parser.add_argument('secretkey')
        parser.add_argument('ip')
        
        arguments = parser.parse_args()

        self.IP_ADDR = arguments.ip
        self.PORT = arguments.port
        self.SECRET_KEY = arguments.secretkey

        return

    def setup(self):
        """ Setup the client """


    def run(self):
        """ Run the client """

        while True:
            return


def run():
    """ Run the client """
    cli = Client()
    cli.setup()

    while True:
        cli.run()


# run the program
if __name__ == "__main__":
    run()