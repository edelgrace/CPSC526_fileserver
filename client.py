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
    CLI_SOCKET = None
    STATE = "HANDSHAKE"
    CHALLENGE = None
    RESPONSE = None

    def parse(self):
        """ Parse the arguments """

        parser = argparse.ArgumentParser()

        # required arguments
        parser.add_argument('operation', choices=['read', 'write'])
        parser.add_argument('filename')
        parser.add_argument('host')
        parser.add_argument('port', type=int)
        parser.add_argument('cipher', choices=['null', 'aes256', 'aes128'])
        parser.add_argument('key')

        # parse the arguments
        arguments = parser.parse_args()

        # save variables
        self.OPERATION = arguments.operation
        self.FILENAME = arguments.filename
        self.IP_ADDR = arguments.host
        self.PORT = arguments.port
        self.CIPHER = arguments.cipher
        self.SECRET_KEY = arguments.key

        return


    def setup(self):
        """ Setup the client """

        # get parsed arguments
        self.parse()

        # setup the client socket
        try:
            self.CLI_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.CLI_SOCKET.connect((self.IP_ADDR, self.PORT))
        
        except Exception as e:
            print(str(e))
            sys.exit(0)

        # start the handshake
        self.handshake()

        return

    
    def handshake(self):
        """ Start the handshake process """

        # send the cipher and nonce
        nonce = uuid.uuid4().hex
        msg = self.CIPHER + " " + nonce

        self.CLI_SOCKET.send(bytearray(msg, "utf-8"))

        self.STATE = "CHALLENGE"

        return

    def challenge(self, data):
        """ Receive and send challenge to server """

        # parse the data from the server
        data = data.decode("utf-8").strip()
        data = data.split(": ")

        self.CHALLENGE = data[1]

        print("DEBUG received challenge " + self.CHALLENGE)

        # generate message to send to server
        challenge = uuid.uuid4().hex
        msg = "You have been challenged: " + challenge

        print("DEBUG sent challenge " + challenge)

        self.CLI_SOCKET.send(bytearray(msg, "utf-8"))

        # generate the response the server should reply with
        response = self.CHALLENGE + self.SECRET_KEY

        print("DEBUG prehash response " + response)

        self.RESPONSE = hashlib.sha224(response.encode("utf-8")).hexdigest()

        print("DEBUG sent response " + self.RESPONSE)

        # change the state
        self.STATE = "RESPONSE"

    def response(self, data):
        """ Receive data from the server """

        # receive the data from the server
        data = data.decode("utf-8").strip()
        data = data.split(": ")
        response = data[1]

        print("DEBUG received response " + response)

        # send response
        msg = "My response: " + self.RESPONSE
        self.CLI_SOCKET.send(bytearray(msg, "utf-8"))

        self.STATE = "AUTHENTICATE"

    def run(self):
        """ Run the client """

        try:
            while True:
                data = self.CLI_SOCKET.recv(1024)
                
                if data:
                    
                    print("DEBUG " + self.STATE)
                    print(data)

                    # check if handshake done
                    if self.STATE == "CHALLENGE":
                        self.challenge(data)

                    # check if challenge send
                    elif self.STATE == "RESPONSE":
                        self.response(data)

                # no more data, close connection
                else:
                    print("Disconnected")
                    self.CLI_SOCKET.close()

        except KeyboardInterrupt:
            print("Disconnected")
            sys.exit(0)

def run():
    """ Run the client """
    cli = Client()
    cli.setup()

    while True:
        cli.run()


# run the program
if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("Disconnected")
        sys.exit(0)