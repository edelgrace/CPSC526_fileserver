# Edel Altares 1009872 Tutorial 2

import select
import socket
import os
import sys
import Queue
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
    FIRSTBLOCK = 0

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
        print("DEBUG setup")
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


    def authenticate(self, data):
        """ TODO """

        # receive data from the server
        response = data.decode("utf-8").strip()
        print("DEBUG authenticate " + response)

        # TODO comment
        if "OK" in response:
            self.CLI_SOCKET.send(bytearray("OK", "utf-8"))

            self.STATE = "REQUEST"

        else:
            # close the connection
            # self.CLI_SOCKET.close()

            # TODO print message

            sys.exit(0)


    def send_request(self, data):
        """ Send file request to the server """

        # construct the message
        msg = self.OPERATION + " " + self.FILENAME

        # send the message
        self.CLI_SOCKET.send(bytearray(msg, "utf-8"))

        # change the state appropriately
        if self.OPERATION == "read":
            self.STATE = "RECEIVING"
        else:
            self.STATE = "SENDING"

        return

    def receiving(self, data):
        """ Receive data from the server """

        lastChar = data[-1]

        content = unicode(data, errors='ignore').strip()

        print("DEBUG lastchar" + lastChar)
        
        if content == "END":
            self.CLI_SOCKET.send(bytearray("END", "utf-8"))
            
            print("DEBUG download successful?")
            
            self.STATE = "DONE"

            return
        
        if lastChar.isdigit():
            index = -1
            lastChar = int(lastChar)
            while index != lastChar:
                if data[0-index] == lastChar:
                    index -= 1
                else:
                    break
                
            if index * -1 == lastChar:
                data = data[:index]

        if lastChar == "-":
            lastChar = data[-3:-1]
            print(lastChar)
            if lastChar.isdigit():
                lastChar = int(lastChar)
                data = data[:0-lastChar]

        # write to stdout
        # sys.stdout.write(data)
        # sys.stdout.flush()

        # check if file operation done yet
        if self.FIRSTBLOCK == 0:
            if os.path.exists(self.FILENAME):
                file = open(self.FILENAME, 'w')
                file.close()
            self.FIRSTBLOCK = 1

        # write to a file
        # reference: https://pages.cpsc.ucalgary.ca/~henrique.pereira/pdfs/read.py
        with open(self.FILENAME, 'ab') as file:
            file.write(data)

            # file.flush()

            file.close()

        return

    def run(self):
        """ Run the client """

        print("DEBUG run loop")

        try:
            while True:
                data = self.CLI_SOCKET.recv(128)
                
                if data:

                    print("DEBUG-" + data)

                    # check if handshake done
                    if self.STATE == "CHALLENGE":
                        print("DEBUG 1")
                        self.challenge(data)

                    # check if challenge send
                    elif self.STATE == "RESPONSE":
                        print("DEBUG 2")
                        self.response(data)

                    # check if authentication good
                    elif self.STATE == "AUTHENTICATE":
                        print("DEBUG 3")
                        self.authenticate(data)

                    # check if request not sent yet
                    elif self.STATE == "REQUEST":
                        print("DEBUG 4")
                        self.send_request(data)

                    # check if receiving data from server
                    elif self.STATE == "RECEIVING":
                        self.receiving(data)

                    # check if sending data to server
                    elif self.STATE == "SENDING":
                        print("DEBUG 5 - sending")
                        self.sending(data)
                    
                    # error state
                    else:
                        # error state
                        print("DEBUG 6 error")

                # no more data, close connection
                else:
                    print("DEBUG closed")
                    print("Disconnected")
                    sys.exit(0)

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
    print("DEBUG running")
    try:
        run()
    except KeyboardInterrupt:
        print("Disconnected")
        sys.exit(0)