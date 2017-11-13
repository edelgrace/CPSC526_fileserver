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
from cryptography.hazmat.primitives import padding

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
    LASTBLOCK = False
    IV = None
    SK = None
    ENC_DEC = None


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
            
            sys.exit(0)

        # start the handshake
        self.handshake()

        return

    
    def decrypt(self, data):
        """ Decrypt a message """

        # decrypt the message
        decryptor = self.ENC_DEC.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        
        data = decryptor.update(data) + decryptor.finalize()

        data = unpadder.update(data) + unpadder.finalize()

        return data


    def encrypt(self, data):
        """ Encrypt a message """

        # padding if needed
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()

        # encrypt the message
        encryptor = self.ENC_DEC.encryptor()
        data = encryptor.update(data) + encryptor.finalize()

        return data

    def handshake(self):
        """ Start the handshake process """

        # send the cipher and nonce
        nonce = uuid.uuid4().hex
        nonce = nonce[:16]
        msg = self.CIPHER + " " + nonce

        # calculate IV and session key
        if self.CIPHER != "null":
            iv = self.SECRET_KEY + nonce + "IV"
            iv = hashlib.sha256(iv).hexdigest()
            self.IV = iv[:16]

            # generate the session-key
            key = self.SECRET_KEY + nonce + "SK"
            key = hashlib.sha256(key).hexdigest()
            self.SK = key

            if self.CIPHER == "aes128":
                self.SK = self.SK[:16]
            else:
                self.SK = self.SK[:32]

            # create the cipher
            backend = default_backend()
            self.ENC_DEC = Cipher(algorithms.AES(self.SK), modes.CBC(self.IV), backend=backend)

        self.CLI_SOCKET.send(bytearray(msg, "utf-8"))

        self.STATE = "CHALLENGE"

        return

    def challenge(self, data):
        """ Receive and send challenge to server """

        # decrypt the data
        if self.CIPHER != "null":
            data = self.decrypt(data)

        # parse the data from the server
        data = data.decode("utf-8").strip()
        data = data.split(": ")

        self.CHALLENGE = data[1]

        # generate message to send to server
        challenge = uuid.uuid4().hex
        msg = "You have been challenged: " + challenge
        msg = self.encrypt(msg)

        self.CLI_SOCKET.send(msg)

        # generate the response the server should reply with
        response = self.CHALLENGE + self.SECRET_KEY

        self.RESPONSE = hashlib.sha224(response.encode("utf-8")).hexdigest()

        # change the state
        self.STATE = "RESPONSE"


    def response(self, data):
        """ Receive data from the server """

        # decrypt the data
        if self.CIPHER != "null":
            data = self.decrypt(data)

        # receive the data from the server
        data = data.decode("utf-8").strip()
        data = data.split(": ")
        response = data[1]

        # send response
        msg = "My response: " + self.RESPONSE
        msg = self.encrypt(msg)
        self.CLI_SOCKET.send(msg)

        self.STATE = "AUTHENTICATE"


    def authenticate(self, data):
        """ TODO """

        # decrypt the data
        if self.CIPHER != "null":
            data = self.decrypt(data)

        # receive data from the server
        response = data.decode("utf-8").strip()
        
        # TODO comment
        if "OK" in response:
            msg = "OK"
            msg = self.encrypt(msg)
            self.CLI_SOCKET.send(msg)

            self.STATE = "REQUEST"

        else:
            # close the connection
            # self.CLI_SOCKET.close()

            # TODO print message
            sys.stderr.write("ERROR: wrong key\n")
            sys.exit(0)


    def send_request(self, data):
        """ Send file request to the server """

        # construct the message
        msg = self.OPERATION + " " + self.FILENAME
        msg = self.encrypt(msg)

        # send the message
        self.CLI_SOCKET.send(msg)

        # change the state appropriately
        if self.OPERATION == "read":
            self.STATE = "RECEIVING"
        else:
            self.STATE = "SENDING"

        return


    def sending(self, data):
        """ Upload a file to the server """

        return


    def receiving(self, data):
        """ Receive data from the server """

        # decrypt the data
        if self.CIPHER != "null":
            data = self.decrypt(data)

        lastChar = data[-1]
        notLastBlock = False

        content = unicode(data, errors='ignore').strip()

        # check if last block
        if content == "END":
            msg = "END"
            msg = self.encrypt(msg)
            self.CLI_SOCKET.send(msg)
            
            self.STATE = "DONE"

            return

        if self.LASTBLOCK:
            notLastBlock = True

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
                self.LASTBLOCK = True

        if lastChar == "-":
            lastChar = data[-3:-1]
            
            if lastChar.isdigit():
                lastChar = int(lastChar)
                data = data[:0-lastChar]
                self.LASTBLOCK = True

        elif lastChar == "*":
            lastChar = data[-4:-1]

            if lastChar.isdigit():
                lastChar = int(lastChar)
                data = data[:0-lastChar]
                self.LASTBLOCK = True

        elif lastChar == "=":
            lastChar = data[-5:6]
            
            if lastChar.isdigit():
                lastChar = int(lastChar)
                data = data[:0-lastChar]
                self.LASTBLOCK = True

        # write to stdout
        # reference: https://pages.cpsc.ucalgary.ca/~henrique.pereira/pdfs/read.py
        if notLastBlock:
            sys.stdout.write("1")
            self.LASTBLOCK = False

        sys.stdout.write(data)
        
        return


    def run(self):
        """ Run the client """

        try:
            while True:
                data = self.CLI_SOCKET.recv(144)
                
                if data:
                    # check if handshake done
                    if self.STATE == "CHALLENGE":
                        self.challenge(data)

                    # check if challenge send
                    elif self.STATE == "RESPONSE":
                        self.response(data)

                    # check if authentication good
                    elif self.STATE == "AUTHENTICATE":
                        
                        self.authenticate(data)

                    # check if request not sent yet
                    elif self.STATE == "REQUEST":
                        
                        self.send_request(data)

                    # check if receiving data from server
                    elif self.STATE == "RECEIVING":
                        self.receiving(data)

                    # check if sending data to server
                    elif self.STATE == "SENDING":
                        
                        self.sending(data)
                    
                    # error state
                    elif self.STATE == "ERROR":
                        # error state
                        sys.stderr.write("ERROR: \n")

                # no more data, close connection
                else:
                    if self.STATE == "DONE":
                        sys.stderr.write("OK\n")
                    else:
                        sys.stderr.write("ERROR\n")
                    sys.exit(0)

        except KeyboardInterrupt:
            
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
        
        sys.exit(0)