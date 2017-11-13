# Edel Altares 10098725 Tutorial 2

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

class Server:
    """ Server Class """

    IP_ADDR = "0.0.0.0"
    PORT = 0
    SVR_SOCKET = None
    SECRET_KEY = None

    INPUTS = []
    OUTPUTS = []

    MESSAGES = {}
    CLIENTS = {}

    def parse(self):
        """ Parse the arguments"""

        parser = argparse.ArgumentParser()

        # required arguments
        parser.add_argument('port', type=int)
        parser.add_argument('secretkey')
        
        arguments = parser.parse_args()

        self.PORT = arguments.port
        self.SECRET_KEY = arguments.secretkey

        return


    def timestamp(self):
        """ Return current time """

        # get the current time
        timestamp = datetime.datetime.now().time()
        timestamp = timestamp.strftime("%H:%M:%S")

        # return timestamp
        return timestamp + " - "

    
    def decrypt(self, data, client):
        """ Decrypt a message """
        
        # decrypt the message
        decryptor = self.CLIENTS[client]['enc-dec'].decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
            
        return data


    def send_msg(self, data, sckt):
        """ Function to send message to a socket """
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)

        cipher_chosen = self.CLIENTS[sckt]['cipher']

        # encrypt if needed
        if cipher_chosen != "null":
            encryptor = self.CLIENTS[sckt]['enc-dec'].encryptor()

            # padding
            padder = padding.PKCS7(128).padder()
            data = padder.update(data) + padder.finalize()

            # encrypt
            data = encryptor.update(data) + encryptor.finalize()
            self.MESSAGES[sckt].put(data)

        else:
            self.MESSAGES[sckt].put(data)

        # add to the outputs
        if sckt not in self.OUTPUTS:
            self.OUTPUTS.append(sckt)


    def setup(self):
        """ Setup the server """
        # get parsed arguments
        self.parse()

        # setup the server socket
        self.SVR_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SVR_SOCKET.setblocking(0)
        self.SVR_SOCKET.bind((self.IP_ADDR, self.PORT))

        return


    def close_socket(self, sckt):
        """ Close a connection to a client """

        # Log connection closing
        print(self.timestamp() + "Closed connection: " + str(sckt.getsockname()[0]))

        # remove from outputs
        if sckt in self.OUTPUTS:
            self.OUTPUTS.remove(sckt)
        
        # remove from inputs
        self.INPUTS.remove(sckt)

        # close the socket
        sckt.close()

    def handshake(self, data, client):
        """ Guides through the initial steps of the protocol """
        
        print(self.timestamp() + "Handshake started")
        
        # receive nonce and cipher from client
        data = data.decode("utf-8")
        data = data.split(" ")

        # check if nonce and cipher really sent
        if len(data) != 2:
            # set the error message and state
            self.CLIENTS[client]['status'] = "CLOSE"
            error = "Error: Cipher and nonce not sent"
            
            # put error on queue
            self.send_msg(error, client)

            print(self.timestamp() + "Handshake error")

            return

        cipher = data[0]
        nonce = data[1]
        client_addr = client.getsockname()[0]
        self.CLIENTS[client]['cipher'] = cipher

        print(self.timestamp() + "New connection from " + client_addr + ", cipher: " + cipher + ", nonce: " + nonce)

        # check if cipher specified
        if cipher != "null":
            # generate the IV
            iv = self.SECRET_KEY + nonce + "IV"
            iv = hashlib.sha256(iv).hexdigest()[:16]

            # generate the session-key
            key = self.SECRET_KEY + nonce + "SK"
            key = hashlib.sha256(key).hexdigest()
            
            # change key depeneding on what cipher chosen
            if cipher == "aes128":
                key = key[:16]
            else:
                key = key[:32]

            self.CLIENTS[client]['iv'] = iv[:16]
            self.CLIENTS[client]['sk'] = key

            backend = default_backend()

            # encrypt
            self.CLIENTS[client]['enc-dec'] = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

        # generate a challenge
        # reference: https://stackoverflow.com/questions/37675280/how-to-generate-a-ranstring
        challenge = uuid.uuid4().hex
        self.CLIENTS[client]['challenge'] = challenge

        # put challenge onto the clients queue
        challenge = "You have been challenged: " + challenge + "\n"

        self.send_msg(challenge, client)

        # change client status
        self.CLIENTS[client]['status'] = "CHALLENGED"

        return

    def challenged(self, data, client):
        """ Receive challenge and compute response """

        # decrypt if needed
        if self.CLIENTS[client]['cipher'] != "null":
            data = self.decrypt(data, client)

        # receive the challenge
        data = data.decode("utf-8").strip()
        data = data.split(": ")
        
        challenge = data[1] + self.SECRET_KEY
        
        print(self.timestamp() + "Pre hash received challenge " + challenge)

        # compute the response to the challenge
        my_response = hashlib.sha224(challenge.encode("utf-8")).hexdigest()

        print(self.timestamp() + "Hash received challenge " + my_response)

        # put message on queue
        my_response = "Server response: " + my_response + "\n"
        self.send_msg(my_response, client)

        # change state to response
        self.CLIENTS[client]['status'] = "CLI-RESPONSE"

        return

    def cliResponse(self, data, client):
        # decrypt if needed
        if self.CLIENTS[client]['cipher'] != "null":
            data = self.decrypt(data, client)

        # get response from client
        data = data.decode("utf-8").strip()
        data = data.split(": ")
        response = data[1].strip()

        # compute the client challenge
        challenge = self.CLIENTS[client]['challenge'] + self.SECRET_KEY
        
        print(self.timestamp() + "Challenge received " + challenge)
        
        challenge = hashlib.sha224(challenge.encode("utf-8")).hexdigest()

        print(self.timestamp() + "Computed response " + challenge + "-")
        print(self.timestamp() + "Actual response " + response + "-")

        # challenge correct
        if str(challenge) == str(response):
            self.CLIENTS[client]['status'] = "SVR-RESPONSE"
            self.send_msg("OK client challenge correct\n", client)
            print(self.timestamp() + " Client knows the secret key")

        # challenge not done correctly
        else:
            self.CLIENTS[client]['status'] = "CLOSE"
            self.send_msg("Error: The response to the challenge was wrong\n", client)

        return

    def svr_response(self, data, client):
        """ Check if the server had a correct response """

        # decrypt if needed
        if self.CLIENTS[client]['cipher'] != "null":
            data = self.decrypt(data, client)

        # get the client response
        data = data.decode("utf-8")
        data = data.strip("\n")

        # the key was computed correctly
        if data == "OK":
            self.CLIENTS[client]['status'] = "FREE"
            self.send_msg("OK server challenge correct\n", client)
            print(self.timestamp() + "Server knows the server key")
        
        # the key was not computer correctly
        else:
            self.CLIENTS[client]['status'] = "CLOSE"
            self.send_msg("ERROR Server did not compute challenge correctly", client)
            print(self.timestamp() + "Server does not know the server key?")


    def operation_request(self, data, client):
        """ Handle the client request """

        # decrypt if needed
        if self.CLIENTS[client]['cipher'] != "null":
            data = self.decrypt(data, client)

        # get the request
        data = data.decode("utf-8").strip()
        data = data.split(" ")
        
        operation = data[0]
        filename = data[1]
        self.CLIENTS[client]['file'] = filename

        # operation is to write a file
        if operation == "write":
            self.CLIENTS[client]['status'] = "RECEIVING"
            self.CLIENTS[client]['LASTBLOCK'] = False
            self.CLIENTS[client]['FIRSTBLOCK'] = True
            self.send_msg("OK", client)


        # operation is to read a file
        else:
            self.read_file(client, filename)


    def receiving(self, client, data):
        """ Write a file to server """

        # decrypt the data
        if self.CLIENTS[client]['cipher'] != "null":
            data = self.decrypt(data, client)

        lastChar = data[-1]
        notLastBlock = False

        content = unicode(data, errors='ignore').strip()

        # check if last block
        if "END" in content:
            print(self.timestamp() + "Client finished uploading")

            msg = "END"

            self.send_msg(msg, client)
            
            self.STATE = "DONE"

            return

        if self.CLIENTS[client]['LASTBLOCK']:
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
                self.CLIENTS[client]['LASTBLOCK'] = True

        if lastChar == "-":
            lastChar = data[-3:-1]
            
            if lastChar.isdigit():
                lastChar = int(lastChar)
                data = data[:0-lastChar]
                self.CLIENTS[client]['LASTBLOCK'] = True

        elif lastChar == "_":
            lastChar = data[-6:-4]

        elif lastChar == "*":
            lastChar = data[-4:-2]

            if lastChar.isdigit():
                lastChar = int(lastChar)
                data = data[:0-lastChar]
                self.CLIENTS[client]['LASTBLOCK'] = True

        elif lastChar == "=":
            lastChar = data[-5:-3]

            if lastChar.isdigit():
                lastChar = int(lastChar)
                data = data[:0-lastChar]
                self.CLIENTS[client]['LASTBLOCK'] = True

        if notLastBlock:
            data = "1" + data
            self.CLIENTS[client]['LASTBLOCK'] = False

        filename = self.CLIENTS[client]['file']

        if os.path.exists(filename) and self.CLIENTS[client]['FIRSTBLOCK']:
            file = open(filename, 'wb')
            file.close()

            
            self.CLIENTS[client]['FIRSTBLOCK'] = False

        with open(filename, 'ab') as file:
            file.write(data)

        return


    def read_file(self, client, filename):
        """ Read a file from server """

        print(self.timestamp() + "Client requested" + filename)

        # open the file
        # reference: https://pages.cpsc.ucalgary.ca/~henrique.pereira/pdfs/read.py
        try:
            with open(filename, 'rb') as file:
                content = None

                # read the file
                while content != b'':
                    # read 128 bits of the file
                    content = file.read(128)

                    if len(content) < 128 and len(content) != 0:
                        padding = 128 - len(content)
                        content = content.decode("utf-8")

                        # padding with one digit
                        if padding < 10:
                            content += str(padding) * padding
                        
                        # padding with two digits
                        elif padding >= 10 and padding < 100:
                            if padding % 2 == 0:
                                content += str(padding) * padding/2
                            else:
                                content += str(padding) * int((padding-1)/2)
                                content += "-"

                        # padding with three digits
                        else:
                            if padding % 3 == 0:
                                content += str(padding) * ((padding/3) - 1)
                                content += "___"
                            elif padding %3 == 1:
                                content += str(padding) * (int((padding-1)/3)-1)
                                content += "***"
                            else:
                                content += str(padding) * int((padding-2)/3)
                                content += "==="
                            
                    if len(content) != 0:
                        self.send_msg(content, client)


                print(self.timestamp() + "File read is done")
                self.CLIENTS[client]['status'] = "DONE"
                self.send_msg(" END ", client)

        # error occured
        except IOError as error:
            error = str(error) + "\n"

            self.send_msg(error, client)

            print(self.timestamp() + "Error: " + error)

            self.CLIENTS[client]['status'] = "CLOSE"

        return

    def done(self, data, client):
        """ Check if done """

        # decrypt if needed
        if self.CLIENTS[client]['cipher'] != "null":
            data = self.decrypt(data, client)

        # receive from client
        data = data.decode("utf-8").strip()

        # close the connection
        self.send_msg("END", client)
        self.CLIENTS[client]['status'] = "CLOSE"

        return

    def run(self):

        """ Run the server """

        # Logging messages
        print("Listening on port: " + str(self.PORT))
        print("Using the secret key: " + self.SECRET_KEY)

        # Start listening for clients
        self.SVR_SOCKET.listen(5)
        self.INPUTS.append(self.SVR_SOCKET)

        while self.INPUTS:
            readable, writable, error = select.select(self.INPUTS, self.OUTPUTS, self.INPUTS, 0)

            # go through inputs
            for sckt in readable:

                # server
                if sckt is self.SVR_SOCKET:
                    # accept a connection
                    connection, client_addr = sckt.accept()
                    connection.setblocking(0)

                    # add connection to the arrays
                    self.INPUTS.append(connection)
                    self.MESSAGES[connection] = Queue.Queue()
                    self.CLIENTS[connection] = {}

                    # og the ip of client
                    print(self.timestamp() + "New connection from: " + client_addr[0])

                # client
                else:
                    data = sckt.recv(144)


                    print(data)

                    # data to be received
                    if data:

                        # start handshake
                        if self.CLIENTS[sckt] == {}:
                            print(self.timestamp() + "Commencing handshake")
                            self.handshake(data, sckt)
                            print(self.timestamp() + "Handshake exited")

                        # handshake already started or completed
                        else:
                            # close connection if error
                            if self.CLIENTS[sckt]['status'] == "CLOSE":
                                self.close_socket(sckt)

                            elif self.CLIENTS[sckt]['status'] == "CHALLENGED":
                                print(self.timestamp() + "1 Client challenged")
                                self.challenged(data, sckt)

                            elif self.CLIENTS[sckt]['status'] == "CLI-RESPONSE":
                                print(self.timestamp() + "2 response")
                                self.cliResponse(data, sckt)
                                
                            elif self.CLIENTS[sckt]['status'] == "SVR-RESPONSE":
                                print(self.timestamp() + "3 server response")
                                self.svr_response(data, sckt)

                            # client can freely communicate
                            elif self.CLIENTS[sckt]['status'] == "FREE":
                                print(self.timestamp() + "4 request")

                                self.operation_request(data, sckt)

                            elif self.CLIENTS[sckt]['status'] == "RECEIVING":
                                print(self.timestamp() + "5 Receiving a file")
                                self.receiving(sckt, data)

                            elif self.CLIENTS[sckt]['status'] == "DONE":
                                print(self.timestamp() + "5 done")
                                
                                self.done(data, sckt)

                            elif data.decode("utf-8").split() == "END":
                                print("CLIENT SENT END")

                            else:
                                print("____________HELP" + data.decode("utf-8"))

                    # no more data = close connection
                    else: 
                        self.close_socket(sckt)
        
            # go through outputs
            for sckt in writable:
                try:
                    # grab the next message
                    next_msg = self.MESSAGES[sckt].get_nowait()

                except Queue.Empty:
                    self.OUTPUTS.remove(sckt)
                    
                    # close connection
                    if self.CLIENTS[sckt]['status'] == "CLOSE":
                        self.close_socket(sckt)

                else:
                    # send the message
                    sckt.send(next_msg)


def run():
    """ Run the server """
    svr = Server()
    svr.setup()

    while True:
        svr.run()

# run the program
if __name__ == "__main__":
    run()
