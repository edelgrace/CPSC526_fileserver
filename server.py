# Edel Altares 10098725 Tutorial 2

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


    def send_msg(self, data, sckt):
        """ Function to send message to a socket """
        if isinstance(data, (bytes, bytearray)):
            data = data.decode("utf-8")

        # TODO Check which cipher is used

        # put message on queue
        self.MESSAGES[sckt].put(bytearray(data,"utf-8"))

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
        print("DEBUG handshake")
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

            print("DEBUG handshake error")

            return

        cipher = data[0]
        nonce = data[1]
        client_addr = client.getsockname()[0]

        print(self.timestamp() + "New connection from " + client_addr + ", cipher: " + cipher + ", nonce: " + nonce)

        # TODO generate IVs and session-keys from nonce and cipher
        self.CLIENTS[client]['IV'] = None
        self.CLIENTS[client]['sessionkey'] = None

        # generate a challenge
        # reference: https://stackoverflow.com/questions/37675280/how-to-generate-a-ranstring
        challenge = uuid.uuid4().hex
        self.CLIENTS[client]['challenge'] = challenge
        print("DEBUG handshake challenge")

        # put challenge onto the clients queue
        challenge = "You have been challenged: " + challenge + "\n"

        self.send_msg(challenge, client)

        # change client status
        self.CLIENTS[client]['status'] = "CHALLENGED"

        return

    def challenged(self, data, client):
        """ Receive challenge and compute response """

        # receive the challenge
        data = data.decode("utf-8").strip()
        data = data.split(": ")
        
        challenge = data[1] + self.SECRET_KEY
        
        print("DEBUG pre hash received challenge " + challenge)

        # compute the response to the challenge
        my_response = hashlib.sha224(challenge.encode("utf-8")).hexdigest()

        print("DEBU hash received challenge " + my_response)

        # put message on queue
        my_response = "Server response: " + my_response + "\n"
        self.send_msg(my_response, client)

        # change state to response
        self.CLIENTS[client]['status'] = "CLI-RESPONSE"

        return

    def cliResponse(self, data, client):
        # get response from client
        data = data.decode("utf-8").strip()
        data = data.split(": ")
        response = data[1].strip()

        # compute the client challenge
        challenge = self.CLIENTS[client]['challenge'] + self.SECRET_KEY
        
        print("DEBUG challenge " + challenge)
        
        challenge = hashlib.sha224(challenge.encode("utf-8")).hexdigest()

        print("DEBUG computed-" + challenge + "-")
        print("DEBUG response-" + response + "-")
        print(challenge==response)

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
        
        # get the request
        data = data.decode("utf-8").strip()
        data = data.split(" ")
        
        operation = data[0]
        filename = data[1]

        # operation is to write a file
        if operation == "write":
            self.write_file(client, filename)


        # operation is to read a file
        else:
            self.read_file(client, filename)

    def write_file(self, client, filename):
        """ Write a file to server """



        return

    def read_file(self, client, filename):
        """ Read a file from server """
        print("DEBUG reading")
        print("DEBUG reading" + filename)


        # open the file
        # reference: https://pages.cpsc.ucalgary.ca/~henrique.pereira/pdfs/read.py
        try:
            with open(filename, 'rb') as file:
                content = None

                # read the file
                while content != b'':
                    # read 128 bits of the file
                    content = file.read(128)

                    if len(content) <= 128:
                        contentSize = len(content)
                        print("DEBUG reading size " + str(contentSize))


                    print("DEBUG reading-" + str(content))

                    self.send_msg(content, client)

                # change the state to close
                self.send_msg("File download successful", client)

        # error occured
        except IOError as error:
            print("DEBUG error")
            error = str(error) + "\n"

            self.send_msg(error, client)

            self.CLIENTS[client]['status'] = "CLOSE"

        print("DEBUG reading done")
        return

    def done(self, data, client):
        """ Check if done """

        # receive from client
        data = data.decode("utf-8").strip()

        # close the connection
        if data == "END":
            print("DEBUG client sent end")
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
                print("DEBUG input" + sckt.getsockname()[0])
                # server
                if sckt is self.SVR_SOCKET:
                    # accept a connection
                    connection, client_addr = sckt.accept()
                    connection.setblocking(0)

                    # add connection to the arrays
                    self.INPUTS.append(connection)
                    self.MESSAGES[connection] = queue.Queue()
                    self.CLIENTS[connection] = {}

                    # og the ip of client
                    print(self.timestamp() + "New connection from: " + client_addr[0])

                # client
                else:
                    data = sckt.recv(1024)
                    print("DEBUG data")
                    print("DEBUG data " + str(self.CLIENTS[sckt]))
                    print("DEBUG data-" + data.decode("utf-8"))

                    # data to be received
                    if data:
                        # start handshake
                        if self.CLIENTS[sckt] == {}:
                            print(self.timestamp() + "Commencing handshake")
                            self.handshake(data, sckt)
                            print("DEBUG handshake exited")

                        # handshake already started or completed
                        else:
                            # close connection if error
                            if self.CLIENTS[sckt]['status'] == "CLOSE":
                                print("DEBUG error")
                                self.close_socket(sckt)

                            elif self.CLIENTS[sckt]['status'] == "CHALLENGED":
                                print("DEBUG 1 challenged")
                                self.challenged(data, sckt)
                                print("DEBUG challenge finished")

                            elif self.CLIENTS[sckt]['status'] == "CLI-RESPONSE":
                                print("DEBUG 2 response")
                                self.cliResponse(data, sckt)
                                print("DEBUG response finished")
                                
                            elif self.CLIENTS[sckt]['status'] == "SVR-RESPONSE":
                                print("DEBUG 3 server response")
                                self.svr_response(data, sckt)
                                print("DEBUG server response finished")

                            # client can freely communicate
                            elif self.CLIENTS[sckt]['status'] == "FREE":
                                print("DEBUG 4 request")
                                # put data in the queue
                                # self.send_msg(data, sckt)

                                self.operation_request(data, sckt)

                                self.CLIENTS[sckt]['status'] = "DONE"

                                print("DEBUG request done")

                            elif self.CLIENTS[sckt]['status'] == "DONE":
                                print("DEBUG done")
                                
                                self.done(data, sckt)

                    # no more data = close connection
                    else: 
                        print("DEBUG close")
                        self.close_socket(sckt)
        
            # go through outputs
            for sckt in writable:
                print("DEBUG input" + sckt.getsockname()[0])
                try:
                    # grab the next message
                    next_msg = self.MESSAGES[sckt].get_nowait()

                except queue.Empty:
                    self.OUTPUTS.remove(sckt)

                else:
                    try:
                        # send the message
                        sckt.send(next_msg)

                        print("DEBUG send " + next_msg)
                    except Exception as e:
                        print(str(e))
                    finally:
                        # close connection if error
                        if self.CLIENTS[sckt]['status'] == "CLOSE":
                            self.close_socket(sckt)
                            print("DEBUG error")


def run():
    """ Run the server """
    svr = Server()
    svr.setup()

    while True:
        svr.run()

# run the program
if __name__ == "__main__":
    run()
