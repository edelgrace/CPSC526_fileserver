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
        return(timestamp + " - ")

    def sendMsg(self, data, sckt):
        """ Function to send message to a socket """
        
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


    def closeSocket(self, sckt):
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
        print("DEBUG handshake started")
        # receive nonce and cipher from client
        data = data.decode("utf-8")
        data = data.split(" ")

        # check if nonce and cipher really sent
        if len(data) != 2:
            # set the error message and state
            self.CLIENTS[client]['status'] = "CLOSE"
            error = "Error: Cipher and nonce not sent"
            
            # put error on queue
            self.sendMsg(error, client)

            print("DEBUG handshake error")

            return

        cipher = data[0]
        nonce = data[1]

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

        self.sendMsg(challenge, client)

        # change client status
        self.CLIENTS[client]['status'] = "CHALLENGED"

        return

    def challenged(self, data, client):
        """ Receive challenge and compute response """

        # receive the challenge
        data = data.decode("utf-8")
        data = data.split(": ")
        
        challenge = data[1] + self.SECRET_KEY
        
        # compute the response to the challenge
        my_response = hashlib.sha224(challenge.encode("utf-8")).hexdigest()



        # put message on queue
        my_response = "Server response: " + my_response
        self.sendMsg(my_response, client)

        # change state to response
        self.CLIENTS[client]['status'] = "RESPONSE"

        return

    def response(self, data, client):
        # get response from client
        data = data.encode("utf-8")
        data = data.split(": ")
        response = data[1].strip("\n")

        # compute the client challenge
        challenge = hashlib.sha224(self.CLIENTS[client['challenge']].encode("utf-8") + self.SECRET_KEY)

        # challenge correct
        if challenge == response:
            self.CLIENTS[client]['status'] = "FREE"
            self.sendMsg("OK Challenge correct", client)

        # challenge not done correctly
        else:
            self.CLIENTS[client]['status'] = "ERROR"
            self.sendMsg("Error: The response to the challenge was wrong", client)

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

                    # Log the ip of client
                    print(self.timestamp() + "New connection from: " + client_addr[0])

                # client
                else:
                    data = sckt.recv(1024)
                    print("DEBUG data")
                    print("DEBUG " + str(self.CLIENTS[sckt]))

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
                                self.closeSocket(sckt)

                            elif self.CLIENTS[sckt]['status'] == "CHALLENGED":
                                print("DEBUG challenged")
                                self.challenged(data, sckt)
                                print("DEBUG finish challenge")

                            elif self.CLIENTS[sckt]['status'] == "RESPONSE":
                                print("DEBUG response")
                                self.response(data, sckt)
                                print("DEBUG finish response")

                            # client can freely communicate
                            else:
                                print("DEBUG free")
                                # put data in the queue
                                self.sendMsg(data, sckt)

                    # no more data = close connection
                    else: 
                        print("DEBUG close")
                        self.closeSocket(sckt)
        
                pass

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
                    except Exception as e:
                        print(str(e))
                    finally:
                        # close connection if error
                        if self.CLIENTS[sckt]['status'] == "CLOSE":
                            self.closeSocket(sckt)


def run():
    """ Run the server """
    svr = Server()
    svr.setup()

    while True:
        svr.run()

# run the program
if __name__ == "__main__":
    run()
