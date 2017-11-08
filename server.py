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
        print(self.timestamp() + "Closed connection: " + str(sckt))

        # remove from outputs
        if sckt in self.OUTPUTS:
            self.OUTPUTS.remove(sckt)
        
        # remove from inputs
        self.INPUTS.remove(sckt)

        # close the socket
        sckt.close()

    def handshake(self, data, client):
        """ Guides through the initial steps of the protocol """

        # receive nonce and cipher from client
        data = data.decode("utf-8")
        data = data.split(" ")

        # check if nonce and cipher really sent
        if len(data) > 2:
            # set the error message and state
            self.CLIENTS[client]['status'] = "CLOSE"
            self.CLIENTS[client]['error'] = "Error: Authentication failed"

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

        # put challenge onto the clients queue
        challenge = "You have been challenged: " + challenge

        self.MESSAGES[client].put(bytearray(challenge, "utf-8"))

        # change client status
        self.CLIENTS[client]['status'] = "CHALLENGED"

    def challenged(self, data, client):
        """ Receive challenge and compute response """

        # receive the challenge
        data = data.decode("utf-8")
        data = data.split(":")

        challenge = data 

        # computer the response to the challenge

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
                    self.MESSAGES[connection] = queue.Queue()
                    self.CLIENTS[connection] = {}

                    # Log the ip of client
                    print(self.timestamp() + "New connection from: " + client_addr[0])

                # client
                else:
                    data = sckt.recv(1024)

                    # data to be received
                    if data:
                        # start handshake
                        if self.CLIENTS[sckt] == {}:
                            print(self.timestamp() + "Commencing handshake")
                            self.handshake(data, sckt)

                        # handshake already started or completed
                        else:
                            if self.CLIENTS[sckt]['status'] == "CHALLENGED":
                                print("challenged")
                                self.challenged(data, sckt)

                            # close connection if error
                            if self.CLIENTS[sckt]['status'] == "CLOSE":
                                print("error")
                                self.closeSocket(sckt)

                            # client can freely communicate
                            else:
                                # put data in the queue
                                self.MESSAGES[sckt].put(data)

                                # add to output list
                                if sckt not in self.OUTPUTS:
                                    self.OUTPUTS.append(sckt)

                    # no more data = close connection
                    else: 
                        self.closeSocket(sckt)

            # go through outputs
            for sckt in writable:

                try:
                    # grab the next message
                    next_msg = self.MESSAGES[sckt].get_nowait()

                except queue.Empty:
                    self.OUTPUTS.remove(sckt)

                else:
                    try:
                        # send the message
                        print(next_msg)
                        sckt.send(next_msg)
                    finally:
                        # close connection if error
                        if self.CLIENTS[sckt]['status'] == "CLOSE":
                            print("error")
                            self.closeSocket(sckt)


            # go through errors
            # for sckt in error:
                # remove from inputs
                # self.INPUTS.remove(sckt)

                # remove from outputs
                # if sckt not in self.OUTPUTS:
                    # self.OUTPUTS.remove(sckt)

                # remove from message queue
                # del self.MESSAGES[sckt]

                # close socket


def run():
    """ Run the server """
    svr = Server()
    svr.setup()

    while True:
        svr.run()

# run the program
if __name__ == "__main__":
    run()
