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
        timestamp = datetime.datetime.now().time()
        
        return timestamp.strftime("%H:%M:%S")

    def setup(self):
        """ Setup the server """
        # get parsed arguments
        self.parse()

        # setup the server socket
        self.SVR_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SVR_SOCKET.setblocking(0)
        self.SVR_SOCKET.bind((self.IP_ADDR, self.PORT))

        return


    def handshake(self, data, client):
        """ Guides through the initial steps of the protocol """

        # receive nonce and cipher from client
        data = data.split(" ")
        cipher = data[0]
        nonce = data[0]

        # TODO generate IVs and session-keys from nonce and cipher

        # change client status to authenticate
        self.CLIENTS[client]['status'] = "AUTHENTICATE"

    def challenge(self, data, client):
        """ Generate challenge for client """
        
        # reference: https://stackoverflow.com/questions/37675280/how-to-generate-a-ranstring
        challenge = uuid.uuid4().hex

        # change client status
        self.CLIENTS[client]['status'] = "CHALLENGED"
    

    def run(self):
        """ Run the server """

        # Logging messages
        print("Listening on port: " + str(self.PORT))
        print("Using the secret key: " + self.SECRET_KEY)

        # Start listening for clients
        self.SVR_SOCKET.listen(5)
        self.INPUTS.append(self.SVR_SOCKET)

        while self.INPUTS:
            readable, writable, error = select.select(self.INPUTS, self.OUTPUTS, self.INPUTS)

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
                    self.CLIENTS[connection] = None

                    # Log the ip of client
                    print(self.timestamp() + " - New connection from: " + client_addr[0])

                # client
                else:
                    data = scktchecjk if.recv(1024)

                    # data to be received
                    if data:

                        # check if handshake done
                        if self.CLIENTS[sckt] is None:
                            self.handshake(data, sckt)

                        # check if not yet authenticated
                        elif self.CLIENTS[sckt]['status'] == "AUTHENTICATE"
                            
                            # create a challenge
                            challenge = self.challenge()

                            # put the challenge onto the queue
                            self.MESSAGES[sckt].put(bytearray(challenge, "utf-8"))
                            
                        # can freely communicate
                        else:
                            # put data in the queue
                            self.MESSAGES[sckt].put(data)

                            if sckt not in self.OUTPUTS:
                                self.OUTPUTS.append(sckt)

                    # no more data = close connection
                    else: 
                        # Log connection closing
                        print(self.timestamp() + "Closed connection: " + str(sckt))

                        # remove from outputs
                        if sckt in self.OUTPUTS:
                            self.OUTPUTS.remove(sckt)
                        
                        # remove from inputs
                        self.INPUTS.remove(sckt)

                        # remove from message queue
                        del self.MESSAGES[sckt]

                        # close the socket
                        sckt.close()

            # go through outputs
            for sckt in writable:

                try:
                    next_msg = self.MESSAGES[sckt].get_nowait()

                except queue.Empty:
                    self.OUTPUTS.remove(sckt)

                else:
                    sckt.send(next_msg)

            # go through errors
            for sckt in error:
                # remove from inputs
                self.INPUTS.remove(sckt)

                # remove from outputs
                if sckt not in self.OUTPUTS:
                    self.OUTPUTS.remove(sckt)

                # remove from message queue
                del self.MESSAGES[sckt]

                # close socket
                sckt.close()


def run():
    """ Run the server """
    svr = Server()
    svr.setup()

    while True:
        svr.run()

# run the program
if __name__ == "__main__":
    run()
