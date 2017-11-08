# Edel Altares 10098725 Tutorial 2

import select
import socket
import os
import sys
import queue
import argparse
import datetime

class Server:
    """ Server Class """

    IP_ADDR = "0.0.0.0"
    PORT = 0
    SVR_SOCKET = None
    SECRET_KEY = None
    INPUTS = []
    OUTPUTS = []
    MESSAGES = {}

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


    def setup(self):
        """ Setup the server """
        # get parsed arguments
        self.parse()
        
        # setup the server socket
        self.SVR_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SVR_SOCKET.setblocking(0)
        self.SVR_SOCKET.bind((self.IP_ADDR, self.PORT))

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
            readable, writable, error = select.select(self.INPUTS, self.OUTPUTS, self.INPUTS)

            # go through inputs
            for sckt in readable:

                # server
                if sckt is self.SVR_SOCKET:
                    # accept a connection
                    connection, client_addr = sckt.accept()
                    connection.setblocking(0)
                    self.INPUTS.append(connection)

                    # Log the ip of client
                    print(str(datetime.datetime.now()) + "New onnection from: " + client_addr)
                
                # client
                else:
                    data = sckt.recv(1024)

                    # data to be received
                    if data:
                        # put data in the queue
                        self.MESSAGES[sckt].put(data)

                        if sckt not in self.OUTPUTS:
                            self.OUTPUTS.append()

                    # no more data = close connection
                    else: 
                        # Log connection closing
                        print(str(datetime.datetime.now()) + "Closed connection: " + str(sckt))

                        # remove from outputs
                        if sckt in self.OUTPUTS:
                            self.OUTPUTS.remove(sckt)
                        
                        # remove from inputs
                        self.INPUTS.remove(sckt)

                        # remove from message queue
                        del self.MESSAGES[sckt]

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
        return

# run
if __name__ == "__main__":
    svr = Server()
    svr.setup()

    while True:
        svr.run()