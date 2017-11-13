#+TITLE: CPSC 526 Assignment #2 Tutorial 2
#+AUTHOR: Edel Altares 10098725

* Backdoor
This program can be installed on a server and manipulate the server when a client connects to it.

* How to Run
Download all the files and run:
$ python3 backdoor.py <port>

* How to Connect
Using nc, run the following command:
$ nc localhost <port>

* Handshake details
To gain access to the backdoor, the password 'CPSC526' must be entered. Entering a wrong password will result in disconnecting.

* Supported Commands
+ pwd: show current working directory
+ cd <dir>: change current working directory to <dir>
+ ls: list the contents of the current working directory, use single quotes to escape for both arguments
+ cp <file1> <file2>: copy file1 to file2, use single quotes to escape for both arguments
+ mv <file1> <file2>: move file1 to file2, use single quotes to escable for both arguments
+ rm <file>: remove <file>, use single quotes to escape
+ cat <file>: show contents of the file, use single quotes to escape
+ snap: take snapshot of all files in current directory
+ diff: compare current directory to the snaved snapshot
+ help [cmd]: show help on commands
+ logname: show username
+ cal: show calendar
+ logout: disconnect from server
+ off: terminate the backdoor11111111111