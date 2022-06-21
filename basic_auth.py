#!/usr/bin/env python3

##### IMPORTS

#Karmvir Singh Dhaliwal
#30025474
#A2 Q9
import argparse
from multiprocessing import Process
from sys import exit
from time import sleep

# Insert your imports here
import socket
import os
import sympy
import secrets
from cryptography.hazmat.primitives import hashes
##### METHODS

def split_ip_port( string ):
    """Split the given string into an IP address and port number.
    
    PARAMETERS
    ==========
    string: A string of the form IP:PORT.

    RETURNS
    =======
    If successful, a tuple of the form (IP,PORT), where IP is a 
      string and PORT is a number. Otherwise, returns None.
    """

    assert type(string) == str

    try:
        idx = string.index(':')
        return (string[:idx], int(string[idx+1:]))
    except:
        return None

def int_to_bytes( value, length ):
    """Convert the given integer into a bytes object with the specified
       number of bits. Uses network byte order.

    PARAMETERS
    ==========
    value: An int to be converted.
    length: The number of bytes this number occupies.

    RETURNS
    =======
    A bytes object representing the integer.
    """
    
    assert type(value) == int
    assert length > 0

    return value.to_bytes( length, 'big' )

def bytes_to_int( value ):
    """Convert the given bytes object into an integer. Uses network
       byte order.

    PARAMETERS
    ==========
    value: An bytes object to be converted.

    RETURNS
    =======
    An integer representing the bytes object.
    """
    
    assert type(value) == bytes
    return int.from_bytes( value, 'big' )

def create_socket( ip, port, listen=False ):
    """Create a TCP/IP socket at the specified port, and do the setup
       necessary to turn it into a connecting or receiving socket. Do
       not actually send or receive data here!

    PARAMETERS
    ==========
    ip: A string representing the IP address to connect/bind to.
    port: An integer representing the port to connect/bind to.
    listen: A boolean that flags whether or not to set the socket up
       for connecting or receiving.

    RETURNS
    =======
    If successful, a socket object that's been prepared according to 
       the instructions. Otherwise, return None.
    """
    
    assert type(ip) == str
    assert type(port) == int

    if(listen == False): #setting up a connecting socket, rest of the code essentially follows from tutorial
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip,port))
            return sock
        except socket.error as err:
            return None
    else: #setting up a receiving socket, rest of the code essentially follows from tutorial
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((ip, port))
            sock.listen()
            return sock
        except socket.error as err:
            return None

def send( sock, data ):
    """Send the provided data across the given socket. This is a
       'reliable' send, in the sense that the function retries sending
       until either a) all data has been sent, or b) the socket 
       closes.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    data: A bytes object containing the data to send.

    RETURNS
    =======
    The number of bytes sent. If this value is less than len(data),
       the socket is dead and a new one must be created, plus an unknown
       amount of the data was transmitted.
    """
    
    assert type(sock) == socket.socket
    assert type(data) == bytes

    try:
        sent_bytes = sock.send(data) #try to send the bytes, return how many bytes were sent 
        #if(sent_bytes != len(data)):
            #return 0
        #else:
        return sent_bytes
    except socket.error as err: #catching any errors that occur and just returning 0
        return 0

def receive( sock, length ):
    """Receive the provided data across the given socket. This is a
       'reliable' receive, in the sense that the function never returns
       until either a) the specified number of bytes was received, or b) 
       the socket closes. Never returning is an option.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    length: A positive integer representing the number of bytes to receive.

    RETURNS
    =======
    A bytes object containing the received data. If this value is less than 
       length, the socket is dead and a new one must be created.
    """
    
    assert type(sock) == socket.socket
    assert length > 0

    try:
        s = sock.recv(length) #trying to receive the correct number of bytes
        
        if(len(s) == length): 
            return s #if we receive the correct number of bytes return the received bytes
        else:
            return b'' #in all other cases return an empty byte string
    except socket.error as err:
        return b''


def safe_prime( bits=512 ):
    """Generate a safe prime that is at least 'bits' bits long. The result
       should be greater than 1 << (bits-1).

    PARAMETERS
    ==========
    bits: An integer representing the number of bits in the safe prime.
       Must be greater than 1.

    RETURNS
    =======
    An interger matching the spec.
    """

    assert bits > 1
    
    
    while(True): #creating an infinite loop that will end once we find an int matching spec 
        x = secrets.randbits(bits) #generating a random integer that is 'bits' long
        
        prime = sympy.nextprime(x) #getting the next prime value after the random int
        
        p = (2*prime)+1 #calculating what should be our safe prime 
        
        if(p.bit_length() != bits): #if the bit length of what were testing is the incorrect bit length required
            
            continue #simply continue onto the next iteration of the loop

        elif(p.bit_length() == bits): #if the bit length is what we need 

            p1 = sympy.isprime(p) #test if the number were testing is a prime 

            if(p1 == True):
                
                return p #if it is a prime, return it

            elif(p1 == False):

                continue #if it isnt a prime start over and try again!

def prim_root( N ):
    """Find a primitive root for N, a large safe prime. Hint: it isn't
       always 2.

    PARAMETERS
    ==========
    N: The prime in question. May be an integer or bytes object.

    RETURNS
    =======
    An integer representing the primitive root. Must be a positive
       number greater than 1.
    """


    if(isinstance(N,bytes)):

        N = bytes_to_int(N) #setting N to an int if it is a bytes object

    less1 = N-1 #p-1 as needed for the prime root calculation

    factors = sympy.primefactors(less1) #getting the factors of p-1, we know they are 2 and q b/c N is a safe prime

    firstfactor = factors[0] #retreiving the first factor from the factor list 
    secondfactor = factors[1] #same as above but second factor

    for i in range(2,100): #from class we know that almost always either 2,3,5,7 will be a prime root, i loop to 100 just to be safe

        k = pow(i,firstfactor,N) #calculating (p-1)/q for each q(prime factor), again we know the only 2 q values are 2 and 'q' 
        j = pow(i,secondfactor,N) #would b redundant to actually perform (p-1)/q for each q b/c we know the prime factors are 2 and q, dividing (p-1) by one of them will just give u the other one

        if((k != 1) and (j != 1)): #if neither return 1 we know i is a prim root by the prim root test
            return i
        elif((k == 1) or (j == 1)): #if either of them are 1 try again with the next i
            continue

        

def calc_x( s, pw ):
    """Calculate the value of x, according to the assignment.

    PARAMETERS
    ==========
    s: The salt to use. A bytes object consisting of 16 bytes.
    pw: The password to use, as a string.

    RETURNS
    =======
    An integer representing x.
    """

    assert type(pw) == str

    pwbytes = pw.encode('utf-8') #getting the bytes of the password b/c the hash function uses bytes
    tohash = s+pwbytes #concating salt to the front of the pwrd

    digest = hashes.Hash(hashes.SHA256()) #hashing the same we do in A1, just using sha256 instead of sha224 as required
    digest.update(tohash)
    d = digest.finalize()
    k = bytes_to_int(d) #we need to return an int so change the hashed bytes to an int using the proided helper function

    return k

def calc_A( N, g, a ):
    """Calculate the value of A, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    g: A primitive root of N. Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing A.
    """
    if(isinstance(N,bytes)): #testing if N, g and a are ints, changing them to ints if not

        N = bytes_to_int(N)

    if(isinstance(g,bytes)):

        g = bytes_to_int(g)
    if(isinstance(a,bytes)):

        a = bytes_to_int(a)

    A = pow(g,a,N) #pow does g^a mod N, which is exactly what we need 
    return A

def calc_B( N, g, b, k, v ):
    """Calculate the value of B, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    g: A primitive root of N. Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing B.
    """
    if(isinstance(N,bytes)): #testing if inputs are ints as before 

        N = bytes_to_int(N)

    if(isinstance(g,bytes)):

        g = bytes_to_int(g)

    if(isinstance(b,bytes)):

        b = bytes_to_int(b)

    if(isinstance(k,bytes)):

        k = bytes_to_int(k)

    if(isinstance(v,bytes)):

        v = bytes_to_int(v)

    kv = ((k * v) % N) #by modular arithmetic rules we know B+kv mod N is equiv to B mod N + kv mod N, so calculating kv mod N for later use
    b1 = pow(g,b,N) 
    
    B = ((kv+b1) % N)  #as explained above doing the necessary modular arithmetic 
    return B



    

def calc_u( A, B ):
    """Calculate the value of u, according to the assignment.

    PARAMETERS
    ==========
    N: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing u.
    """

    if(isinstance(A,int)): #testing if inputs are bytes and changing to bytes if they arent, since hashing takes in bytes

        A = int_to_bytes(A,64)

    if(isinstance(B,int)):

        B = int_to_bytes(B,64)
    
    tohash = A+B #concating a and b as required
    digest = hashes.Hash(hashes.SHA256()) #hashing same way as before
    digest.update(tohash)
    d = digest.finalize()
    u = bytes_to_int(d) #return needs to be an int

    return u

    

def calc_K_client( N, B, k, v, a, u, x ):
    """Calculate the value of K_client, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.
    x: See calc_x(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_client.
    """

    if(isinstance(N,bytes)): #testing if inputs are bytes, changing them to ints if they are 

        N = bytes_to_int(N)

    if(isinstance(B,bytes)):

        B = bytes_to_int(B)
    
    if(isinstance(k,bytes)):

        k = bytes_to_int(k)
    
    if(isinstance(v,bytes)):

        v = bytes_to_int(v)

    if(isinstance(a,bytes)):

        a = bytes_to_int(a)

    if(isinstance(u,bytes)):

        u = bytes_to_int(u)

    if(isinstance(x,bytes)):

        x = bytes_to_int(x)

    kv = k * v #necessary calculations as given in the function requirements
    base = B - kv
    ux = u * x
    power = a+ux
    K = pow(base,power,N)
    return K

def calc_K_server( N, A, b, v, u ):
    """Calculate the value of K_server, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    A: See calc_A(). Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_server.
    """
    if(isinstance(N,bytes)): #testing if inputs are ints, changing them to ints if they arent

       N = bytes_to_int(N)
    
    if(isinstance(A,bytes)):

        A = bytes_to_int(A)
    
    if(isinstance(b,bytes)):

        b = bytes_to_int(b)
    
    if(isinstance(v,bytes)):

        v = bytes_to_int(v)

    if(isinstance(u,bytes)):

        u = bytes_to_int(u)

    tomult = pow(v,u,N) #by modular arithmetic rules, a*b mod N = a mod N * b mod N,  so calculating our 'b' value as required
    base = A * tomult #calculating the base 
    K = pow(base,b,N) 

    return K

    

def calc_M1( A, B, K_client ):
    """Calculate the value of M1, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.
    K_client: See calc_K_client(). Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing M1.
    """

    if(isinstance(A,int)): #checking if inputs are bytes and changing them if they arent

        A = int_to_bytes(A,64)
    
    if(isinstance(B,int)):

        B = int_to_bytes(B,64)

    if(isinstance(K_client,int)):

        K_client = int_to_bytes(K_client,64)

    tohash = A+B+K_client #hashing same as before 
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tohash)
    d = digest.finalize()
    
    return d #returning hashed bytes as opposed to int before


def calc_M2( A, M1, K_server ):
    """Calculate the value of M2, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    M1: See calc_M1(). Could be an integer or bytes object.
    K_server: See calc_K_server(). Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing M2.
    """

    if(isinstance(A,int)): #checking if inputs are bytes changing them if they arent

        A = int_to_bytes(A,64)

    if(isinstance(M1,int)):

        M1 = int_to_bytes(M1,32)

    if(isinstance(K_server,int)):

        K_server = int_to_bytes(K_server,64)

    tohash = A+M1+K_server #hashing as before
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tohash)
    d = digest.finalize()
    
    return d
    
def client_prepare():
    """Do the preparations necessary to connect to the server. Basically,
       just generate a salt.

    RETURNS
    =======
    A bytes object containing a randomly-generated salt, 16 bytes long.
    """

    salt = os.urandom(16) #generating a random 16 bytes to be used as a salt 
    return salt

def server_prepare():
    """Do the preparations necessary to accept clients. Generate N and g,
       and compute k.

    RETURNS
    =======
    A tuple of the form (N, g, k), containing those values as integers.
    """

    N = safe_prime() #finding a random safe prime
    g = prim_root(N) #finding a prim root of that prime


    nbytes = int_to_bytes(N,64) #changing the ints to bytes for hashing 
    gbytes = int_to_bytes(g,64)

    tohash = nbytes+gbytes #concating as required

    digest = hashes.Hash(hashes.SHA256()) #hashing same as before 
    digest.update(tohash)
    d = digest.finalize()
    k = bytes_to_int(d)

    return (N,g,k) #return the tuple we need 
    




def client_register( ip, port, username, pw, s ):
    """Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'r'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long.

    RETURNS
    =======
    If successful, return a tuple of the form (N, g, v), all integers.
       On failure, return None.
    """

    # delete this comment and insert your code here

def server_register( sock, N, g, database ):
    """Handle the server's side of the registration. IMPORTANT: reading the
       initial 'r' has been handled for you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If the registration process was successful, return an updated version of the
       database. If it was not, return None. NOTE: a username that tries to
       re-register with a different salt and password is likely malicious,
       and should therefore count as an unsuccessful registration that doesn't
       modify the user database.
    """

    # delete this comment and insert your code here

def client_protocol( ip, port, N, g, username, pw, s ):
    """Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'p'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long. Must match what the server 
       sends back.

    RETURNS
    =======
    If successful, return a tuple of the form (a, K_client), where both a and 
       K_client are integers. If not, return None.
    """

    # delete this comment and insert your code here

def server_protocol( sock, N, g, database ):
    """Handle the server's side of the consensus protocal. 
       IMPORTANT: reading the initial 'p' has been handled for 
       you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If successful, return a tuple of the form (username, b, K_server), where both b and 
       K_server are integers while username is a string. If not, return None.
    """

    # delete this comment and insert your code here


##### MAIN

if __name__ == '__main__':

    # parse the command line args
    cmdline = argparse.ArgumentParser( description="Test out a secure key exchange algorithm." )

    methods = cmdline.add_argument_group( 'ACTIONS', "The three actions this program can do." )

    methods.add_argument( '--client', metavar='IP:port', type=str, \
        help='Perform registration and the protocol on the given IP address and port.' )
    methods.add_argument( '--server', metavar='IP:port', type=str, \
        help='Launch the server on the given IP address and port.' )
    methods.add_argument( '--quit', metavar='IP:port', type=str, \
        help='Tell the server on the given IP address and port to quit.' )

    methods = cmdline.add_argument_group( 'OPTIONS', "Modify the defaults used for the above actions." )

    methods.add_argument( '--username', metavar='NAME', type=str, default="admin", \
        help='The username the client sends to the server.' )
    methods.add_argument( '--password', metavar='PASSWORD', type=str, default="swordfish", \
        help='The password the client sends to the server.' )
    methods.add_argument( '--salt', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='A specific salt for the client to use, stored as a file. Randomly generated if not given.' )
    methods.add_argument( '--timeout', metavar='SECONDS', type=int, default=600, \
        help='How long until the program automatically quits. Negative or zero disables this.' )
    methods.add_argument( '-v', '--verbose', action='store_true', \
        help="Be more verbose about what is happening." )

    args = cmdline.parse_args()

    # handle the salt
    if args.salt:
        salt = args.salt.read( 16 )
    else:
        salt = client_prepare()

    if args.verbose:
        print( f"Program: Using salt <{salt.hex()}>" )
    
    # first off, do we have a timeout?
    killer = None           # save this for later
    if args.timeout > 0:

        # define a handler
        def shutdown( time, verbose=False ):

            sleep( time )
            if verbose:
                print( "Program: exiting after timeout.", flush=True )

            return # optional, but I like having an explicit return

        # launch it
        if args.verbose:
            print( "Program: Launching background timeout.", flush=True )
        killer = Process( target=shutdown, args=(args.timeout,args.verbose) )
        killer.daemon = True
        killer.start()

    # next off, are we launching the server?
    result      = None     # pre-declare this to allow for cascading

    server_proc = None
    if args.server:
        if args.verbose:
            print( "Program: Attempting to launch server.", flush=True )
        result = split_ip_port( args.server )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Server: Asked to start on IP {IP} and port {port}.", flush=True )
            print( f"Server: Generating N and g, this will take some time.", flush=True )
        N, g, k = server_prepare() 
        if args.verbose:
            print( f"Server: Finished generating N and g.", flush=True )

        # use an inline routine as this doesn't have to be globally visible
        def server_loop( IP, port, N, g, k, verbose=False ):
            
            database = dict()           # for tracking registered users

            sock = create_socket( IP, port, listen=True )
            if sock is None:
                if verbose:
                    print( f"Server: Could not create socket, exiting.", flush=True )
                return

            if verbose:
                print( f"Server: Beginning connection loop.", flush=True )
            while True:

                (client, client_address) = sock.accept()
                if verbose:
                    print( f"Server: Got connection from {client_address}.", flush=True )

                mode = receive( client, 1 )
                if len(mode) != 1:
                    if verbose:
                        print( f"Server: Socket error with client, closing it and waiting for another connection.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    continue

                if mode == b'q':
                    if verbose:
                        print( f"Server: Asked to quit by client. Shutting down.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return

                elif mode == b'r':
                    if verbose:
                        print( f"Server: Asked to register by client.", flush=True )

                    temp = server_register( client, N, g, database )
                    if (temp is None) and verbose:
                            print( f"Server: Registration failed, closing socket and waiting for another connection.", flush=True )
                    elif temp is not None:
                        if verbose:
                            print( f"Server: Registration complete, current users: {[x for x in temp]}.", flush=True )
                        database = temp

                elif mode == b'p':
                    if verbose:
                        print( f"Server: Asked to generate shared secret by client.", flush=True )

                    temp = server_protocol( client, N, g, database )
                    if (temp is None) and verbose:
                            print( f"Server: Protocol failed, closing socket and waiting for another connection.", flush=True )
                    elif type(temp) == tuple:
                        if verbose:
                            print( f"Server: Protocol complete, negotiated shared key for {temp[0]}.", flush=True )
                            print( f"Server:  Shared key is {temp[2]}.", flush=True )

                # clean up is done inside the functions
                # loop back

        # launch the server
        if args.verbose:
            print( "Program: Launching server.", flush=True )
        p = Process( target=server_loop, args=(IP, port, N, g, k, args.verbose) )
        p.daemon = True
        p.start()
        server_proc = p

    # finally, check if we're launching the client
    result      = None     # clean this up

    client_proc = None
    if args.client:
        if args.verbose:
            print( "Program: Attempting to launch client.", flush=True )
        result = split_ip_port( args.client )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Client: Asked to connect to IP {IP} and port {port}.", flush=True )
        # another inline routine
        def client_routine( IP, port, username, pw, s, verbose=False ):

            if verbose:
                print( f"Client: Beginning registration.", flush=True )

            results = client_register( IP, port, username, pw, s )
            if results is None:
                if verbose:
                    print( f"Client: Registration failed, not attempting the protocol.", flush=True )
                return
            else:
                N, g, v = results
                if verbose:
                    print( f"Client: Registration successful, g = {g}.", flush=True )

            if verbose:
                print( f"Client: Beginning the shared-key protocol.", flush=True )

            results = client_protocol( IP, port, N, g, username, pw, s )
            if results is None:
                if verbose:
                    print( f"Client: Protocol failed.", flush=True )
            else:
                a, K_client = results
                if verbose:
                    print( f"Client: Protocol successful.", flush=True )
                    print( f"Client:  K_client = {K_client}.", flush=True )

            return

        # launch the server
        if args.verbose:
            print( "Program: Launching client.", flush=True )
        p = Process( target=client_routine, args=(IP, port, args.username, args.password, salt, args.verbose) )
        p.daemon = True
        p.start()
        client_proc = p
        

    # finally, the quitting routine
    result      = None     # clean this up

    if args.quit:
        # defer on the killing portion, in case the client is active
        result = split_ip_port( args.quit )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Quit: Asked to connect to IP {IP} and port {port}.", flush=True )
        if client_proc is not None:
            if args.verbose:
                print( f"Quit: Waiting for the client to complete first.", flush=True )
            client_proc.join()

        if args.verbose:
            print( "Quit: Attempting to kill the server.", flush=True )

        # no need for multiprocessing here
        sock = create_socket( IP, port )
        if sock is None:
            if args.verbose:
                print( f"Quit: Could not connect to the server to send the kill signal.", flush=True )
        else:
            count = send( sock, b'q' )
            if count != 1:
                if args.verbose:
                    print( f"Quit: Socket error when sending the signal.", flush=True )
            elif args.verbose:
                    print( f"Quit: Signal sent successfully.", flush=True )

            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    # finally, we wait until we're told to kill ourselves off, or both the client and server are done
    while not ((server_proc is None) and (client_proc is None)):

        if not killer.is_alive():
            if args.verbose:
                print( f"Program: Timeout reached, so exiting.", flush=True )
            if client_proc is not None:
                client_proc.terminate()
            if server_proc is not None:
                server_proc.terminate()
            exit()

        if (client_proc is not None) and (not client_proc.is_alive()):
            if args.verbose:
                print( f"Program: Client terminated.", flush=True )
            client_proc = None
        
        if (server_proc is not None) and (not server_proc.is_alive()):
            if args.verbose:
                print( f"Program: Server terminated.", flush=True )
            server_proc = None

#    exit()

