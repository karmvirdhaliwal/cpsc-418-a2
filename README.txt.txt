Karmvir Singh Dhaliwal
30025474
CPSC 418 
A2 Q9


I am submitting 1 file, the file basic_auth.py. This program goes through the various steps of implementing a secure password based authentication and key exchange. 

The functions I have implemented are: create_socket, send, receive, safe_prime, prim_root, calc_x, calc_A, calc_B, calc_u, calc_K_client, calc_K_server, calc_M1, calc_M2, client_prepare, and server_prepare. There are no known bugs in these implemented functions.

The functions I have not implemented are: client_register, server_register, client_protocol and server_protocol.


To generate a safe prime N i have used the following procedure:
- 1. generate a random number x that is the correct length based on the input bits, using the secrets library
- 2. using the sympy library, get the next prime after x, we'll call this y.
- 3. calculate p = 2y+1
- 4. First, test to see if p is the correct bit length, if it is not, restart from step 1
- 5. If p passes the first test, next check to see if p is prime using sympys isprime method, again if it is not restart from step 1
- 6. If p is prime, we have found a safe prime of the correct bit length so return p

This is done using an infinite while loop; when we have found a prime p and return is called the while loop will break, but while a prime hasnt been found it will continue to loop.

To find a primitive root g of a safe prime N I have used the following procedure:
- 1. calculate p = N-1
- 2. get the prime factors of this value using sympy.primefactors; since we know N is a safe prime and safe primes have the form 2q+1 where q is a prime, we know the prime factors pf p will be 2 and q
- 3. we then begin a for loop from i=2 to 100, we know from class that most of the time 2,3,5, or 7 will be a prime root, but we loop to 100 just to be safe
- 4. calculate i^(p-1)/q mod N where q are the prime factors of (p-1). Since we know the only two prime factors are 2 and 'q', we can avoid this division as itll lead to redundancy, dividing (p-1) by one prime factor will just give you the other prime factor. So, we really just calculate i^q mod N for each prime factor q.
- 5. check to see if any of the i^q mod N calculations are equivalent to 1. If they are, we have not found a prime root so we must increment i and repeat steps 4 and 5. If none of the i^q mod N calculations are equivalent to 1, we have found a prime root so simple return the root.

Essentially, I am implementing the prime root test we learned in class using a for loop. if a value i passes this prime root test, return it as a prime root, if it doesnt simply increment i and go through the test with the new i.