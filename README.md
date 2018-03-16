# Cryptography-and-security-protocols
Assignment one

**Symmetric Encryption Using Diffie-Hellman Key Agreement**

The aim of this assignment is to perform symmetric encryption using the block cipher AES. Before this encryption can be done, a key must be exchanged with the receiver of the message (me); this will be done using Diffie-Hellman key agreement. The values which you need to know for this exchange are as follows:

The prime modulus p is the following 1024-bit prime (given in hexadecimal):

b59dd795 68817b4b 9f678982 2d22594f 376e6a9a bc024184 6de426e5 dd8f6edd
ef00b465 f38f509b 2b183510 64704fe7 5f012fa3 46c5e2c4 42d7c99e ac79b2bc
8a202c98 327b9681 6cb80426 98ed3734 643c4c05 164e739c b72fba24 f6156b6f
47a7300e f778c378 ea301e11 41a6b25d 48f19242 68c62ee8 dd313474 5cdf7323

The generator g is the following (again in hexadecimal):

44ec9d52 c8f9189e 49cd7c70 253c2eb3 154dd4f0 8467a64a 0267c9de fe4119f2
e373388c fa350a4e 66e432d6 38ccdc58 eb703e31 d4c84e50 398f9f91 677e8864
1a2d2f61 57e2f4ec 538088dc f5940b05 3c622e53 bab0b4e8 4b1465f5 738f5496
64bd7430 961d3e5a 2e7bceb6 2418db74 7386a58f f267a993 9833beef b7a6fd68

My public key A for the Diffie-Hellman key change is given by ga (mod p) where a is my private key. A has the following value:

5af3e806 e0fa466d c75de601 86760516 792b70fd cd72a5b6 238e6f6b 76ece1f1
b38ba4e2 10f61a2b 84ef1b5d c4151e79 9485b217 1fcf318f 86d42616 b8fd8111
d59552e4 b5f228ee 838d535b 4b987f1e af3e5de3 ea0c403a 6c38002b 49eade15
171cb861 b3677324 60e3a984 2b532761 c16218c4 fea51be8 ea024838 5f6bac0d

In order to perform the Diffie-Hellman key exchange, you should do the following:

Generate a random 1023-bit integer; this will be your private key b.
Generate your public key B given by gb (mod p)
Calculate the shared key s given by Ab (mod p)
Now that you have the value of the shared key s, you can use this as the key for your AES encryption. However, this key is too large (1024 bits) to be used directly as the AES key. You should therefore use SHA-256 to produce a 256-bit digest from the shared key s, giving a 256-bit AES key k.

You will then encrypt an input binary file using AES in CBC mode with the 256-bit key k and a block size of 128-bits. The IV for this encryption (i) will be a randomly generated 128-bit value. You will use the following padding scheme (as given in lectures): if the final part of the message is less than the block size, append a 1-bit and fill the rest of the block with 0-bits; if the final part of the message is equal to the block size, then create an extra block starting with a 1-bit and fill the rest of the block with 0-bits.

The implementation language must be Java. You will have to make use of the BigInteger class (java.math.BigInteger), the security libraries (java.security.*) and the crypto libraries (javax.crypto.*). You must not make use of the modular exponentiation method provided by the BigInteger class; all modular exponentiation must be done using one of the two methods described in the lectures. You can however make use of the crypto libraries to perform the AES encryption and the SHA-256 hashing.

Once your implementation is complete, you should create a zip file containing all your code, encrypt this file as described above, and send me the following by email:

Your 1024-bit public key B in hexadecimal.
Your 128-bit IV (i) in hexadecimal.
Your zipped code file which was encrypted.
Your AES encryption of the above zipped code file in hexadecimal.
A declaration that this is solely your own work (except elements that are explicitly attributed to another source).






**Assignemnt two**

**Digital Signature Using RSA**

The aim of this assignment is to implement a digital signature using RSA. Before the digital signature can be implemented, you will need to set up an appropriate public/private RSA key pair. This should be done as follows:

Generate two distinct 512-bit probable primes p and q
Calculate the product of these two primes N = pq
Calculate the Euler totient function phi(N)
You will be using an encryption exponent e = 65537, so you will need to ensure that this is relatively prime to phi(N). If it is not, go back to step 1 and generate new values for p and q
Compute the value for the decryption exponent d, which is the multiplicative inverse of e (mod phi(N)). This should use your own implementation of the extended Euclidean GCD algorithm to calculate the inverse rather than using a library method for this purpose.
You should then write code to implement a decryption method which calculates cd (mod N). You should use your own implementation of the Chinese Remainder Theorem to calculate this more efficiently; this can also make use of your multiplicative inverse implementation.

Once your implementation is complete, you should create a zip file containing all your code and digitally sign a digest of this file as follows:

Generate a 256-bit digest of the zip file using SHA-256.
Apply your decryption method to this digest. Note that for the purpose of this assignment no padding should be added to the digest.
You should send me the following by email:

Your 1024-bit modulus N in hexadecimal.
Your zipped code file.
The digitally signed code digest in hexadecimal.
A declaration that this is solely your own work (except elements that are explicitly attributed to another source).
The implementation language must be Java. You can make use of the BigInteger class (java.math.BigInteger), the security libraries (java.security.*) and the crypto libraries (javax.crypto.*). You must not make use of the multiplicative inverse or GCD methods provided by the BigInteger class; you will need to implement these yourself. You can however make use of the crypto libraries to perform the SHA-256 hashing.
