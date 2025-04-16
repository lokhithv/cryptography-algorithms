Classical Cipher Algorithms in C

This project implements 13 classical encryption and decryption algorithms in the C programming language. It features a user-interactive interface for encrypting and decrypting messages using a variety of traditional cipher techniques.

List of Implemented Ciphers:
1.Caesar Cipher
2.Atbash Cipher
3.August Cipher
4.Affine Cipher
5.Vigenère Cipher
6.Gronsfeld Cipher
7.Beaufort Cipher
8.Autoclave / Running Key Cipher
9.N-Gram Operations (Bigram, Trigram, etc.)
10.Hill Cipher (Supports 2×2 and 3x3 key matrix for encryption and decryption)
11.Rail Fence Cipher
12.Route Cipher
13.Myszkowski Cipher

Features:
Full support for encryption and decryption for all 13 ciphers

User can input:

The plaintext or ciphertext

The cipher type

Required keys/parameters like shift values, key matrices, etc.

Modular code with dedicated functions for each cipher

Hill Cipher implementation supports any n × n key matrix, with matrix inverse calculation for decryption

How It Works:
User selects a cipher by entering a number from 1 to 13

Text input is taken (plaintext for encryption, ciphertext for decryption)

Depending on the selected cipher, the program:

Requests additional parameters (key, shift, matrix, etc.)

Performs encryption and decryption

The encrypted and decrypted output is printed to the screen

Requirements:
C Compiler (like GCC)

Standard C libraries: stdio.h, stdlib.h, string.h, ctype.h, math.h

Compilation & Execution
Compile:
gcc ciphers.c -o ciphers

Run:
gcc ciphers.c -o cipher

ciphers.c -> Main C source file containing all cipher logic

README.txt -> Project documentation (this file)

Notes:
The Hill cipher requires the key matrix to be invertible mod 26. The program checks for this and prompts if the matrix is invalid.

N-Gram operation prints and reorders character pairs/triplets but does not substitute them like modern block ciphers.

For Gronsfeld and Vigenère ciphers, only uppercase alphabets are used for simplicity.

Author:
This project was developed as a comprehensive exercise in classical cryptography and C programming.

License:
This project is open-source and available for use, modification, and distribution for educational or academic purposes.
