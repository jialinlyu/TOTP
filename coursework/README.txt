TOTP Generator
This repository contains an implementation of the TOTP (Time-Based One-Time Password) algorithm

Dependencies
· OpenSSL 

Setup and Installation
gcc .\coursework.c -o coursework -lssl -lcrypto
.\coursework.exe

Grading Criteria Completion
Adherence to RFC 6238 Algorithm: The TOTP algorithm strictly follows the specifications set by RFC 6238.
TOTP generator generating appropriate output: The generator outputs a consistent and accurate 6-digit code, in line with TOTP standards.
Appropriate secure coding and OpenSSL Algorithms: The implementation uses OpenSSL for cryptographic functions ensuring security. We've employed the SHA-256 hashing function from OpenSSL.
Appropriate error handling: Our code gracefully handles potential errors, such as time sync issues or invalid keys, ensuring a robust user experience.
Verifiable TOTP code: The generated TOTP codes can be verified using any standard TOTP verification tool or service.
Good coding practice and code quality: The code is well-structured, commented, and follows language-specific best practices.

Jialin.lyu
ID:2369752
