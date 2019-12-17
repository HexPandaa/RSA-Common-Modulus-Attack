# RSA-Common-Modulus-Attack

## Introduction

**RSA-Common-Modulus-Attack** is a Python 3 script to perform common modulus attacks on RSA. Given two ciphertext, encrypted with the same modulus `N`, but a different exponent `e`, it is possible to recover the plaintext of the message.
In order for this attack to work, the greatest common denominator of the two exponent should be 1 : `gcd(e1, e2) = 1`.

You can read more about this attack at https://medium.com/bugbountywriteup/rsa-attacks-common-modulus-7bdb34f331a5

I relied on [Ashutosh Ahelleya](https://github.com/ashutosh1206)'s script for the math part : https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Common-Modulus/exploit.py



## Installation

In order to run this script, you'll need to install some Python 3 modules.

```bash
git clone https://github.com/HexPandaa/RSA-Common-Modulus-Attack.git
cd RSA-Common-Modulus-Attack
pip3 install -r requirements.txt
```



## Usage

To run the script, simply type the following command.

```bash
python3 rsa-cm.py -c1 <ciphertext1> -c2 <ciphertext2> -k1 <publickey1> -k2 <publickey2>
```

The output should be like so :

```bash
# ./rsa-cm.py -c1 message1.b64 -c2 message2.b64 -k1 key1.pub.pem -k2 key2.pub.pem 
[+] Recovered message:
6277601[...]
[+] Recovered bytes:
b'Yeah man[...]'
```



And finally the help message.

```bash
# rsa-cm.py -h
usage: rsa-cm.py [-h] -c1 ciphertext1 -c2 ciphertext2 -k1 pubkey1 -k2 pubkey2
                 [-o outfile]

A simple script to perform RSA common modulus attacks.

optional arguments:
  -h, --help       show this help message and exit
  -c1 ciphertext1  The first ciphered message
  -c2 ciphertext2  The second ciphered message
  -k1 pubkey1      The first public key
  -k2 pubkey2      The second public key
  -o outfile       Output file

More info at https://github.com/HexPandaa/RSA-Common-Modulus-Attack/
```



**Happy hacking!**

