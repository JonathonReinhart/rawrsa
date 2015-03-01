# rawrsa
Create PEM-encoded RSA pubilc key from raw modulus / exponent.

Inspired by: http://stackoverflow.com/questions/28770426/

### Building

`rawrsa` uses Scons for its build system:

```
$ scons -Q
gcc -o main.o -c -Wall -Werror -g main.c
gcc -o rawrsa main.o -lcrypto
```

### Usage

```
Usage:
 rawrsa [options] <modulus-file>

Options:
 -e, --exponent EXP  Exponent, defaults to 65537

$ hexdump 128.key 
0000000 e36e b0ac 4a68 d9f2 689d 1e43 1c41 0179
0000010 e170 1526 3772 87ad 5fb6 a18b a6a5 a9e3
0000020 923f 80e6 f251 ec34 1de0 7650 b4f2 44d3
0000030 8cd4 32c3 76bf 5cc5 8aac af08 665c ca7a
0000040 33c1 5527 dab8 f2cd ae90 e510 d8e1 2f44
0000050 3a8f 5221 e34b 082d a123 206c 3e83 4a3d
0000060 419e 2409 9fa7 3f7c 7ba5 b369 6236 06ef
0000070 e053 7426 f616 789b a807 dd37 78a3 9ce3
0000080

$ ./rawrsa -e 65537 128.key  | openssl rsa -pubin -text
Public-Key: (1023 bit)
Modulus:
    6e:e3:ac:b0:68:4a:f2:d9:9d:68:43:1e:41:1c:79:
    01:70:e1:26:15:72:37:ad:87:b6:5f:8b:a1:a5:a6:
    e3:a9:3f:92:e6:80:51:f2:34:ec:e0:1d:50:76:f2:
    b4:d3:44:d4:8c:c3:32:bf:76:c5:5c:ac:8a:08:af:
    5c:66:7a:ca:c1:33:27:55:b8:da:cd:f2:90:ae:10:
    e5:e1:d8:44:2f:8f:3a:21:52:4b:e3:2d:08:23:a1:
    6c:20:83:3e:3d:4a:9e:41:09:24:a7:9f:7c:3f:a5:
    7b:69:b3:36:62:ef:06:53:e0:26:74:16:f6:9b:78:
    07:a8:37:dd:a3:78:e3:9c
Exponent: 65537 (0x10001)
writing RSA key
-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG7jrLBoSvLZnWhDHkEceQFw4SYV
cjeth7Zfi6GlpuOpP5LmgFHyNOzgHVB28rTTRNSMwzK/dsVcrIoIr1xmesrBMydV
uNrN8pCuEOXh2EQvjzohUkvjLQgjoWwggz49Sp5BCSSnn3w/pXtpszZi7wZT4CZ0
FvabeAeoN92jeOOcAgMBAAE=
-----END PUBLIC KEY-----

```
