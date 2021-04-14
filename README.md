# rawrsa
![Build and Test badge](https://github.com/JonathonReinhart/rawrsa/actions/workflows/build-test.yml/badge.svg)

Create PEM-encoded RSA public key from raw modulus and public exponent.
Optionally create an RSA private key by supplying a raw private exponent.

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
 -e, --exponent EXP    Exponent, defaults to 65537
 -p, --privexp  FILE   Private exponent bignum file

If --privexp is given, output format is a private key.
```

Example:
```
$ xxd -p raw.key
6ee3acb0684af2d99d68431e411c790170e126157237ad87b65f8ba1a5a6
e3a93f92e68051f234ece01d5076f2b4d344d48cc332bf76c55cac8a08af
5c667acac1332755b8dacdf290ae10e5e1d8442f8f3a21524be32d0823a1
6c20833e3d4a9e410924a79f7c3fa57b69b33662ef0653e0267416f69b78
07a837dda378e39c

$ ./rawrsa -e 65537 raw.key  | openssl rsa -pubin -text
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

See test.sh for advanced usage and test.
