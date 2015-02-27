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
Usage: rawrsa modulus-file exponent

$ ./rawrsa key.bin 65537
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA9cFHSTQ6h1Ls/vx7B+V/84XVlLxUU1dU1mEr9ROAqWrZtfasvx2E
21lbva+AdJ/B4u6fGVhCEMgekXsRB65CqZfwL3DFL6tqam6GvrOyvZgAlQKrA54w
DaKMT8Kfg2I2K9W/HCkCOHczhuHhjFmeiV9BuQgpmcPcNz6UXBwU05d3g6oM/X4m
lEhEsaH4bqo1qsMX6jp6WnsR13GEfsYoYVmHgEbnKJyGpsoRVW6HQXLHvef9XLEJ
v9n7nLdHToya75svxJ3v9JugD3n6PiC48085/FWb9980o4hmG9iW5rehm4Dlui8c
TDnHkQSrvi9WLlZ+S8hdtwDRN/pVVTjgPAIDAQAB
-----END RSA PUBLIC KEY-----
```
