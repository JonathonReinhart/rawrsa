#!/usr/bin/env python3

# Adapted from:
# https://gist.github.com/ostinelli/aeebf4643b7a531c248a353cee8b9461

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def parse_args():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('-s', '--size', dest='key_size', type=int, default=2048,
            help="Key size (default 2048)")
    ap.add_argument('-e', '--exp', dest='public_exp', type=int, default=65537,
            help="Public exponent (default 65537)")
    return ap.parse_args()


def main():
    args = parse_args()

    print(f"Generating key ({args.key_size} bits)")
    private_key = rsa.generate_private_key(
            public_exponent=args.public_exp,
            key_size=args.key_size,
            backend=default_backend(),
            )

    privnums = private_key.private_numbers()
    pubnums = privnums.public_numbers

    print(f"d: {privnums.d}")
    print(f"e: {pubnums.e}")
    print(f"n: {pubnums.n}")

    # Write raw binary bignum files
    def write_bn(path, bn):
        with open(path, 'wb') as f:
            f.write(bn.to_bytes(args.key_size//8, 'big'))

    path = "pubmod.bin"
    write_bn(path, pubnums.n)
    print(f"Raw bublic modulus (n) written to {path}")

    path = "privexp.bin"
    write_bn(path, privnums.d)
    print(f"Raw private exponent (d) written to {path}")

    def save_file(filename, content):
        with open(filename, 'wb') as f:
            f.write(content)

    # Write PEM private key
    pem = private_key.private_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PrivateFormat.TraditionalOpenSSL,
	encryption_algorithm=serialization.NoEncryption()
    )
    path = "private.pem"
    save_file(path, pem)
    print(f"Private key written to {path}")

    # generate public key
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = "public.pem"
    save_file(path, pem)
    print(f"Public key written to {path}")


if __name__ == '__main__':
    main()
