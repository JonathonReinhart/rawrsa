#!/bin/bash
set -e

EXP=65537

scons
./generate_rsa_key.py -e $EXP

# Reconstruct public key
./rawrsa -e $EXP pubmod.bin > public_out.pem

# Reconstruct expanded private key
./rawrsa -e $EXP --privexp privexp.bin --expand pubmod.bin > private_out.pem

# Compare
md5sum *.pem

diff public.pem public_out.pem
echo "Reconstructed public key matches generated PEM!"

diff private.pem private_out.pem
echo "Reconstructed private key matches generated PEM!"
