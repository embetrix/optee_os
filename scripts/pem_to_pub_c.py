#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2015, Linaro Limited

# SHA-256 of the DER encoded publicly known public key of development keys
# For a PEM private key it can be computed with:
#   openssl pkey -in <key.pem> -pubout -outform DER | sha256sum
DEV_KEY_SHA256 = {
    # keys/default.pem (keys/default_ta.pem) RSA 4096
    'cac7bcfaf8674a57e5eaa8ef1a7c9b67af1fd5562a06440d88d5e3c632e88c48',
    # keys/default_ecdsa.pem ECDSA NIST P-256
    '488e6f02c7296b6aa522ab71b539e00d4fb1ff4ae2683e35bddbb2d66a4c12e3',
}


def get_args():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--prefix', required=True,
        help='Prefix for the public key exponent and modulus in c file')
    parser.add_argument(
        '--out', required=True,
        help='Name of c file for the public key')
    parser.add_argument('--key', required=True, help='Name of key file')
    parser.add_argument(
        '--dev-key-check', choices=['warn', 'error'],
        help='Warn or fail if the key is a publicly known development key')

    return parser.parse_args()


def load_public_key(path):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    with open(path, 'rb') as f:
        data = f.read()

    try:
        key = serialization.load_pem_private_key(data, password=None,
                                                 backend=default_backend())
        return key.public_key()
    except ValueError:
        return serialization.load_pem_public_key(data,
                                                 backend=default_backend())


def is_dev_key(key):
    import hashlib
    from cryptography.hazmat.primitives import serialization

    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest() in DEV_KEY_SHA256


def main():
    import array
    import sys

    args = get_args()

    key = load_public_key(args.key)

    if args.dev_key_check and is_dev_key(key):
        msg = ('{} is a publicly known development key, anyone can sign '
               'binaries that will pass verification'.format(args.key))
        if args.dev_key_check == 'error':
            sys.exit('ERROR: ' + msg + '. Provide a private key and/or '
                     'set CFG_INSECURE=y.')
        print('WARNING: ' + msg + '.', file=sys.stderr)

    # Refuse public exponent with more than 32 bits. Otherwise the C
    # compiler may simply truncate the value and proceed.
    # This will lead to TAs seemingly having invalid signatures with a
    # possible security issue for any e = k*2^32 + 1 (for any integer k).
    if key.public_numbers().e > 0xffffffff:
        raise ValueError(
            'Unsupported large public exponent detected. ' +
            'OP-TEE handles only public exponents up to 2^32 - 1.')

    with open(args.out, 'w') as f:
        f.write("#include <stdint.h>\n")
        f.write("#include <stddef.h>\n\n")
        f.write("const uint32_t " + args.prefix + "_exponent = " +
                str(key.public_numbers().e) + ";\n\n")
        f.write("const uint8_t " + args.prefix + "_modulus[] = {\n")
        i = 0
        nbuf = key.public_numbers().n.to_bytes(key.key_size >> 3, 'big')
        for x in array.array("B", nbuf):
            f.write("0x" + '{0:02x}'.format(x) + ",")
            i = i + 1
            if i % 8 == 0:
                f.write("\n")
            else:
                f.write(" ")
        f.write("};\n")
        f.write("const size_t " + args.prefix + "_modulus_size = sizeof(" +
                args.prefix + "_modulus);\n")


if __name__ == "__main__":
    main()
