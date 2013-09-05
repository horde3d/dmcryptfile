Encrypts/decrypts file in dm-crypt compatible way, using kernel crypto API.
Copyright (c) 2013 Maxim Radugin.

Usage: dmcryptfile <arguments>

This utility is designed to encrypt disk/partition image files in userspace
without root priviledges and without using device mapper and cryptsetup.
Currently supports only plain mode, no LUKS support!
Backend code is taken from cryptsetup.
Input key size should be of desired cipher key size.
Key is passed directly to the cipher algorithm, no hashing or any other
processing is performed. It is up to the user to provide strong key.
For available ciphers, chain modes and key sizes check /proc/crypto.
Only plain IV mode is supported.
Input file size must be multiple of sector size i.e. 512 bytes.
If input file is not multiple of sector size, output will be truncated.

