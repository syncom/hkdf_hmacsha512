[![Build Status](https://github.com/syncom/hkdf_hmacsha512/actions/workflows/build.yml/badge.svg)]

# hkdf_hmacsha512: HKDF-HMACSHA512 (RFC 5869) with libsodium

This is an implementation of HKDF based on HMAC-SHA512, using the
Sodium crypto library's HMAC-SHA512 implementation 
(http://doc.libsodium.org/). Originally wirtten in 2015.

The reference Makefile assumes libsodium is installed in 
/usr/local/lib (and headers in /usr/local/include). 