# hkdf_hmacsha512: HKDF-HMACSHA512 (RFC 5869) with libsodium

[![Build Status](https://github.com/syncom/hkdf_hmacsha512/actions/workflows/build.yml/badge.svg)](https://github.com/syncom/hkdf_hmacsha512/actions/workflows/build.yml)
[![CoddQL](https://github.com/syncom/hkdf_hmacsha512/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/syncom/hkdf_hmacsha512/actions/workflows/codeql-analysis.yml)

This is an implementation of HKDF based on HMAC-SHA512, using the Sodium
crypto library's HMAC-SHA512 implementation
([https://doc.libsodium.org/](https://doc.libsodium.org)). Originally
written in 2015.

The reference Makefile assumes libsodium is installed in /usr/local/lib
(and headers in /usr/local/include).