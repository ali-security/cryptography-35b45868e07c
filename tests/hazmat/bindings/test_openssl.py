# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import subprocess
import sys

import pytest

from cryptography.exceptions import InternalError
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.bindings.openssl.binding import (
    Binding,
    _openssl_assert,
    _verify_package_version,
)


# OpenSSL's CVE-2026-45447 regression input
# (test/smime-eml/pkcs7-empty-digest-set.eml): a multipart/signed S/MIME
# message whose detached signedData carries an empty digestAlgorithms SET.
_PKCS7_EMPTY_DIGEST_SET_EML = (
    b"MIME-Version: 1.0\n"
    b"Content-Type: multipart/signed; "
    b'protocol="application/x-pkcs7-signature"; micalg="sha-256"; '
    b'boundary="----E0314CC5D732C92AE2D7A3BACDCDCFCE"\n'
    b"\n"
    b"This is an S/MIME signed message\n"
    b"\n"
    b"------E0314CC5D732C92AE2D7A3BACDCDCFCE\n"
    b"This is the content to be signed.\n"
    b"\n"
    b"------E0314CC5D732C92AE2D7A3BACDCDCFCE\n"
    b'Content-Type: application/x-pkcs7-signature; name="smime.p7s"\n'
    b"Content-Transfer-Encoding: base64\n"
    b'Content-Disposition: attachment; filename="smime.p7s"\n'
    b"\n"
    b"MIIFWgYJKoZIhvcNAQcCoIIFSzCCBUcCAQExADALBgkqhkiG9w0BBwGgggLuMIIC\n"
    b"6jCCAdKgAwIBAgIUL5E46FxyhsT7C3G1NS27OtR7XAowDQYJKoZIhvcNAQELBQAw\n"
    b"FTETMBEGA1UEAwwKUG9DIFNpZ25lcjAeFw0yNjA1MDgxMDIwNDhaFw0yNzA1MDgx\n"
    b"MDIwNDhaMBUxEzARBgNVBAMMClBvQyBTaWduZXIwggEiMA0GCSqGSIb3DQEBAQUA\n"
    b"A4IBDwAwggEKAoIBAQDSSu/gupmIlclvmTMHiqOrCqmB8NRTjAMoI//MPJrnFXYp\n"
    b"FjDPMk7Y/kCcHztudaIvADkowaFtOm4oMinQFhjwCNCo5K5WrrlAitnpcd5QH2nA\n"
    b"iVZXjjohQUJEd7n33AGqTwo5EGaCK+alAZL7tA7bdhNi/aZ33L3bUNYqoHbXiNsE\n"
    b"u1tj8frLfIjduOt0TMPSOrrFjjEsrL3T3tg+HmxpalDHz7E6o9zJu0wlk8bcR2Xk\n"
    b"mpX8RdYCu7K9m39N1F2WKa9WJh24NQLpWRfwD213jaIFK2EXy/XHePDUeiMYtVOV\n"
    b"oovCSmY7OqowupA7J+4dcsnRjFqgZECctHhAfk+PAgMBAAGjMjAwMB0GA1UdDgQW\n"
    b"BBRZlupXNYq4fny0SE76sr/CdQ2DUTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n"
    b"DQEBCwUAA4IBAQANOlttTWVz620JNTrPzhiR4x9+5UiF4GSqv8BRJQFj3Xh7fsUp\n"
    b"+3GDs9M27f4FVh3utJsjt7Sa9ZWLpBVdgjGBwGLAtPsoYMjhnUgZTUvwEk5+aXyv\n"
    b"zJxn4I7mMbDhlNCMHcVtGdtA+2UOEuvdGfuEilpzPsV8DzM1K3xU5bSWoo0BRFKK\n"
    b"srHkyEfxCFPAQOcX80ZbMO6zdcXeJjC6mQXGqy2aqeQob0vuSZJ7QHZBlRjY5YHR\n"
    b"wWlIqG8G3Eist16iTqdX2PQFZT1/QAEQ/LnXARTUUjUroccdci8YNASoeHDpcjRL\n"
    b"MBrN+QBNZVt5qLhDogwZb2ZwqKfZ8Aqg3oAkMYICPzCCAjsCAQEwLTAVMRMwEQYD\n"
    b"VQQDDApQb0MgU2lnbmVyAhQvkTjoXHKGxPsLcbU1Lbs61HtcCjANBglghkgBZQME\n"
    b"AgEFAKCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP\n"
    b"Fw0yNjA1MDgxMDIwNDhaMC8GCSqGSIb3DQEJBDEiBCAvyoHfycLqb8UzVPizy1uA\n"
    b"o3h7tza3HebeiJaSnpIJHzB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjAL\n"
    b"BglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMC\n"
    b"AgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDANBgkq\n"
    b"hkiG9w0BAQEFAASCAQBIpl7U2j4YiU1vdZHyx2dCK41ZahtTVOB4RVJcrmopgans\n"
    b"fICdkSTfb0dVqc13++bYn4i1b2R2os5YIkoGxdrM5aZB7KF9r1xwgrendTF4/BwP\n"
    b"gQq2khNtKebv9Yr0kOPynFIsgx5BHk99wrzfwidJUFuJJgQ9W0YOf7EGkbnZvPT+\n"
    b"hV0aeLmJAb5jjWhbDciqUjR3O23JQhzVj4U3vo2TeN7VYmNJsX+fA4sZzIbYSei9\n"
    b"ps7GZruiRcKgqgUj1l8HjIGMHqd9lccchk/BYyAGxAbgGisntvfJdPZO09wG8rHh\n"
    b"eS6FYkkXAKBO49WbhE9aVLJH0zgA6gTfyEvOOOS1\n"
    b"\n"
    b"------E0314CC5D732C92AE2D7A3BACDCDCFCE--\n"
    b"\n"
)

# Run in a child interpreter: on a vulnerable OpenSSL, PKCS7_verify() frees
# the caller's indata BIO, so touching it afterwards is a use-after-free that
# takes the whole process down rather than raising.
_PKCS7_VERIFY_INDATA_SCRIPT = """
import sys

from cryptography.hazmat.bindings.openssl.binding import Binding

PKCS7_NOVERIFY = 0x20

b = Binding()
lib, ffi = b.lib, b.ffi
eml = sys.stdin.buffer.read()
in_bio = lib.BIO_new_mem_buf(eml, len(eml))
assert in_bio != ffi.NULL
bcont = ffi.new("BIO **")
p7 = lib.SMIME_read_PKCS7(in_bio, bcont)
assert p7 != ffi.NULL
indata = bcont[0]
assert indata != ffi.NULL
data = ffi.new("char **")
assert lib.BIO_get_mem_data(indata, data) > 0
ret = lib.PKCS7_verify(
    p7, ffi.NULL, ffi.NULL, indata, ffi.NULL, PKCS7_NOVERIFY
)
assert ret == 0, ret
# PKCS7_verify() read the detached content through indata (so it reached
# the digest stage) and must have left the caller's BIO alive and usable.
assert lib.BIO_get_mem_data(indata, data) == 0
assert lib.BIO_write(indata, b"ok", 2) == 2
out = ffi.new("char[]", 2)
assert lib.BIO_read(indata, out, 2) == 2
assert ffi.buffer(out, 2)[:] == b"ok"
assert lib.BIO_free(indata) == 1
lib.PKCS7_free(p7)
lib.BIO_free(in_bio)
lib.ERR_clear_error()
print("indata intact")
"""


class TestOpenSSL:
    def test_binding_loads(self):
        binding = Binding()
        assert binding
        assert binding.lib
        assert binding.ffi

    def test_ssl_ctx_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        # SSL_OP_ALL is 0 on BoringSSL
        if not b.lib.CRYPTOGRAPHY_IS_BORINGSSL:
            assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLS_method())
        assert ctx != b.ffi.NULL
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        current_options = b.lib.SSL_CTX_get_options(ctx)
        resp = b.lib.SSL_CTX_set_options(ctx, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_CTX_get_options(ctx) == expected_options

    def test_ssl_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        # SSL_OP_ALL is 0 on BoringSSL
        if not b.lib.CRYPTOGRAPHY_IS_BORINGSSL:
            assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLS_method())
        assert ctx != b.ffi.NULL
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        ssl = b.lib.SSL_new(ctx)
        ssl = b.ffi.gc(ssl, b.lib.SSL_free)
        current_options = b.lib.SSL_get_options(ssl)
        resp = b.lib.SSL_set_options(ssl, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_get_options(ssl) == expected_options

    def test_conditional_removal(self):
        b = Binding()

        if not b.lib.CRYPTOGRAPHY_IS_LIBRESSL:
            assert b.lib.TLS_ST_OK
        else:
            with pytest.raises(AttributeError):
                b.lib.TLS_ST_OK

    def test_openssl_assert_error_on_stack(self):
        b = Binding()
        b.lib.ERR_put_error(
            b.lib.ERR_LIB_EVP,
            b.lib.EVP_F_EVP_ENCRYPTFINAL_EX,
            b.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH,
            b"",
            -1,
        )
        with pytest.raises(InternalError) as exc_info:
            _openssl_assert(False)

        error = exc_info.value.err_code[0]
        assert error.lib == b.lib.ERR_LIB_EVP
        assert error.reason == b.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
        if not b.lib.CRYPTOGRAPHY_IS_BORINGSSL:
            assert b"data not multiple of block length" in error.reason_text

    def test_pkcs7_verify_empty_digest_set_keeps_indata(self):
        # CVE-2026-45447: with an empty digestAlgorithms SET, PKCS7_verify()
        # used the caller's indata BIO as its own chain and freed it on the
        # way out (use-after-free / double free in the caller).
        b = Binding()
        if not b.lib.Cryptography_HAS_PKCS7_FUNCS:
            pytest.skip("Requires PKCS7_verify")
        result = subprocess.run(
            [sys.executable, "-c", _PKCS7_VERIFY_INDATA_SCRIPT],
            input=_PKCS7_EMPTY_DIGEST_SET_EML,
            capture_output=True,
        )
        assert result.returncode == 0, (result.returncode, result.stderr)
        assert result.stdout.strip() == b"indata intact"

    def test_version_mismatch(self):
        with pytest.raises(ImportError):
            _verify_package_version("nottherightversion")

    def test_rust_internal_error(self):
        with pytest.raises(InternalError) as exc_info:
            rust_openssl.raise_openssl_error()

        assert len(exc_info.value.err_code) == 0

        b = Binding()
        b.lib.ERR_put_error(
            b.lib.ERR_LIB_EVP,
            b.lib.EVP_F_EVP_ENCRYPTFINAL_EX,
            b.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH,
            b"",
            -1,
        )
        with pytest.raises(InternalError) as exc_info:
            rust_openssl.raise_openssl_error()

        error = exc_info.value.err_code[0]
        assert error.lib == b.lib.ERR_LIB_EVP
        assert error.reason == b.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
        if not b.lib.CRYPTOGRAPHY_IS_BORINGSSL:
            assert b"data not multiple of block length" in error.reason_text
