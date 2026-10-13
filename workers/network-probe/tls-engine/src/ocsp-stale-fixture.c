/* SPDX-License-Identifier: Apache-2.0
 * Test fixture only: create a correctly signed but expired OCSP staple.
 * It is never shipped in the runtime image or used against remote hosts.
 */
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    FILE *cert_file = fopen(argv[1], "rb"), *key_file = fopen(argv[2], "rb");
    if (!cert_file || !key_file) return 3;
    X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    EVP_PKEY *key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(cert_file); fclose(key_file);
    if (!cert || !key) return 4;
    OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), cert, cert);
    OCSP_BASICRESP *basic = OCSP_BASICRESP_new();
    time_t now = time(NULL);
    ASN1_TIME *this_update = ASN1_TIME_set(NULL, now - 3 * 86400);
    ASN1_TIME *next_update = ASN1_TIME_set(NULL, now - 86400);
    if (!id || !basic || !this_update || !next_update ||
        !OCSP_basic_add1_status(basic, id, V_OCSP_CERTSTATUS_GOOD,
                                OCSP_REVOKED_STATUS_NOSTATUS, NULL,
                                this_update, next_update) ||
        !OCSP_basic_sign(basic, cert, key, EVP_sha256(), NULL, 0)) return 5;
    OCSP_RESPONSE *response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    if (!response) return 6;
    unsigned char *der = NULL;
    int length = i2d_OCSP_RESPONSE(response, &der);
    FILE *out = fopen(argv[3], "wb");
    int ok = length > 0 && out && fwrite(der, 1, (size_t)length, out) == (size_t)length;
    if (out) fclose(out);
    OPENSSL_free(der); OCSP_RESPONSE_free(response); OCSP_BASICRESP_free(basic);
    OCSP_CERTID_free(id); ASN1_TIME_free(this_update); ASN1_TIME_free(next_update);
    EVP_PKEY_free(key); X509_free(cert);
    return ok ? 0 : 7;
}
