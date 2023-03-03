#ifndef _GMCM_ALG_API_H_
#define _GMCM_ALG_API_H_


#include "gmcmSdf.h"

#ifndef EXPORT_FUNC
#define EXPORT_FUNC
#endif

EXPORT_FUNC void openssl_err_stack();

EXPORT_FUNC int alg_random(unsigned int length, unsigned char * buf);

EXPORT_FUNC int alg_str_to_int(const char *alg);
EXPORT_FUNC char *alg_pem_get_base64(char *alg);

EXPORT_FUNC int alg_sm2_gen_pri(unsigned char *pri);
EXPORT_FUNC int alg_sm2_pri_gen_pub(unsigned char *pri, unsigned char *pub_x, unsigned char *pub_y);
EXPORT_FUNC int alg_sm2_gen_key_pair(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri);
EXPORT_FUNC int alg_sm2_export(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri, char *sPem);
EXPORT_FUNC int alg_sm2_import(char *sPem, ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri);

EXPORT_FUNC int alg_sm2_pub_encrypt(ECCrefPublicKey *pPub, unsigned char *data, unsigned int dataLen, ECCCipher *cipher);
EXPORT_FUNC int alg_sm2_pri_decrypt(ECCrefPrivateKey *pPri, ECCCipher *cipher, unsigned char *data, unsigned int *dataLen);
EXPORT_FUNC int alg_sm2_sign(ECCrefPrivateKey *pPri, unsigned char *data, unsigned int dataLen, ECCSignature *sign);
EXPORT_FUNC int alg_sm2_verify(ECCrefPublicKey *pPub, unsigned char *data, unsigned int dataLen, ECCSignature *sign);

EXPORT_FUNC int alg_rsa_gen_key_pair(int bits, unsigned long e, RSArefPublicKey *pPub, RSArefPrivateKey *pPri);
EXPORT_FUNC int alg_rsa_export(RSArefPrivateKey *pPri, char *sPem);
EXPORT_FUNC int alg_rsa_import(char *sPem, RSArefPublicKey *pPub, RSArefPrivateKey *pPri);

#define MAX_DATA_LEN   8192
EXPORT_FUNC int alg_sm4_encrypt(unsigned char *key, unsigned int algid, unsigned int pad,
                                unsigned char *in, unsigned int inLen,
                                unsigned char *iv, unsigned int ivLen,
                                unsigned char *out, unsigned int *outLen);
EXPORT_FUNC int alg_sm4_decrypt(unsigned char *key, unsigned int algid, unsigned int pad,
                                unsigned char *in, unsigned int inLen,
                                unsigned char *iv, unsigned int ivLen,
                                unsigned char *out, unsigned int *outLen);

EXPORT_FUNC int alg_sm3_init(unsigned char *pSm3Ctx, unsigned int *ctxLen, unsigned char *pubX, unsigned char *pubY, unsigned char *id, unsigned int idLen);
EXPORT_FUNC void alg_sm3_update(unsigned char *pSm3Ctx, unsigned char *data, unsigned int dataLen);
EXPORT_FUNC void alg_sm3_final(unsigned char *pSm3Ctx, unsigned char *hash);


// static BIT_STRING_BITNAME key_usage_type_table[] = {
//     {0, "Digital Signature", "digitalSignature"},
//     {1, "Non Repudiation", "nonRepudiation"},
//     {2, "Key Encipherment", "keyEncipherment"},
//     {3, "Data Encipherment", "dataEncipherment"},
//     {4, "Key Agreement", "keyAgreement"},
//     {5, "Certificate Sign", "keyCertSign"},
//     {6, "CRL Sign", "cRLSign"},
//     {7, "Encipher Only", "encipherOnly"},
//     {8, "Decipher Only", "decipherOnly"},
//     {-1, NULL, NULL}
// };

//ex usage serverAuth,clientAuth
// ex usage critical,timeStamping

enum cert_usage
{
    USAGE_CA = 1, //
    USAGE_SIGN,   //
    USAGE_ENC,    //
    USAGE_TLS,    //
    USAGE_WEB,    //
    USAGE_TSA,    //
    USAGE_IPSEC,  //
    USAGE_EMAIL,  //
    USAGE_CARD,   //
};

EXPORT_FUNC int alg_pem_import_cert(const char *b64Cert, void **pCert);
EXPORT_FUNC void alg_free_cert(void ** pCert);

EXPORT_FUNC int alg_pem_import_key(const char *b64Key, void **pKey);
EXPORT_FUNC void alg_free_key(void **pKey);

#define CNF_POLSECT "authorityInfoAccess = OCSP;URI:http://islam3rd.top\n"       \
                    "authorityInfoAccess = caIssuers;URI:http://islam3rd.top/\n" \
                    "certificatePolicies = ia5org,2.23.140.1.2.1,@polsect\n"     \
                    "[ polsect ]\n"                                              \
                    "policyIdentifier = 1.3.6.1.4.1.44947.1.1.1\n"               \
                    "CPS=http://islam3rd.top\n"

#define CNF_CA_REQ "[ v3_req ]\n"                         \
                   "basicConstraints = CA:true\n"         \
                   "nsCertType = sslCA, emailCA, objCA\n" \
                   "keyUsage = nonRepudiation,keyCertSign,cRLSign\n"

#define CNF_SIGN_ENC_REQ "[ v3_req ]\n"                                                                     \
                         "keyUsage = nonRepudiation, digitalSignature, dataEncipherment, keyEncipherment\n" \
                         "basicConstraints = CA:FALSE\n"

#define CNF_TLS_REQ "[ v3_req ]\n"                               \
                    "extendedKeyUsage = serverAuth,clientAuth\n" \
                    "keyUsage = digitalSignature,keyAgreement\n" \
                    "basicConstraints = CA:FALSE\n"

#define CNF_WEB_REQ "[ v3_req ]\n"                                                                               \
                    "extendedKeyUsage = serverAuth,clientAuth\n"                                                 \
                    "keyUsage = nonRepudiation,keyEncipherment,dataEncipherment,digitalSignature,keyAgreement\n" \
                    "basicConstraints = CA:FALSE\n" // "subjectAltName = DNS:site"

#define CNF_TSA_REQ "[ v3_req ]\n"                                                                  \
                    "extendedKeyUsage = timeStamping\n"                                             \
                    "keyUsage = nonRepudiation,keyEncipherment,dataEncipherment,digitalSignature\n" \
                    "basicConstraints = CA:FALSE\n"

#define CNF_IPSEC_REQ "[ v3_req ]\n"                                                                  \
                      "extendedKeyUsage = 1.3.6.1.5.5.8.2.2\n"                                        \
                      "keyUsage = nonRepudiation,keyEncipherment,dataEncipherment,digitalSignature\n" \
                      "basicConstraints = CA:FALSE\n"

#define CNF_EMAIL_REQ "[ v3_req ]\n"                                                                  \
                      "extendedKeyUsage = emailProtection\n"                                          \
                      "keyUsage = nonRepudiation,keyEncipherment,dataEncipherment,digitalSignature\n" \
                      "basicConstraints = CA:FALSE\n"

#define CNF_CARD_REQ "[ v3_req ]\n"                                                              \
                     "extendedKeyUsage = 1.3.6.1.4.1.311.10.3.11,msEFS,1.3.6.1.4.1.311.20.2.2\n" \
                     "keyUsage = digitalSignature,keyAgreement,decipherOnly\n"                   \
                     "basicConstraints = CA:FALSE\n"


EXPORT_FUNC int alg_csr_gen_sm2(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri, char *subj, char *b64Csr);
EXPORT_FUNC int alg_csr_gen_rsa(RSArefPublicKey *pPub, RSArefPrivateKey *pPri, char *subj, char *b64Csr);

EXPORT_FUNC int alg_csr_sign_cert_sm2(char *b64Csr, void *pCa, ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri,
                                      unsigned int days, cert_usage usage, unsigned char *serial,
                                      unsigned int serLen, char *sCert);
EXPORT_FUNC int alg_csr_sign_cert_rsa(char *b64Csr, void *pCa, RSArefPublicKey *pPub, RSArefPrivateKey *pPri,
                                      unsigned int days, cert_usage usage, unsigned char *serial,
                                      unsigned int serLen, char *sCert);

// tls

EXPORT_FUNC void *alg_tls_ctx_init(int isClient,
                                   const char *signCert, const char *signKey,
                                   const char *encCert, const char *encKey);
EXPORT_FUNC void alg_tls_free(void **ctx);
EXPORT_FUNC int alg_tls_ctx_add_ca(void *ctx, char *caPem);
EXPORT_FUNC int alg_tls_ctx_add_ca_dir(void *ctx, const char *dir);

#endif