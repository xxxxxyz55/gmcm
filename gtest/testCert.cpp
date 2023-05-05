#include <iostream>
#include "algApi.h"
#include "utilFunc.h"

#define ALG_LOG_DEBUG(fmt, ...) fprintf(stdout, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);
#define ALG_LOG_ERROR(fmt, ...) fprintf(stderr, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);
using namespace std;

#define TEST_API(x)                            \
    do                                         \
    {                                          \
        int ret = x;                           \
        if (ret)                               \
        {                                      \
            ALG_LOG_ERROR(#x " err = %d", ret); \
            exit(1);                           \
        }                                      \
    } while (0)

#define TO_STR(x) #x

void test_import_cert();
void test_import_cert_no_header();

void test_import_key();
void test_import_key_no_header();

void test_gen_sm2_cert();
void test_gen_rsa_cert();

int main(int argc, char const *argv[])
{
    int choose = 0;
    if(argc == 1)
    {
        choose = utilTool::stdGetInt("1 test import cert\n"
                                       "2 test import key\n"
                                       "3 test import cert no header\n"
                                       "4 test import key no header\n"
                                       "5 test gen sm2 cert\n"
                                       "6 test gen sm2 cert\n");
    }
    else if (argc == 2)
    {
        choose = atoi(argv[1]);
    }

    switch (choose)
    {
    case 1:
        test_import_cert();
        break;
    case 2:
        test_import_key();
        break;
    case 3:
        test_import_cert_no_header();
        break;
    case 4:
        test_import_key_no_header();
        break;
    case 5:
        test_gen_sm2_cert();
        break;
    case 6:
        test_gen_rsa_cert();
        break;

    default:
        break;
    }




    return 0;
}

void test_import_cert()
{
    char b64RsaCert[] = "-----BEGIN CERTIFICATE-----\n\
MIIDCTCCAnKgAwIBAgIJAOxfmWcbpvMoMA0GCSqGSIb3DQEBCwUAMIGiMQswCQYD\
VQQGEwJDTjEQMA4GA1UECAwHQkVJSklORzEQMA4GA1UEBwwHQkVJSklORzE9MDsG\
A1UECgw0QmVpamluZyBUb3BzZWMgTmV0d29yayBTZWN1cml0eSBUZWNobm9sb2d5\
IENvLiwgTHRkLjEfMB0GA1UECwwWRW5naW5lZXJpbmcgRGVwYXJ0bWVudDEPMA0G\
A1UEAwwGcm9vdENBMB4XDTIyMDgyNDA5MDc1MloXDTMyMDgyMTA5MDc1MlowgaIx\
CzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCRUlKSU5HMRAwDgYDVQQHDAdCRUlKSU5H\
MT0wOwYDVQQKDDRCZWlqaW5nIFRvcHNlYyBOZXR3b3JrIFNlY3VyaXR5IFRlY2hu\
b2xvZ3kgQ28uLCBMdGQuMR8wHQYDVQQLDBZFbmdpbmVlcmluZyBEZXBhcnRtZW50\
MQ8wDQYDVQQDDAZyb290Q0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKv7\
9aQm6v1esHaTfN0Htm+cs7QcKvFo6VHKOOpM6D19hzKmg99bXZQPRbTqWtpni/Yp\
RQZo+cWdUZa03OaOMO9WLUL72Zh0eLMy3KYpnr53gXg0zYmOmNc7bJyYpr9MLavd\
Tq7DhjOd//+Aln/Df9inugWhhGoM3ceE8GJ0VEo/AgMBAAGjRTBDMB0GA1UdDgQW\
BBTS76GuaiJIvEFZXhJY9BAMdUhGLzARBglghkgBhvhCAQEEBAMCAAcwDwYDVR0T\
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQBZHcOrsHZ+qBdOwl3f0qt4B03P\
drcWTRGYycsdf3rx7QufJEQu+skvqygd9A7uQLC34WgZ0IUDsYNA1ksBwdhrZVbc\
9ea2mMaXrlEVwqTDluBbo1nOQkkUIRMSS0PlASJwGo/UpAbqUl3Ow8bRA6PewdMh\
pN/a71MFGo6G4aNdnw==\n\
-----END CERTIFICATE-----";
    char b64Sm2Cert[] = "-----BEGIN CERTIFICATE-----\n\
MIICijCCAjCgAwIBAgIJALY4gSWs3XImMAoGCCqBHM9VAYN1MIGmMQswCQYDVQQG\
EwJDTjEQMA4GA1UECAwHQkVJSklORzEQMA4GA1UEBwwHQkVJSklORzE9MDsGA1UE\
Cgw0QmVpamluZyBUb3BzZWMgTmV0d29yayBTZWN1cml0eSBUZWNobm9sb2d5IENv\
LiwgTHRkLjEfMB0GA1UECwwWRW5naW5lZXJpbmcgRGVwYXJ0bWVudDETMBEGA1UE\
AwwKcm9vdENBLnNtMjAeFw0yMjA4MjQwOTA3NTNaFw0zMjA4MjEwOTA3NTNaMIGm\
MQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQkVJSklORzEQMA4GA1UEBwwHQkVJSklO\
RzE9MDsGA1UECgw0QmVpamluZyBUb3BzZWMgTmV0d29yayBTZWN1cml0eSBUZWNo\
bm9sb2d5IENvLiwgTHRkLjEfMB0GA1UECwwWRW5naW5lZXJpbmcgRGVwYXJ0bWVu\
dDETMBEGA1UEAwwKcm9vdENBLnNtMjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA\
BBS4R7v7hvuyF2zKt/oxiSEg+GeTkDVIFciFuUgzXc34pHV+kC7VfchyBGIDVDHC\
u3nAJj3SXs/T6Nq//nTvXy+jRTBDMB0GA1UdDgQWBBTX7P7zDACZnjhvL6oNHJrH\
+19RCDARBglghkgBhvhCAQEEBAMCAAcwDwYDVR0TAQH/BAUwAwEB/zAKBggqgRzP\
VQGDdQNIADBFAiEAtQlq6xUtU6H2sihI00COkaapunFdAUlTL9WzxvNgj44CIBkq\
/3y4QUm1f9GSVw8XLthvAWY5sYmDM9zrbnBlUDOn\n\
-----END CERTIFICATE-----";

    void *rsaCert = NULL;
    TEST_API(alg_pem_import_cert(b64RsaCert, &rsaCert));
    alg_free_cert(&rsaCert);

    void *sm2Cert = NULL;
    TEST_API(alg_pem_import_cert(b64Sm2Cert, &sm2Cert));
    alg_free_cert(&sm2Cert);
}

void test_import_key()
{
    char b64RsaKey[] = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQCr+/WkJur9XrB2k3zdB7ZvnLO0HCrxaOlRyjjqTOg9fYcypoPf\
W12UD0W06lraZ4v2KUUGaPnFnVGWtNzmjjDvVi1C+9mYdHizMtymKZ6+d4F4NM2J\
jpjXO2ycmKa/TC2r3U6uw4Yznf//gJZ/w3/Yp7oFoYRqDN3HhPBidFRKPwIDAQAB\
AoGBAJB0vrvVcJXG3gOLGFrzKnqPLaX/7tX839UyPSIX3Q4hDNkvYh7OuEgvl8ZA\
/nTqenYV7gNXU0x4OlqSqeUB0/kjTW/tPJ0li6oJd6hpJFpR62JEt/zfXil6b79v\
9yE9XNPiICKUfmyZzZ0TrOeP7G2yIq/G4qHooZJoTdOOUAFxAkEA2Bjqz6wwTChy\
l5d7cvRdar6ERPLKwatIlexCN0F/1giePAQ9Z1eWP7d14fBqNkljTC2pyNEYqcuK\
hX+P3DtxmQJBAMu9yEMciZb19ERL7xp7WuL2rPf/Fjcz4RRpa/JuI4q1kY/0EIEd\
7ZNdLWgnSQZiJv4sHZiO0QjfBXdGilB2MZcCQAbLuc6wHpC2kOv9go9Z6foqZaR5\
cjDm/xBf7rEoKSoE+Vzv0TKHyZzVWyqw0dZFNo81vGopUTo9wWxzV4XYhLkCQQCJ\
hiAAVOn2sSxhUVQi7vLpUpJsj42iU21xhrtrl7Z78ZVAswDU9quflfyJWkMrgONL\
G+IaUQR+VXPuD/pa130fAkAn+wRTRZgdNWfv5CB1NC+QvVNpJSSpx19u4JmKS0AI\
pot/CcOWEXguIEHmWIGBnIaMlN0t7Xg/6W1FrPh3sSgf\n\
-----END RSA PRIVATE KEY-----";
    char b64Sm2Key[] = "-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIHNGMv3r2iqtYOnN+qhvgx2Dk4YptopVCVroF0hCFxA5oAoGCCqBHM9V\
AYItoUQDQgAEFLhHu/uG+7IXbMq3+jGJISD4Z5OQNUgVyIW5SDNdzfikdX6QLtV9\
yHIEYgNUMcK7ecAmPdJez9Po2r/+dO9fLw==\n\
-----END EC PRIVATE KEY-----";

    void * rsaKey = NULL;
    TEST_API(alg_pem_import_key(b64RsaKey, &rsaKey));
    alg_free_key(&rsaKey);

    void *sm2Key = NULL;
    TEST_API(alg_pem_import_key(b64Sm2Key, &sm2Key));
    alg_free_key(&sm2Key);
}

void test_import_cert_no_header()
{
    char b64RsaCert[] = "MIIDCTCCAnKgAwIBAgIJAOxfmWcbpvMoMA0GCSqGSIb3DQEBCwUAMIGiMQswCQYD\
VQQGEwJDTjEQMA4GA1UECAwHQkVJSklORzEQMA4GA1UEBwwHQkVJSklORzE9MDsG\
A1UECgw0QmVpamluZyBUb3BzZWMgTmV0d29yayBTZWN1cml0eSBUZWNobm9sb2d5\
IENvLiwgTHRkLjEfMB0GA1UECwwWRW5naW5lZXJpbmcgRGVwYXJ0bWVudDEPMA0G\
A1UEAwwGcm9vdENBMB4XDTIyMDgyNDA5MDc1MloXDTMyMDgyMTA5MDc1MlowgaIx\
CzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCRUlKSU5HMRAwDgYDVQQHDAdCRUlKSU5H\
MT0wOwYDVQQKDDRCZWlqaW5nIFRvcHNlYyBOZXR3b3JrIFNlY3VyaXR5IFRlY2hu\
b2xvZ3kgQ28uLCBMdGQuMR8wHQYDVQQLDBZFbmdpbmVlcmluZyBEZXBhcnRtZW50\
MQ8wDQYDVQQDDAZyb290Q0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKv7\
9aQm6v1esHaTfN0Htm+cs7QcKvFo6VHKOOpM6D19hzKmg99bXZQPRbTqWtpni/Yp\
RQZo+cWdUZa03OaOMO9WLUL72Zh0eLMy3KYpnr53gXg0zYmOmNc7bJyYpr9MLavd\
Tq7DhjOd//+Aln/Df9inugWhhGoM3ceE8GJ0VEo/AgMBAAGjRTBDMB0GA1UdDgQW\
BBTS76GuaiJIvEFZXhJY9BAMdUhGLzARBglghkgBhvhCAQEEBAMCAAcwDwYDVR0T\
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQBZHcOrsHZ+qBdOwl3f0qt4B03P\
drcWTRGYycsdf3rx7QufJEQu+skvqygd9A7uQLC34WgZ0IUDsYNA1ksBwdhrZVbc\
9ea2mMaXrlEVwqTDluBbo1nOQkkUIRMSS0PlASJwGo/UpAbqUl3Ow8bRA6PewdMh\
pN/a71MFGo6G4aNdnw==";
    char b64Sm2Cert[] = "MIICijCCAjCgAwIBAgIJALY4gSWs3XImMAoGCCqBHM9VAYN1MIGmMQswCQYDVQQG\
EwJDTjEQMA4GA1UECAwHQkVJSklORzEQMA4GA1UEBwwHQkVJSklORzE9MDsGA1UE\
Cgw0QmVpamluZyBUb3BzZWMgTmV0d29yayBTZWN1cml0eSBUZWNobm9sb2d5IENv\
LiwgTHRkLjEfMB0GA1UECwwWRW5naW5lZXJpbmcgRGVwYXJ0bWVudDETMBEGA1UE\
AwwKcm9vdENBLnNtMjAeFw0yMjA4MjQwOTA3NTNaFw0zMjA4MjEwOTA3NTNaMIGm\
MQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQkVJSklORzEQMA4GA1UEBwwHQkVJSklO\
RzE9MDsGA1UECgw0QmVpamluZyBUb3BzZWMgTmV0d29yayBTZWN1cml0eSBUZWNo\
bm9sb2d5IENvLiwgTHRkLjEfMB0GA1UECwwWRW5naW5lZXJpbmcgRGVwYXJ0bWVu\
dDETMBEGA1UEAwwKcm9vdENBLnNtMjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA\
BBS4R7v7hvuyF2zKt/oxiSEg+GeTkDVIFciFuUgzXc34pHV+kC7VfchyBGIDVDHC\
u3nAJj3SXs/T6Nq//nTvXy+jRTBDMB0GA1UdDgQWBBTX7P7zDACZnjhvL6oNHJrH\
+19RCDARBglghkgBhvhCAQEEBAMCAAcwDwYDVR0TAQH/BAUwAwEB/zAKBggqgRzP\
VQGDdQNIADBFAiEAtQlq6xUtU6H2sihI00COkaapunFdAUlTL9WzxvNgj44CIBkq\
/3y4QUm1f9GSVw8XLthvAWY5sYmDM9zrbnBlUDOn";

    void *rsaCert = NULL;
    TEST_API(alg_pem_import_cert(b64RsaCert, &rsaCert));
    alg_free_cert(&rsaCert);

    void *sm2Cert = NULL;
    TEST_API(alg_pem_import_cert(b64Sm2Cert, &sm2Cert));
    alg_free_cert(&sm2Cert);
}

void test_import_key_no_header()
{
    char b64RsaKey[] = "MIICXQIBAAKBgQCr+/WkJur9XrB2k3zdB7ZvnLO0HCrxaOlRyjjqTOg9fYcypoPf\
W12UD0W06lraZ4v2KUUGaPnFnVGWtNzmjjDvVi1C+9mYdHizMtymKZ6+d4F4NM2J\
jpjXO2ycmKa/TC2r3U6uw4Yznf//gJZ/w3/Yp7oFoYRqDN3HhPBidFRKPwIDAQAB\
AoGBAJB0vrvVcJXG3gOLGFrzKnqPLaX/7tX839UyPSIX3Q4hDNkvYh7OuEgvl8ZA\
/nTqenYV7gNXU0x4OlqSqeUB0/kjTW/tPJ0li6oJd6hpJFpR62JEt/zfXil6b79v\
9yE9XNPiICKUfmyZzZ0TrOeP7G2yIq/G4qHooZJoTdOOUAFxAkEA2Bjqz6wwTChy\
l5d7cvRdar6ERPLKwatIlexCN0F/1giePAQ9Z1eWP7d14fBqNkljTC2pyNEYqcuK\
hX+P3DtxmQJBAMu9yEMciZb19ERL7xp7WuL2rPf/Fjcz4RRpa/JuI4q1kY/0EIEd\
7ZNdLWgnSQZiJv4sHZiO0QjfBXdGilB2MZcCQAbLuc6wHpC2kOv9go9Z6foqZaR5\
cjDm/xBf7rEoKSoE+Vzv0TKHyZzVWyqw0dZFNo81vGopUTo9wWxzV4XYhLkCQQCJ\
hiAAVOn2sSxhUVQi7vLpUpJsj42iU21xhrtrl7Z78ZVAswDU9quflfyJWkMrgONL\
G+IaUQR+VXPuD/pa130fAkAn+wRTRZgdNWfv5CB1NC+QvVNpJSSpx19u4JmKS0AI\
pot/CcOWEXguIEHmWIGBnIaMlN0t7Xg/6W1FrPh3sSgf";
    char b64Sm2Key[] = "MHcCAQEEIHNGMv3r2iqtYOnN+qhvgx2Dk4YptopVCVroF0hCFxA5oAoGCCqBHM9V\
AYItoUQDQgAEFLhHu/uG+7IXbMq3+jGJISD4Z5OQNUgVyIW5SDNdzfikdX6QLtV9\
yHIEYgNUMcK7ecAmPdJez9Po2r/+dO9fLw==";

    void * rsaKey = NULL;
    TEST_API(alg_pem_import_key(b64RsaKey, &rsaKey));
    alg_free_key(&rsaKey);

    void *sm2Key = NULL;
    TEST_API(alg_pem_import_key(b64Sm2Key, &sm2Key));
    alg_free_key(&sm2Key);
}

void test_gen_sm2_cert()
{
    ECCrefPublicKey rootPub;
    ECCrefPrivateKey rootPri;
    TEST_API(alg_sm2_gen_key_pair(&rootPub, &rootPri));

    char rootKeyPem[8192];
    TEST_API(alg_sm2_export(&rootPub, &rootPri, rootKeyPem));
    cout << "rootKeyPem :\n" << rootKeyPem << endl;

    char rootCsr[8192];
    TEST_API(alg_csr_gen_sm2(&rootPub, &rootPri, (char *)"/CN=gmcmCA", rootCsr));
    cout << "rootCsr : \n" << rootCsr << endl;

    char rootCert[8192];
    TEST_API(alg_csr_sign_cert_sm2(rootCsr, NULL, &rootPub, &rootPri, 3650, USAGE_CA, NULL, 0, rootCert));
    cout << "rootCert :\n" << rootCert << endl;

    ECCrefPublicKey usrPub;
    ECCrefPrivateKey usrPri;
    TEST_API(alg_sm2_gen_key_pair(&usrPub, &usrPri));

    char usrKeyPem[8192];
    TEST_API(alg_sm2_export(&usrPub, &usrPri, usrKeyPem));
    cout << "usrKeyPem :\n" << rootKeyPem << endl;

    char usrCsr[8192];
    TEST_API(alg_csr_gen_sm2(&usrPub, &usrPri, (char *)"/CN=www.islam3rd.top", usrCsr));
    cout << "usrCsr :\n" << usrCsr << endl;

    void *caCert = NULL;
    TEST_API(alg_pem_import_cert(rootCert, &caCert));

    char usrCert[8192];
    TEST_API(alg_csr_sign_cert_sm2(usrCsr, caCert, &rootPub, &rootPri, 3650, USAGE_TLS, NULL, 0, usrCert));
    cout << "usrCert :\n" << usrCert << endl;
}

void test_gen_rsa_cert()
{
    RSArefPublicKey rootPub;
    RSArefPrivateKey rootPri;
    TEST_API(alg_rsa_gen_key_pair(1024, 0x10001, &rootPub, &rootPri));

    char rootKeyPem[8192];
    TEST_API(alg_rsa_export(&rootPri, rootKeyPem));
    cout << "rootKeyPem :\n" << rootKeyPem << endl;

    char rootCsr[8192];
    TEST_API(alg_csr_gen_rsa(&rootPub, &rootPri, (char *)"/CN=gmcmCA", rootCsr));
    cout << "rootCsr : \n" << rootCsr << endl;

    char rootCert[8192];
    TEST_API(alg_csr_sign_cert_rsa(rootCsr, NULL, &rootPub, &rootPri, 3650, USAGE_CA, NULL, 0, rootCert));
    cout << "rootCert :\n" << rootCert << endl;

    RSArefPublicKey usrPub;
    RSArefPrivateKey usrPri;
    TEST_API(alg_rsa_gen_key_pair(1024, 0x10001, &usrPub, &usrPri));

    char usrKeyPem[8192];
    TEST_API(alg_rsa_export(&usrPri, usrKeyPem));
    cout << "usrKeyPem :\n" << rootKeyPem << endl;

    char usrCsr[8192];
    TEST_API(alg_csr_gen_rsa(&usrPub, &usrPri, (char *)"/CN=www.islam3rd.top", usrCsr));
    cout << "usrCsr :\n" << usrCsr << endl;

    void *caCert = NULL;
    TEST_API(alg_pem_import_cert(rootCert, &caCert));

    char usrCert[8192];
    TEST_API(alg_csr_sign_cert_rsa(usrCsr, caCert, &rootPub, &rootPri, 3650, USAGE_TLS, NULL, 0, usrCert));
    cout << "usrCert :\n" << usrCert << endl;
}