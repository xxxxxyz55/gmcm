#ifndef _GMCM_SDF_H_
#define _GMCM_SDF_H_

#include <stdint.h>

typedef char SGD_CHAR;
typedef char SGD_INT8;
typedef int16_t SGD_INT16;
typedef int32_t SGD_INT32;
typedef int64_t SGD_INT64;
typedef unsigned char SGD_UCHAR;
typedef uint8_t SGD_UINT8;
typedef uint16_t SGD_UINT16;
typedef uint32_t SGD_UINT32;
typedef uint64_t SGD_UINT64;
typedef uint32_t SGD_RV;
typedef void *SGD_OBJ;
typedef int32_t SGD_BOOL;

#define SGD_ECB         0x01
#define SGD_CBC         0x02
#define SGD_CFB         0x04
#define SGD_OFB         0x08
#define SGD_MAC         0x10

#define SGD_SM1			0x00000100
#define SGD_SM4			0x00000400

#define SGD_SYM_PAD     0x20

#define SGD_SM1_ECB         (SGD_SM1|SGD_ECB)
#define SGD_SM1_CBC         (SGD_SM1|SGD_CBC)
#define SGD_SM1_CFB         (SGD_SM1|SGD_CFB)
#define SGD_SM1_OFB         (SGD_SM1|SGD_OFB)
#define SGD_SM1_MAC         (SGD_SM1|SGD_MAC)

#define SGD_SM4_ECB         (SGD_SM4|SGD_ECB)
#define SGD_SM4_CBC         (SGD_SM4|SGD_CBC)
#define SGD_SM4_CFB         (SGD_SM4|SGD_CFB)
#define SGD_SM4_OFB         (SGD_SM4|SGD_OFB)
#define SGD_SM4_MAC         (SGD_SM4|SGD_MAC)

/* public key usage */
#define SGD_PK_SIGN         0x0100
#define SGD_PK_DH           0x0200
#define SGD_PK_ENC          0x0400

/* public key types */
#define SGD_RSA             0x00010000
#define SGD_RSA_SIGN        (SGD_RSA|SGD_PK_SIGN)
#define SGD_RSA_ENC         (SGD_RSA | SGD_PK_ENC)

#define SGD_SM2_0           0x00020000
#define SGD_SM2             0x00020100
#define SGD_SM2_1           0x00020200 //签名
#define SGD_SM2_2           0x00020400 //dh
#define SGD_SM2_3           0x00020800 //加密
#define SGD_SM2_SIGN        SGD_SM2_1
#define SGD_SM2_DH          SGD_SM2_2
#define SGD_SM2_ENC         SGD_SM2_3

#define SGD_SM3             0x00000001
#define SGD_SHA1            0x00000002
#define SGD_SHA256          0x00000004
#define SGD_SHA512          0x00000008
#define SGD_SHA384          0x00000010
#define SGD_SHA224          0x00000020
#define SGD_MD2             0x00000040
#define SGD_MD5             0x00000080
#define SGD_MD4             0x00000100

#define ECCref_MAX_LEN      64
#define SM2_BITS 256


typedef struct DeviceInfo_st
{
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16]; /* 8-char date +
					 * 3-char batch num +
					 * 5-char serial num
					 */
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2]; /* AsymAlgAbility[0] = algors
					 * AsymAlgAbility[1] = modulus lens
					 */
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;

typedef struct ECCrefPublicKey_st
{
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st
{
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
    unsigned char C[1];
} ECCCipher;

typedef struct ECCSignature_st
{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

typedef struct SDF_ENVELOPEDKEYBLOB
{
    unsigned long Version;
    unsigned long ulSymmAlgID;
    ECCCipher ECCCipehrBlob;
    ECCrefPublicKey PubKey;
    unsigned char cbEncryptedPrivKey[64];
} EnvelopedKeyBlob, *PEnvelopedKeyBlob;

/*RSA密钥*/
#define RSAref_MAX_BITS    2048       
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKey_st
{
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st
{
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

enum sdf_error
{
    SDR_OK,
    SDR_PARAM_NULL,
    SDR_DATA_LENGTH,
    SDR_OPER_NOT_SUPPORT,
    SDR_ALG_NOT_SUPPORT,
    SDR_UIKEY_NOT_EXIST,
    SDR_HASH_PROC,
};

#endif