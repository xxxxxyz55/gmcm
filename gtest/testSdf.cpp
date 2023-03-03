#include <iostream>
#include "softSdfApi.h"
#include "utilFunc.h"
#include <string.h>

void test_encrypt();
void test_hash();
void test_sm2_sign();
void test_sm2_enc();
#define ALG_LOG_DEBUG(fmt, ...) fprintf(stdout, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);
#define ALG_LOG_ERROR(fmt, ...) fprintf(stderr, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);

void * gDevHandle = NULL;

int main(int argc, char const *argv[])
{
    int choose = 0;
    if(argc == 1)
    {
        choose = utilTool::stdGetInt("1 test encrypt\n"
                                       "2 test hash\n"
                                       "3 test sign\n"
                                       "4 test enc\n");
    }
    else if (argc == 2)
    {
        choose = atoi(argv[1]);
    }

    if (SDF_OpenDevice(&gDevHandle))
    {
        ALG_LOG_ERROR("open dev fail.");
        return 0;
    }

    switch (choose)
    {
    case 1:
        test_encrypt();
        break;
    case 2:
        test_hash();
        break;
    case 3:
        test_sm2_sign();
        break;
    case 4:
        test_sm2_enc();
        break;

    default:
        break;
    }

    SDF_CloseDevice(gDevHandle);
    return 0;
}

typedef struct encrypt_buffer_st
{
    unsigned char data[8192];
    unsigned int dataLen;
    unsigned char enc[8192 + 16];
    unsigned int encLen;
    unsigned char dec[8192 + 16];
    unsigned int decLen;
    unsigned int algid;
    unsigned char ivIn[16];
    unsigned char ivOut[16];
} encrypt_buffer;

void printf_encrypt_buffer(encrypt_buffer *encData)
{
    utilTool::printHex(encData->data, encData->dataLen, "data");
    printf("alg : %d\n", encData->algid);
    utilTool::printHex(encData->ivIn, sizeof(encData->ivIn), "iv");
    utilTool::printHex(encData->enc, encData->encLen, "enc");
    utilTool::printHex(encData->dec, encData->decLen, "dec");
}

void test_sm4_enc(void *hSessionHandle, void *pKey, encrypt_buffer *encData)
{
    int iRet = 0;

    memcpy(encData->ivOut, encData->ivIn, 16);
    iRet = SDF_Encrypt(hSessionHandle, pKey, encData->algid, encData->ivOut,
                       encData->data, encData->dataLen, encData->enc, &encData->encLen);
    if (iRet)
    {
        ALG_LOG_ERROR("SDF_Encrypt fail %d.", iRet)
        return;
    }

    memcpy(encData->ivOut, encData->ivIn, 16);
    iRet = SDF_Decrypt(hSessionHandle, pKey, encData->algid, encData->ivOut,
                       encData->enc, encData->encLen, encData->dec, &encData->decLen);
    if (iRet)
    {
        ALG_LOG_ERROR("SDF_Decrypt fail %d.", iRet)
        return;
    }

    if (memcmp(encData->data, encData->dec, encData->dataLen))
    {
        ALG_LOG_ERROR("memcpy src with dec fail.")
    }

    printf_encrypt_buffer(encData);
}

void test_encrypt()
{
    void *hSessionHandle = NULL;
    int iRet = 0;

    iRet = SDF_OpenSession(gDevHandle, &hSessionHandle);
    if(iRet)
    {
        ALG_LOG_ERROR("SDF_OpenSession fail %d.", iRet)
    }
    else
    {
        void *pkey = NULL;
        unsigned char key[16] = {0x31, 0x32, 0x33, 0x34, 0x34, 0x36, 0x37, 0x38,
                                 0x31, 0x32, 0x33, 0x34, 0x34, 0x36, 0x37, 0x38};
        unsigned int keyLen = 16;

        iRet = SDF_ImportKey(hSessionHandle, key, keyLen, &pkey);
        if (iRet)
        {
            ALG_LOG_ERROR("hSessionHandle fail %d.", iRet)
        }
        else
        {
            encrypt_buffer encData = {0};
            encData.algid = SGD_SM4_ECB;
            encData.dataLen = 16;
            test_sm4_enc(hSessionHandle, pkey, &encData);

            encData.algid = SGD_SM4_ECB | SGD_SYM_PAD;
            encData.dataLen = 8;
            test_sm4_enc(hSessionHandle, pkey, &encData);
        }

        SDF_DestroyKey(hSessionHandle, pkey);
        SDF_CloseSession(hSessionHandle);
    }
}

void test_hash()
{
    void *hSessionHandle = NULL;
    int iRet = 0;

    iRet = SDF_OpenSession(gDevHandle, &hSessionHandle);
    if(iRet)
    {
        ALG_LOG_ERROR("SDF_OpenSession fail %d.", iRet)
    }
    else
    {
        unsigned char data[16] = {0};
        unsigned int dataLen = 16;
        unsigned char hash[32] = {0};
        unsigned int hashLen = 0;
        unsigned char id[32] = "1234567812345678";
        unsigned int idLen = 16;

        {

            SDF_HashInit(hSessionHandle, SGD_SM3, NULL, NULL, 0);
            SDF_HashUpdate(hSessionHandle, data, dataLen);
            SDF_HashFinal(hSessionHandle, hash, &hashLen);

            utilTool::printHex(data, dataLen, "data");
            utilTool::printHex(hash, hashLen, "hash");
        }

        {
            ECCrefPublicKey pub = {0};
            ECCrefPrivateKey pri = {0};

            iRet = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2, 256, &pub, &pri);
            if (iRet)
            {
                ALG_LOG_ERROR("SDF_HashFinal fail %d.", iRet)
            }

            SDF_HashInit(hSessionHandle, SGD_SM3, &pub, id, idLen);
            SDF_HashUpdate(hSessionHandle, data, dataLen);
            SDF_HashFinal(hSessionHandle, hash, &hashLen);

            utilTool::printHex(data, dataLen, "data");
            utilTool::printHex(pub.x, 64, "pub-x");
            utilTool::printHex(pub.y, 64, "pub-y");
            utilTool::printHex(hash, hashLen, "hash with Id");
        }

        SDF_CloseSession(hSessionHandle);
    }
}

void test_sm2_sign()
{
    void *hSessionHandle = NULL;
    int iRet = 0;

    iRet = SDF_OpenSession(gDevHandle, &hSessionHandle);
    if(iRet)
    {
        ALG_LOG_ERROR("SDF_OpenSession fail %d.", iRet)
        return;
    }
    else
    {
        ECCrefPublicKey pub = {0};
        ECCrefPrivateKey pri = {0};
        unsigned char data[32] = {0};
        unsigned char dataLen = 32;
        ECCSignature sign = {0};

        iRet = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2, 256, &pub, &pri);
        if (iRet)
        {
            ALG_LOG_ERROR("SDF_GenerateKeyPair_ECC fail %d.", iRet)
        }
        utilTool::printHex(pub.x, 64, "pub.x");
        utilTool::printHex(pub.y, 64, "pub.y");
        utilTool::printHex(pri.K, 64, "pub.K");

        iRet = SDF_ExternalSign_ECC(hSessionHandle, SGD_SM2, &pri, data, dataLen, &sign);
        if (iRet)
        {
            ALG_LOG_ERROR("SDF_ExternalSign_ECC fail %d.", iRet)
        }
        utilTool::printHex(sign.r, 64, "sign->r");
        utilTool::printHex(sign.s, 64, "sign->s");

        iRet = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2, &pub, data, dataLen, &sign);
        if (iRet)
        {
            ALG_LOG_ERROR("SDF_ExternalVerify_ECC fail %d.", iRet)
        }

        SDF_CloseSession(hSessionHandle);
    }
}

void test_sm2_enc()
{
    void *hSessionHandle = NULL;
    int iRet = 0;

    iRet = SDF_OpenSession(gDevHandle, &hSessionHandle);
    if(iRet)
    {
        ALG_LOG_ERROR("SDF_OpenSession fail %d.", iRet)
        return;
    }
    else
    {
        ECCrefPublicKey pub = {0};
        ECCrefPrivateKey pri = {0};
        unsigned char data[32] = {0};
        unsigned int dataLen = 32;
        unsigned char dec[1024] = {0};
        unsigned int decLen = 0;
        ECCCipher *cipher = (ECCCipher *)calloc(1, sizeof(ECCCipher) + dataLen);

        iRet = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2, 256, &pub, &pri);
        if (iRet)
        {
            ALG_LOG_ERROR("SDF_GenerateKeyPair_ECC fail %d.", iRet)
        }

        iRet = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2, &pub, data, dataLen, cipher);
        if(iRet)
        {
            ALG_LOG_ERROR("SDF_ExternalEncrypt_ECC fail %d.", iRet)
        }

        iRet = SDF_ExternalDecrypt_ECC(hSessionHandle, SGD_SM2, &pri, cipher, dec, &decLen);
        if(iRet)
        {
            ALG_LOG_ERROR("SDF_ExternalDecrypt_ECC fail %d.", iRet)
        }

        if(memcmp(data, dec, dataLen))
        {
            ALG_LOG_ERROR("memcmp fail %d.", iRet)
        }
        free(cipher);
        SDF_CloseSession(hSessionHandle);
    }
}