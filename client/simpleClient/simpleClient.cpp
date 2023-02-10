#include <iostream>
#include "../include/gmcmSdkApi.h"
#include "utilFunc.h"

void * gDev = NULL;

int test_random()
{
    void * pSession = NULL;
    int ret;

    ret = SDF_OpenSession(gDev, &pSession);
    if (ret)
    {
        printf("SDF_OpenSession fail %d\n", ret);
    }
    else
    {
        SDK_LOG_DEBUG("SDF_OpenSession success");
    }

    unsigned char rand[8192] = {0};
    unsigned int randLen = 0;
    int count = 100;
    while (count --)
    {
        randLen = 4096;
        ret = SDF_GenerateRandom(pSession, randLen, rand);
        if (ret)
        {
            printf("SDF_GenerateRandom fail %d\n", ret);
            break;
        }
        // else
        // {
        //     utilTool::printHex(rand, randLen);
        // }
    }

    SDF_CloseSession(pSession);
    return 0;
}

int gen_sm2()
{
    void * pSession = NULL;
    int ret;

    ret = SDF_OpenSession(gDev, &pSession);
    if (ret)
    {
        printf("SDF_OpenSession fail %d\n", ret);
    }
    else
    {
        SDK_LOG_DEBUG("SDF_OpenSession success");
    }

    ECCrefPublicKey pub;
    ECCrefPrivateKey pri;

    int count = 100;
    while (count --)
    {
        ret = SDF_GenerateKeyPair_ECC(pSession, SGD_SM2, 256, &pub, &pri);
        if (ret)
        {
            printf("SDF_GenerateKeyPair_ECC fail %d\n", ret);
            break;
        }
        else
        {
            utilTool::printHex((unsigned char *)&pub, sizeof(ECCrefPublicKey), "pub");
            utilTool::printHex((unsigned char *)&pri, sizeof(ECCrefPrivateKey), "pri");
        }
    }

    SDF_CloseSession(pSession);
    return 0;
}

int enc_dec()
{
    void * pSession = NULL;
    int ret;

    ret = SDF_OpenSession(gDev, &pSession);
    if (ret)
    {
        printf("SDF_OpenSession fail %d\n", ret);
    }
    else
    {
        SDK_LOG_DEBUG("SDF_OpenSession success");
    }

    void *uiKey = NULL;
    unsigned char key[16];
    unsigned int keyLen = 16;
    unsigned char data[32];
    unsigned int dataLen;
    unsigned char encData[64];
    unsigned int encDataLen;
    unsigned char decData[64];
    unsigned int decDataLen;
    unsigned char iv[16];

    ret = SDF_GenerateRandom(pSession, keyLen, key);
    if(ret)
    {
        printf("random fail\n");
    }
    else
    {
        utilTool::printHex(key, keyLen, "key");
    }

    ret = SDF_ImportKey(pSession, key, keyLen, &uiKey);
    if(ret)
    {
        printf("import key fail\n");
    }
    else
    {
        printf("handle  [%d]\n", *(unsigned int *)uiKey);
    }

    dataLen = 32;
    ret = SDF_GenerateRandom(pSession, dataLen, data);
    if(ret)
    {
        printf("random fail\n");
    }
    else
    {
        utilTool::printHex(data, dataLen, "data");
    }

    ret = SDF_Encrypt(pSession, uiKey, SGD_SM4_ECB, iv, data, dataLen, encData, &encDataLen);
    if(ret)
    {
        printf("encrypt fail ret = %d\n", ret);
    }
    else
    {
        utilTool::printHex(encData, encDataLen, "enc");
    }

    ret = SDF_Decrypt(pSession, uiKey, SGD_SM4_ECB, iv, encData, encDataLen, decData, &decDataLen);
    if(ret)
    {
        printf("decrypt fail ret = %d\n", ret);
    }
    else
    {
        utilTool::printHex(decData, decDataLen, "dec");
    }

    dataLen = 36;
    ret = SDF_GenerateRandom(pSession, dataLen, data);
    if(ret)
    {
        printf("random fail\n");
    }
    else
    {
        utilTool::printHex(data, dataLen, "data");
    }

    ret = SDF_Encrypt(pSession, uiKey, SGD_SM4_ECB|SGD_SYM_PAD, iv, data, dataLen, encData, &encDataLen);
    if(ret)
    {
        printf("encrypt fail ret = %d\n", ret);
    }
    else
    {
        utilTool::printHex(encData, encDataLen, "enc");
    }

    ret = SDF_Decrypt(pSession, uiKey, SGD_SM4_ECB | SGD_SYM_PAD, iv, encData, encDataLen, decData, &decDataLen);
    if(ret)
    {
        printf("decrypt fail ret = %d\n", ret);
    }
    else
    {
        utilTool::printHex(decData, decDataLen, "dec");
    }

    SDF_DestroyKey(pSession, uiKey);
    SDF_CloseSession(pSession);
    return 0;
}



int main(int argc, char const *argv[])
{
    int ret;
    int choose = 999;

    ret = SDF_OpenDevice(&gDev);
    if(ret)
    {
        printf("SDF_OpenDevice fail %d\n", ret);
    }

    do
    {
        switch (choose)
        {
        case 999:
            printf("0 exit\n");
            printf("1 random\n");
            printf("2 gen sm2\n");
            printf("3 uikey enc dec\n");
            break;
        case 1:
            test_random();
            break;
        case 2:
            gen_sm2();
            break;
        case 3:
            enc_dec();
            break;

        default:
            goto end;
            break;
        }
    } while ((choose = utilTool::std_get_int(">>")));

end:
    SDF_CloseDevice(gDev);
    return 0;
}


