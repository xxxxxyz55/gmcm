#include <iostream>
#include "gmcmalgConf.h"
#include "../include/softSdfApi.h"
#include "../include/algApi.h"
#include <string.h>
#include "uiKey.h"

using namespace std;

#define DEV_HANDLE(pDev)          ((sdf_dev *)pDev)
#define DEV_HKEY(pDev)            ((uiKeyArray *)(DEV_HANDLE(pDev)->sessionKeyMgmt))
#define SESSION_HANDLE(pSession)  ((sdf_session *)pSession)
#define SESSION_HKEY(pSession)    DEV_HKEY(SESSION_HANDLE(pSession)->pDev)
#define SESSION_METH(pSession)    SESSION_HANDLE(pSession)->pDev->sessionMeth
#define SESSION_KEYMETH(pSession) SESSION_HANDLE(pSession)->pDev->keyMgmtMeth

int SDF_OpenDevice(void **phDeviceHandle)
{
    sdf_dev * pDev = new sdf_dev;
    pDev->sessionKeyMgmt = new uiKeyArray(0);
    *phDeviceHandle = pDev;
    return 0;
}

int SDF_CloseDevice(void *hDeviceHandle)
{
    if (hDeviceHandle)
    {
        if(DEV_HANDLE(hDeviceHandle)->sessionMeth && DEV_HANDLE(hDeviceHandle)->sessionMeth->close)
        {
            DEV_HANDLE(hDeviceHandle)->sessionMeth->close(DEV_HANDLE(hDeviceHandle)->sessionMeth->obj);
        }

        if (DEV_HANDLE(hDeviceHandle)->keyMgmtMeth && DEV_HANDLE(hDeviceHandle)->keyMgmtMeth->close)
        {
            DEV_HANDLE(hDeviceHandle)->keyMgmtMeth->close(DEV_HANDLE(hDeviceHandle)->keyMgmtMeth->obj);
        }
        delete DEV_HKEY(hDeviceHandle);
        delete DEV_HANDLE(hDeviceHandle);
    }
    return 0;
}

int SDF_OpenDeviceWithCb(void **phDeviceHandle, session_meth *pSessionMeth,
                           key_mgmt_meth *pKeyMeth, int hKeyTimeout)
{
    sdf_dev * pDev = new sdf_dev;
    pDev->sessionMeth = pSessionMeth;
    pDev->keyMgmtMeth = pKeyMeth;
    pDev->sessionKeyMgmt = new uiKeyArray(hKeyTimeout);
    *phDeviceHandle = pDev;
    return 0;
}

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    if(hDeviceHandle == NULL)
    {
        return -1;
    }

    *phSessionHandle = new sdf_session;
    SESSION_HANDLE(*phSessionHandle)->pDev = (sdf_dev *)hDeviceHandle;
    SESSION_HANDLE(*phSessionHandle)->hashCtxLen = 256;
    if (SESSION_METH(*phSessionHandle) && SESSION_METH(*phSessionHandle)->open_session_cb)
    {
        return SESSION_METH(*phSessionHandle)->open_session_cb(((sdf_session *)*phSessionHandle)->handle);
    }
    return 0;
}

int SDF_CloseSession(void *hSessionHandle)
{
    if(hSessionHandle == NULL)
    {
        return 0;
    }

    if (SESSION_METH(hSessionHandle) && SESSION_METH(hSessionHandle)->close_session_cb)
    {
        return SESSION_METH(hSessionHandle)->close_session_cb(((sdf_session *)hSessionHandle)->handle);
    }
    delete SESSION_HANDLE(hSessionHandle);

    return 0;
}

int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo)
{
    if (pstDeviceInfo == NULL)
    {
        return SDR_PARAM_NULL;
    }

    memcpy(pstDeviceInfo->IssuerName, "gmcm", 4);
    memcpy(pstDeviceInfo->DeviceName, "gmcm alg lib", 12);
    memcpy(pstDeviceInfo->DeviceName, "000", 3);
    pstDeviceInfo->DeviceVersion = 0x0101;
    pstDeviceInfo->StandardVersion = 0x0100;
    pstDeviceInfo->AsymAlgAbility[0] = SGD_SM2;
    pstDeviceInfo->AsymAlgAbility[1] = 256;
    pstDeviceInfo->SymAlgAbility = SGD_SM4;
    pstDeviceInfo->HashAlgAbility = SGD_SM3;
    pstDeviceInfo->BufferSize = 1024 * 1024 * 1024;

    return 0;
}

int SDF_GenerateRandom(void *hSessionHandle, SGD_UINT32 uiLength, SGD_UCHAR *pucRandom)
{
    if (pucRandom == NULL)
    {
        return SDR_PARAM_NULL;
    }

    if(uiLength > 8192)
    {
        return SDR_DATA_LENGTH;
    }

    return alg_random(uiLength, pucRandom);
}

int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength)
{
    if (SESSION_KEYMETH(hSessionHandle) && SESSION_KEYMETH(hSessionHandle)->get_priKey_access_right)
    {
        return SESSION_KEYMETH(hSessionHandle)->get_priKey_access_right(hSessionHandle, uiKeyIndex, pucPassword, uiPwdLength);
    }
    return 0;
}

int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, SGD_UINT32 uiKeyIndex)
{
    if (SESSION_KEYMETH(hSessionHandle) && SESSION_KEYMETH(hSessionHandle)->realse_priKey_access_right)
    {
        return SESSION_KEYMETH(hSessionHandle)->realse_priKey_access_right(hSessionHandle, uiKeyIndex);
    }
    return 0;
}

int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    if(SESSION_KEYMETH(hSessionHandle) == NULL || SESSION_KEYMETH(hSessionHandle)->get_sign_pubKey_ecc == NULL)
    {
        return SDR_OPER_NOT_SUPPORT;
    }
    else
    {
        return SESSION_KEYMETH(hSessionHandle)->get_sign_pubKey_ecc(uiKeyIndex, pucPublicKey);
    }
    
    return 0;
}

int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    if(SESSION_KEYMETH(hSessionHandle) == NULL || SESSION_KEYMETH(hSessionHandle)->get_sign_pubKey_ecc == NULL)
    {
        return SDR_OPER_NOT_SUPPORT;
    }
    else
    {
        return SESSION_KEYMETH(hSessionHandle)->get_enc_pubKey_ecc(uiKeyIndex, pucPublicKey);
    }

    return 0;
}

int SDF_GenerateKeyPair_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    if ((uiAlgID & SGD_SM2) == 0)
    {
        return SDR_ALG_NOT_SUPPORT;
    }

    return alg_sm2_gen_key_pair(pucPublicKey, pucPrivateKey);
}

int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, SGD_UINT32 uiIPKIndex,
                               SGD_UINT32 uiKeyBits, ECCCipher *pucKey, void **phKeyHandle)
{
    if(hSessionHandle == NULL || pucKey == NULL || phKeyHandle == NULL)
    {
        return SDR_PARAM_NULL;
    }

    return 0;
}

int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, SGD_UINT32 uiKeyBits,
                               SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle)
{
    return 0;
}
int SDF_ImportKeyWithISK_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex,
                             ECCCipher *pucKey, void **phKeyHandle)
{
    return 0;
}

int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength,
                                     ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle)
{
    return 0;
}

int SDF_GenerateKeyWithECC(void *hSessionHandle, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
                           ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle, void **phKeyHandle)
{
    return 0;
}

int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength,
                                           SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
                                           ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle)
{
    return 0;
}

int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex,
                                       SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut)
{
    return 0;
}

int SDF_GenerateKeyWithKEK(void *hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, void **phKeyHandle)
{
    return 0;
}

int SDF_ImportKeyWithKEK(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, void **phKeyHandle)
{
    return 0;
}

int SDF_ImportKey(void *hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, void **phKeyHandle)
{
    if(hSessionHandle == NULL || pucKey == NULL || phKeyHandle == NULL)
    {
        return SDR_PARAM_NULL;
    }

    if(uiKeyLength != 16)
    {
        return SDR_DATA_LENGTH;
    }

    return SESSION_HKEY(hSessionHandle)->import_key(pucKey, uiKeyLength, phKeyHandle);
}

int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL)
    {
        return SDR_PARAM_NULL;
    }

    return SESSION_HKEY(hSessionHandle)->delKey(hKeyHandle);
}

int SDF_ExternalSign_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature)
{
    if (hSessionHandle == NULL || pucPrivateKey == NULL || pucData == NULL || pucSignature == NULL)
    {
        return SDR_PARAM_NULL;
    }

    return alg_sm2_sign(pucPrivateKey, pucData, uiDataLength, pucSignature);
}

int SDF_ExternalVerify_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength,
                           ECCSignature *pucSignature)
{
    if (hSessionHandle == NULL || pucPublicKey == NULL || pucDataInput == NULL || pucSignature == NULL)
    {
        return SDR_PARAM_NULL;
    }

    return alg_sm2_verify(pucPublicKey, pucDataInput, uiInputLength, pucSignature);
}

int SDF_InternalSign_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature)
{
    return 0;
}

int SDF_InternalVerify_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature)
{
    return 0;
}

int SDF_ExternalEncrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey,
                            SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData)
{
    if (hSessionHandle == NULL || pucPublicKey == NULL || pucData == NULL || pucEncData == NULL)
    {
        return SDR_PARAM_NULL;
    }

    return alg_sm2_pub_encrypt(pucPublicKey, pucData, uiDataLength, pucEncData);
}

int SDF_ExternalDecrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey,
                            ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength)
{
    if (hSessionHandle == NULL || pucPrivateKey == NULL || pucData == NULL || pucEncData == NULL)
    {
        return SDR_PARAM_NULL;
    }

    return alg_sm2_pri_decrypt(pucPrivateKey, pucEncData, pucData, puiDataLength);
}

int SDF_InternalEncrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiIPKIndex,
                            SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData)
{
    return 0;
}

int SDF_InternalDecrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiISKIndex,
                            ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *uiDataLength)
{
    return 0;
}

/*??????????????????????????? 3???*/
int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV,
                SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLength)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL || pucData == NULL || pucEncData == NULL || puiEncDataLength == NULL)
    {
        return SDR_PARAM_NULL;
    }

    if (uiDataLength > MAX_DATA_LEN + 16)
    {
        return SDR_DATA_LENGTH;
    }

    if (!(uiAlgID & SGD_SM4))
    {
        return SDR_ALG_NOT_SUPPORT;
    }

    if(!(uiAlgID &SGD_ECB) && pucIV == NULL)
    {
        return SDR_PARAM_NULL;
    }

    unsigned char key[16];
    unsigned int keyLen;
    if (SESSION_HKEY(hSessionHandle)->getKey(hKeyHandle, key, &keyLen) || keyLen < 16)
    {
        return SDR_UIKEY_NOT_EXIST;
    }

    return alg_sm4_encrypt(key, uiAlgID & (~SGD_SYM_PAD), uiAlgID & SGD_SYM_PAD, pucData, uiDataLength, pucIV, 16, pucEncData, puiEncDataLength);
}

int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData,
                SGD_UINT32 *puiDataLength)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL || pucData == NULL || pucEncData == NULL || puiDataLength == NULL)
    {
        return SDR_PARAM_NULL;
    }

    if(uiEncDataLength > MAX_DATA_LEN + 16)
    {
        return SDR_DATA_LENGTH;
    }

    if (!(uiAlgID & SGD_SM4))
    {
        return SDR_ALG_NOT_SUPPORT;
    }

    if (!(uiAlgID & SGD_ECB) && pucIV == NULL)
    {
        return SDR_PARAM_NULL;
    }

    unsigned char key[16];
    unsigned int keyLen;
    if (SESSION_HKEY(hSessionHandle)->getKey(hKeyHandle, key, &keyLen) || keyLen < 16)
    {
        printf("handle not exist [%d]\n", *(unsigned int *)hKeyHandle);
        return SDR_UIKEY_NOT_EXIST;
    }

    return alg_sm4_decrypt(key, uiAlgID & (~SGD_SYM_PAD), uiAlgID & SGD_SYM_PAD, pucEncData, uiEncDataLength, pucIV, 16, pucData, puiDataLength);
}

int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC,
                     SGD_UINT32 *puiMACLength)
{
    if (pucMAC == NULL)
    {
        return SDR_PARAM_NULL;
    }

    unsigned char enc[MAX_DATA_LEN + 16];
    int iRet = SDF_Encrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, enc, puiMACLength);
    if (iRet)
    {
        return iRet;
    }

    memcpy(pucMAC, enc + *puiMACLength - 16, 16);
    *puiMACLength = 16;
    return SDR_OK;
}

/*????????????????????? 3???*/
int SDF_HashInit(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength)
{
    if(hSessionHandle == NULL)
    {
        return SDR_PARAM_NULL;
    }

    if (!(uiAlgID & SGD_SM3))
    {
        return SDR_ALG_NOT_SUPPORT;
    }

    sdf_session *pSession = (sdf_session *)hSessionHandle;
    pSession->hashProc = 1;
    if (pucPublicKey == NULL || pucID == NULL || uiIDLength == 0)
    {
        return alg_sm3_init(pSession->hashCtx, &pSession->hashCtxLen, NULL, NULL, NULL, 0);
    }
    else
    {
        return alg_sm3_init(pSession->hashCtx, &pSession->hashCtxLen, pucPublicKey->x + 32, pucPublicKey->y + 32, pucID, uiIDLength);
    }
}

int SDF_HashUpdate(void *hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength)
{
    if(hSessionHandle == NULL || pucData == NULL)
    {
        return SDR_PARAM_NULL;
    }

    sdf_session * pSession = (sdf_session *)hSessionHandle;
    if(pSession->hashProc != 2 && pSession->hashProc != 1)
    {
        return SDR_HASH_PROC;
    }

    pSession->hashProc = 2;

    alg_sm3_update(pSession->hashCtx, pucData, uiDataLength);

    return SDR_OK;
}

int SDF_HashFinal(void *hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength)
{
    if (hSessionHandle == NULL || pucHash == NULL || puiHashLength == NULL)
    {
        return SDR_PARAM_NULL;
    }

    sdf_session *pSession = (sdf_session *)hSessionHandle;
    if (pSession->hashProc != 2)
    {
        return SDR_HASH_PROC;
    }

    pSession->hashProc = 0;

    alg_sm3_final(pSession->hashCtx, pucHash);
    *puiHashLength = 32;
    return SDR_OK;
}
