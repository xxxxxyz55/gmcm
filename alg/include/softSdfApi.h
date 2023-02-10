#ifndef _GMCM_SOFT_SDF_API_H_
#define _GMCM_SOFT_SDF_API_H_

#include "gmcmSdf.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef SDF_EXPORT_FUNC
#define SDF_EXPORT_FUNC
#endif

typedef struct session_cb_st
{
    int (*open_session_cb)(void *hSessionHandle);
    int (*close_session_cb)(void *hSessionHandle);
} session_cb;

typedef struct key_mgmt_meth_st
{
    int (*get_sign_pubKey_ecc)(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
    int (*get_sign_priKey_ecc)(unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey);
    int (*get_enc_pubKey_ecc)(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
    int (*get_enc_priKey_ecc)(unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey);
    int (*get_kek)(unsigned int uiKeyIndex, unsigned char *key, unsigned int *keyLen, unsigned int *keyalg);
    int (*get_priKey_access_right)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength);
    int (*realse_priKey_access_right)(void *hSessionHandle, unsigned int uiKeyIndex);
} key_mgmt_meth;

typedef struct sdf_session_st
{
    void *handle;
    int hashProc;
    unsigned char hashCtx[256];
    unsigned int hashCtxLen;
} sdf_session;

#define HASH_CTX(session) ((sdf_session *)session)->hashCtx
#define HASH_CTX_LEN(session) ((sdf_session *)session)->hashCtxLen

//设置密钥管理接口回调
SDF_EXPORT_FUNC int SDF_SetMgmtMeth(key_mgmt_meth *pKeyMeth, session_cb * pSessionMeth);
SDF_EXPORT_FUNC key_mgmt_meth *SDF_GetKeyMgmtMeth();

SDF_EXPORT_FUNC int SDF_OpenDevice(void **phDeviceHandle);
SDF_EXPORT_FUNC int SDF_CloseDevice(void *hDeviceHandle);
SDF_EXPORT_FUNC int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
SDF_EXPORT_FUNC int SDF_CloseSession(void *hSessionHandle);
SDF_EXPORT_FUNC int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);
SDF_EXPORT_FUNC int SDF_GenerateRandom(void *hSessionHandle, SGD_UINT32 uiLength, SGD_UCHAR *pucRandom);

SDF_EXPORT_FUNC int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength);
SDF_EXPORT_FUNC int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, SGD_UINT32 uiKeyIndex);

SDF_EXPORT_FUNC int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SDF_EXPORT_FUNC int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SDF_EXPORT_FUNC int SDF_GenerateKeyPair_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
SDF_EXPORT_FUNC int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, SGD_UINT32 uiIPKIndex,
                                               SGD_UINT32 uiKeyBits, ECCCipher *pucKey, void **phKeyHandle);
SDF_EXPORT_FUNC int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, SGD_UINT32 uiKeyBits,
                                               SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle);
SDF_EXPORT_FUNC int SDF_ImportKeyWithISK_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex,
                                             ECCCipher *pucKey, void **phKeyHandle);
SDF_EXPORT_FUNC int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength,
                                                     ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle);
SDF_EXPORT_FUNC int SDF_GenerateKeyWithECC(void *hSessionHandle, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
                                           ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle, void **phKeyHandle);
SDF_EXPORT_FUNC int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength,
                                                           SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
                                                           ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle);
SDF_EXPORT_FUNC int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex,
                                                       SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut);
SDF_EXPORT_FUNC int SDF_GenerateKeyWithKEK(void *hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, void **phKeyHandle);
SDF_EXPORT_FUNC int SDF_ImportKeyWithKEK(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, void **phKeyHandle);

SDF_EXPORT_FUNC int SDF_ImportKey(void *hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, void **phKeyHandle);
SDF_EXPORT_FUNC int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);

SDF_EXPORT_FUNC int SDF_ExternalSign_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SDF_EXPORT_FUNC int SDF_ExternalVerify_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength,
                                           ECCSignature *pucSignature);
SDF_EXPORT_FUNC int SDF_InternalSign_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SDF_EXPORT_FUNC int SDF_InternalVerify_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);

SDF_EXPORT_FUNC int SDF_ExternalEncrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
SDF_EXPORT_FUNC int SDF_ExternalDecrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);
SDF_EXPORT_FUNC int SDF_InternalEncrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiIPKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
SDF_EXPORT_FUNC int SDF_InternalDecrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiISKIndex, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *uiDataLength);

/*对称算法运算类函数 3个*/
SDF_EXPORT_FUNC int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData,
                                SGD_UINT32 *puiEncDataLength);
SDF_EXPORT_FUNC int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData,
                                SGD_UINT32 *puiDataLength);
SDF_EXPORT_FUNC int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC,
                                     SGD_UINT32 *puiMACLength);

/*杂凑运算类函数 3个*/
SDF_EXPORT_FUNC int SDF_HashInit(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength);
SDF_EXPORT_FUNC int SDF_HashUpdate(void *hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength);
SDF_EXPORT_FUNC int SDF_HashFinal(void *hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength);

#ifdef __cplusplus
}
#endif

#endif