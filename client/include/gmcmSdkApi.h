#ifndef _GMCM_SDK_API_H_
#define _GMCM_SDK_API_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "./gmcmSdf.h"

#ifndef SDF_EXPORT_FUNC
#define SDF_EXPORT_FUNC __attribute__((visibility("default")))
#endif


SDF_EXPORT_FUNC int SDF_OpenDevice(void **phDeviceHandle);
SDF_EXPORT_FUNC int SDF_OpenDeviceWithIp(void **phDeviceHandle, const char *ip, unsigned short port);
SDF_EXPORT_FUNC int SDF_CloseDevice(void *hDeviceHandle);
SDF_EXPORT_FUNC int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
SDF_EXPORT_FUNC int SDF_CloseSession(void *hSessionHandle);
//1
SDF_EXPORT_FUNC int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);
//2
SDF_EXPORT_FUNC int SDF_GenerateRandom(void *hSessionHandle, SGD_UINT32 uiLength, SGD_UCHAR *pucRandom);
//3
SDF_EXPORT_FUNC int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucPassword, SGD_UINT32 uiPwdLength);
//4
SDF_EXPORT_FUNC int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, SGD_UINT32 uiKeyIndex);
//5
SDF_EXPORT_FUNC int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey);
//6
SDF_EXPORT_FUNC int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey *pucPublicKey);
//7
SDF_EXPORT_FUNC int SDF_GenerateKeyPair_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
//8
SDF_EXPORT_FUNC int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, SGD_UINT32 uiIPKIndex,
                                               SGD_UINT32 uiKeyBits, ECCCipher *pucKey, void **phKeyHandle);
//9
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
//17
SDF_EXPORT_FUNC int SDF_ImportKey(void *hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, void **phKeyHandle);
//18
SDF_EXPORT_FUNC int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);
//19
SDF_EXPORT_FUNC int SDF_ExternalSign_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
//20
SDF_EXPORT_FUNC int SDF_ExternalVerify_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength,
                                           ECCSignature *pucSignature);
//21
SDF_EXPORT_FUNC int SDF_InternalSign_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
//22
SDF_EXPORT_FUNC int SDF_InternalVerify_ECC(void *hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);

//23
SDF_EXPORT_FUNC int SDF_ExternalEncrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
//24
SDF_EXPORT_FUNC int SDF_ExternalDecrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);
//25
SDF_EXPORT_FUNC int SDF_InternalEncrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiIPKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
//26
SDF_EXPORT_FUNC int SDF_InternalDecrypt_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiISKIndex, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *uiDataLength);

/*对称算法运算类函数 3个*/
//27
SDF_EXPORT_FUNC int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData,
                                SGD_UINT32 *puiEncDataLength);
//28
SDF_EXPORT_FUNC int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData,
                                SGD_UINT32 *puiDataLength);
//29
SDF_EXPORT_FUNC int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC,
                                     SGD_UINT32 *puiMACLength);

/*杂凑运算类函数 3个*/
//30
SDF_EXPORT_FUNC int SDF_HashInit(void *hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength);
//31
SDF_EXPORT_FUNC int SDF_HashUpdate(void *hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength);
//32
SDF_EXPORT_FUNC int SDF_HashFinal(void *hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength);

enum
{
    SDK_ERR_CONN        = 1001,
    SDK_ERR_SEND        = 1002,
    SDK_ERR_PARAM_NULL  = 1003,
    SDK_ERR_RECV        = 1004,
    SDK_ERR_LENGTH      = 1005,
};

#define SDK_LOG_DEBUG(fmt, ...) fprintf(stdout, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);
#define SDK_LOG_ERROR(fmt, ...) fprintf(stderr, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);

#ifdef __cplusplus
}
#endif

#endif