#ifndef _SDF_EX_H_
#define _SDF_EX_H_
#include "gmcmSdf.h"

typedef int (*SDF_OpenDevice_FuncPtr)(
    void **phDeviceHandle);

typedef int (*SDF_CloseDevice_FuncPtr)(
    void *hDeviceHandle);

typedef int (*SDF_OpenSession_FuncPtr)(
    void *hDeviceHandle,
    void **phSessionHandle);

typedef int (*SDF_CloseSession_FuncPtr)(
    void *hSessionHandle);

typedef int (*SDF_GetDeviceInfo_FuncPtr)(
    void *hSessionHandle,
    DEVICEINFO *pstDeviceInfo);

typedef int (*SDF_GenerateRandom_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiLength,
    unsigned char *pucRandom);

typedef int (*SDF_GetPrivateKeyAccessRight_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    unsigned char *pucPassword,
    unsigned int uiPwdLength);

typedef int (*SDF_ReleasePrivateKeyAccessRight_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex);

typedef int (*SDF_ExportSignPublicKey_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    RSArefPublicKey *pucPublicKey);

typedef int (*SDF_ExportEncPublicKey_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    RSArefPublicKey *pucPublicKey);

typedef int (*SDF_GenerateKeyPair_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyBits,
    RSArefPublicKey *pucPublicKey,
    RSArefPrivateKey *pucPrivateKey);

typedef int (*SDF_GenerateKeyWithIPK_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiIPKIndex,
    unsigned int uiKeyBits,
    unsigned char *pucKey,
    unsigned int *puiKeyLength,
    void **phKeyHandle);

typedef int (*SDF_GenerateKeyWithEPK_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyBits,
    RSArefPublicKey *pucPublicKey,
    unsigned char *pucKey,
    unsigned int *puiKeyLength,
    void **phKeyHandle);

typedef int (*SDF_ImportKeyWithISK_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiISKIndex,
    unsigned char *pucKey,
    unsigned int uiKeyLength,
    void **phKeyHandle);

typedef int (*SDF_ExchangeDigitEnvelopeBaseOnRSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    RSArefPublicKey *pucPublicKey,
    unsigned char *pucDEInput,
    unsigned int uiDELength,
    unsigned char *pucDEOutput,
    unsigned int *puiDELength);

typedef int (*SDF_ExportSignPublicKey_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    ECCrefPublicKey *pucPublicKey);

typedef int (*SDF_ExportEncPublicKey_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    ECCrefPublicKey *pucPublicKey);

typedef int (*SDF_GenerateKeyPair_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiAlgID,
    unsigned int uiKeyBits,
    ECCrefPublicKey *pucPublicKey,
    ECCrefPrivateKey *pucPrivateKey);

typedef int (*SDF_GenerateKeyWithIPK_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiIPKIndex,
    unsigned int uiKeyBits,
    ECCCipher *pucKey,
    void **phKeyHandle);

typedef int (*SDF_GenerateKeyWithEPK_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyBits,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucKey,
    void **phKeyHandle);

typedef int (*SDF_ImportKeyWithISK_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiISKIndex,
    ECCCipher *pucKey,
    void **phKeyHandle);

typedef int (*SDF_GenerateAgreementDataWithECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiISKIndex,
    unsigned int uiKeyBits,
    unsigned char *pucSponsorID,
    unsigned int uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    void **phAgreementHandle);

typedef int (*SDF_GenerateKeyWithECC_FuncPtr)(
    void *hSessionHandle,
    unsigned char *pucResponseID,
    unsigned int uiResponseIDLength,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle,
    void **phKeyHandle);

typedef int (*SDF_GenerateAgreementDataAndKeyWithECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiISKIndex,
    unsigned int uiKeyBits,
    unsigned char *pucResponseID,
    unsigned int uiResponseIDLength,
    unsigned char *pucSponsorID,
    unsigned int uiSponsorIDLength,
    ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey,
    void **phKeyHandle);

typedef int (*SDF_ExchangeDigitEnvelopeBaseOnECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    ECCCipher *pucEncDataIn,
    ECCCipher *pucEncDataOut);

typedef int (*SDF_GenerateKeyWithKEK_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyBits,
    unsigned int uiAlgID,
    unsigned int uiKEKIndex,
    unsigned char *pucKey,
    unsigned int *puiKeyLength,
    void **phKeyHandle);

typedef int (*SDF_ImportKeyWithKEK_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiAlgID,
    unsigned int uiKEKIndex,
    unsigned char *pucKey,
    unsigned int uiKeyLength,
    void **phKeyHandle);

typedef int (*SDF_ImportKey_FuncPtr)(
    void *hSessionHandle,
    unsigned char *pucKey,
    unsigned int uiKeyLength,
    void *hKeyHandle);

typedef int (*SDF_DestroyKey_FuncPtr)(
    void *hSessionHandle,
    void *hKeyHandle);

typedef int (*SDF_ExternalPublicKeyOperation_RSA_FuncPtr)(
    void *hSessionHandle,
    RSArefPublicKey *pucPublicKey,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

typedef int (*SDF_InternalPublicKeyOperation_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

typedef int (*SDF_InternalPrivateKeyOperation_RSA_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiKeyIndex,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

typedef int (*SDF_ExternalSign_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiAlgID,
    ECCrefPrivateKey *pucPrivateKey,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    ECCSignature *pucSignature);

typedef int (*SDF_ExternalVerify_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    ECCSignature *pucSignature);

typedef int (*SDF_InternalSign_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiISKIndex,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCSignature *pucSignature);

typedef int (*SDF_InternalVerify_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiIPKIndex,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCSignature *pucSignature);

typedef int (*SDF_ExternalEncrypt_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCCipher *pucEncData);

typedef int (*SDF_ExternalDecrypt_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiAlgID,
    ECCrefPrivateKey *pucPrivateKey,
    ECCCipher *pucEncData,
    unsigned char *pucData,
    unsigned int *puiDataLength);

typedef int (*SDF_InternalEncrypt_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiIPKIndex,
    unsigned int uiAlgID,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCCipher *pucEncData);

typedef int (*SDF_InternalDecrypt_ECC_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiISKIndex,
    unsigned int uiAlgID,
    ECCCipher *pucEncData,
    unsigned char *pucData,
    unsigned int *puiDataLength);

typedef int (*SDF_Encrypt_FuncPtr)(
    void *hSessionHandle,
    void *hKeyHandle,
    unsigned int uiAlgID,
    unsigned char *pucIV,
    unsigned char *pucData,
    unsigned int uiDataLength,
    unsigned char *pucEncData,
    unsigned int *puiEncDataLength);

typedef int (*SDF_Decrypt_FuncPtr)(
    void *hSessionHandle,
    void *hKeyHandle,
    unsigned int uiAlgID,
    unsigned char *pucIV,
    unsigned char *pucEncData,
    unsigned int uiEncDataLength,
    unsigned char *pucData,
    unsigned int *puiDataLength);

typedef int (*SDF_CalculateMAC_FuncPtr)(
    void *hSessionHandle,
    void *hKeyHandle,
    unsigned int uiAlgID,
    unsigned char *pucIV,
    unsigned char *pucData,
    unsigned int uiDataLength,
    unsigned char *pucMAC,
    unsigned int *puiMACLength);

typedef int (*SDF_HashInit_FuncPtr)(
    void *hSessionHandle,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    unsigned char *pucID,
    unsigned int uiIDLength);

typedef int (*SDF_HashUpdate_FuncPtr)(
    void *hSessionHandle,
    unsigned char *pucData,
    unsigned int uiDataLength);

typedef int (*SDF_HashFinal_FuncPtr)(void *hSessionHandle,
                                     unsigned char *pucHash,
                                     unsigned int *puiHashLength);

typedef int (*SDF_CreateObject_FuncPtr)(
    void *hSessionHandle,
    unsigned char *pucFileName,
    unsigned int uiNameLen,
    unsigned int uiFileSize);

typedef int (*SDF_ReadObject_FuncPtr)(
    void *hSessionHandle,
    unsigned char *pucFileName,
    unsigned int uiNameLen,
    unsigned int uiOffset,
    unsigned int *puiReadLength,
    unsigned char *pucBuffer);

typedef int (*SDF_WriteObject_FuncPtr)(
    void *hSessionHandle,
    unsigned char *pucFileName,
    unsigned int uiNameLen,
    unsigned int uiOffset,
    unsigned int uiWriteLength,
    unsigned char *pucBuffer);

typedef int (*SDF_DeleteObject_FuncPtr)(
    void *hSessionHandle,
    unsigned char *pucFileName,
    unsigned int uiNameLen);

typedef struct sdf_method_st
{
    SDF_OpenDevice_FuncPtr OpenDevice;
    const char * OpenDevice_FuncName;
    SDF_CloseDevice_FuncPtr CloseDevice;
    const char * CloseDevice_FuncName;
    SDF_OpenSession_FuncPtr OpenSession;
    const char * OpenSession_FuncName;
    SDF_CloseSession_FuncPtr CloseSession;
    const char * CloseSession_FuncName;
    SDF_GetDeviceInfo_FuncPtr GetDeviceInfo;
    const char * GetDeviceInfo_FuncName;
    SDF_GenerateRandom_FuncPtr GenerateRandom;
    const char * GenerateRandom_FuncName;

    SDF_GetPrivateKeyAccessRight_FuncPtr GetPrivateKeyAccessRight;
    const char * GetPrivateKeyAccessRight_FuncName;
    SDF_ReleasePrivateKeyAccessRight_FuncPtr ReleasePrivateKeyAccessRight;
    const char * ReleasePrivateKeyAccessRight_FuncName;

    SDF_ExportSignPublicKey_RSA_FuncPtr ExportSignPublicKey_RSA;
    const char * ExportSignPublicKey_RSA_FuncName;
    SDF_ExportEncPublicKey_RSA_FuncPtr ExportEncPublicKey_RSA;
    const char * ExportEncPublicKey_RSA_FuncName;
    SDF_GenerateKeyPair_RSA_FuncPtr GenerateKeyPair_RSA;
    const char * GenerateKeyPair_RSA_FuncName;
    SDF_GenerateKeyWithIPK_RSA_FuncPtr GenerateKeyWithIPK_RSA;
    const char * GenerateKeyWithIPK_RSA_FuncName;
    SDF_GenerateKeyWithEPK_RSA_FuncPtr GenerateKeyWithEPK_RSA;
    const char * GenerateKeyWithEPK_RSA_FuncName;
    SDF_ImportKeyWithISK_RSA_FuncPtr ImportKeyWithISK_RSA;
    const char * ImportKeyWithISK_RSA_FuncName;
    SDF_ExchangeDigitEnvelopeBaseOnRSA_FuncPtr ExchangeDigitEnvelopeBaseOnRSA;
    const char * ExchangeDigitEnvelopeBaseOnRSA_FuncName;

    SDF_ExportSignPublicKey_ECC_FuncPtr ExportSignPublicKey_ECC;
    const char * ExportSignPublicKey_ECC_FuncName;
    SDF_ExportEncPublicKey_ECC_FuncPtr ExportEncPublicKey_ECC;
    const char * ExportEncPublicKey_ECC_FuncName;
    SDF_GenerateKeyPair_ECC_FuncPtr GenerateKeyPair_ECC;
    const char * GenerateKeyPair_ECC_FuncName;
    SDF_GenerateKeyWithIPK_ECC_FuncPtr GenerateKeyWithIPK_ECC;
    const char * GenerateKeyWithIPK_ECC_FuncName;
    SDF_GenerateKeyWithEPK_ECC_FuncPtr GenerateKeyWithEPK_ECC;
    const char * GenerateKeyWithEPK_ECC_FuncName;
    SDF_ImportKeyWithISK_ECC_FuncPtr ImportKeyWithISK_ECC;
    const char * ImportKeyWithISK_ECC_FuncName;

    SDF_GenerateAgreementDataWithECC_FuncPtr GenerateAgreementDataWithECC;
    const char * GenerateAgreementDataWithECC_FuncName;
    SDF_GenerateKeyWithECC_FuncPtr GenerateKeyWithECC;
    const char * GenerateKeyWithECC_FuncName;
    SDF_GenerateAgreementDataAndKeyWithECC_FuncPtr GenerateAgreementDataAndKeyWithECC;
    const char * GenerateAgreementDataAndKeyWithECC_FuncName;

    SDF_ExchangeDigitEnvelopeBaseOnECC_FuncPtr ExchangeDigitEnvelopeBaseOnECC;
    const char * ExchangeDigitEnvelopeBaseOnECC_FuncName;

    SDF_GenerateKeyWithKEK_FuncPtr GenerateKeyWithKEK;
    const char * GenerateKeyWithKEK_FuncName;
    SDF_ImportKeyWithKEK_FuncPtr ImportKeyWithKEK;
    const char * ImportKeyWithKEK_FuncName;
    SDF_ImportKey_FuncPtr ImportKey;
    const char * ImportKey_FuncName;
    SDF_DestroyKey_FuncPtr DestroyKey;
    const char * DestroyKey_FuncName;

    SDF_ExternalPublicKeyOperation_RSA_FuncPtr ExternalPublicKeyOperation_RSA;
    const char * ExternalPublicKeyOperation_RSA_FuncName;
    SDF_InternalPublicKeyOperation_RSA_FuncPtr InternalPublicKeyOperation_RSA;
    const char * InternalPublicKeyOperation_RSA_FuncName;
    SDF_InternalPrivateKeyOperation_RSA_FuncPtr InternalPrivateKeyOperation_RSA;
    const char * InternalPrivateKeyOperation_RSA_FuncName;

    SDF_ExternalSign_ECC_FuncPtr ExternalSign_ECC;
    const char * ExternalSign_ECC_FuncName;
    SDF_ExternalVerify_ECC_FuncPtr ExternalVerify_ECC;
    const char * ExternalVerify_ECC_FuncName;
    SDF_InternalSign_ECC_FuncPtr InternalSign_ECC;
    const char * InternalSign_ECC_FuncName;
    SDF_InternalVerify_ECC_FuncPtr InternalVerify_ECC;
    const char * InternalVerify_ECC_FuncName;

    SDF_ExternalEncrypt_ECC_FuncPtr ExternalEncrypt_ECC;
    const char * ExternalEncrypt_ECC_FuncName;
    SDF_ExternalDecrypt_ECC_FuncPtr ExternalDecrypt_ECC;
    const char * ExternalDecrypt_ECC_FuncName;
    SDF_InternalEncrypt_ECC_FuncPtr InternalEncrypt_ECC;
    const char * InternalEncrypt_ECC_FuncName;
    SDF_InternalDecrypt_ECC_FuncPtr InternalDecrypt_ECC;
    const char * InternalDecrypt_ECC_FuncName;

    SDF_Encrypt_FuncPtr Encrypt;
    const char * Encrypt_FuncName;
    SDF_Decrypt_FuncPtr Decrypt;
    const char * Decrypt_FuncName;
    SDF_CalculateMAC_FuncPtr CalculateMAC;
    const char * CalculateMAC_FuncName;

    SDF_HashInit_FuncPtr HashInit;
    const char * HashInit_FuncName;
    SDF_HashUpdate_FuncPtr HashUpdate;
    const char * HashUpdate_FuncName;
    SDF_HashFinal_FuncPtr HashFinal;
    const char * HashFinal_FuncName;

    SDF_CreateObject_FuncPtr CreateObject;
    const char * CreateObject_FuncName;
    SDF_ReadObject_FuncPtr ReadObject;
    const char * ReadObject_FuncName;
    SDF_WriteObject_FuncPtr WriteObject;
    const char * WriteObject_FuncName;
    SDF_DeleteObject_FuncPtr DeleteObject;
    const char * DeleteObject_FuncName;
} SDF_METHOD;

#endif
