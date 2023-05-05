#include "algProvider.h"
#include <dlfcn.h>
#include <unistd.h>
#include "../gmcmErr.h"
#include "../tool/gmcmLog.h"
#include "../serverConf.h"

int dso::load_so_lib(const char *soPath)
{
    if (soPath == NULL)
    {
        return GMCM_PARAM_NULL;
    }
    if (access(soPath, F_OK) != 0)
    {
        return GMCM_ERR_FILE_PATH;
    }

    void *pSoLib = NULL;
    pSoLib = dlopen(soPath, RTLD_LAZY | RTLD_LOCAL);
    if (pSoLib == NULL)
    {
        return GMCM_ERR_DLOPEN;
    }
    else
    {
        if (this->pLib)
        {
            dlclose(this->pLib);
        }
        this->pLib = pSoLib;
        sPath = soPath;
        return GMCM_OK;
    }
}

dso::dso(const char *soPath)
{
    int iRet = load_so_lib(soPath);
    if (iRet)
    {
        throw iRet;
    }
}

dso::~dso()
{
    if (pLib)
    {
        dlclose(pLib);
    }
}

void *dso::getFuncPointer(const char *funcName)
{
    if (pLib == NULL)
    {
        return NULL;
    }

    return dlsym(pLib, funcName);
}

#define DSO_LOAD_FUNC(pLib, pFunc, funcName)                                                   \
    do                                                                                         \
    {                                                                                          \
        void **ptr = (void **)&pFunc;                                                          \
        *ptr = pLib->getFuncPointer(funcName);                                                 \
        if (pFunc == NULL)                                                                     \
        {                                                                                      \
            string libPath = pLib->getLibPath();                                               \
            gmcmLog::LogError() << libPath << " load func " << funcName << " failed." << endl; \
            return GMCM_FAIL;                                                                  \
        }                                                                                      \
    } while (0);

int sdfMeth::load_all_sdf_func()
{
    if(pLib == NULL)
    {
        return GMCM_ERR_LIB_NOT_FOUND;
    }

    DSO_LOAD_FUNC(pLib, tMeth.OpenDevice, "SDF_OpenDevice")
    DSO_LOAD_FUNC(pLib, tMeth.CloseDevice, "SDF_CloseDevice")
    DSO_LOAD_FUNC(pLib, tMeth.OpenSession, "SDF_OpenSession")
    DSO_LOAD_FUNC(pLib, tMeth.CloseSession, "SDF_CloseSession")
    DSO_LOAD_FUNC(pLib, tMeth.GetDeviceInfo, "SDF_GetDeviceInfo")
    DSO_LOAD_FUNC(pLib, tMeth.GenerateRandom, "SDF_GenerateRandom")

    DSO_LOAD_FUNC(pLib, tMeth.GetPrivateKeyAccessRight, "SDF_GetPrivateKeyAccessRight")
    DSO_LOAD_FUNC(pLib, tMeth.ReleasePrivateKeyAccessRight, "SDF_ReleasePrivateKeyAccessRight")

    DSO_LOAD_FUNC(pLib, tMeth.ExportSignPublicKey_ECC, "SDF_ExportSignPublicKey_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.ExportEncPublicKey_ECC, "SDF_ExportEncPublicKey_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.GenerateKeyPair_ECC, "SDF_GenerateKeyPair_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.GenerateKeyWithIPK_ECC, "SDF_GenerateKeyWithIPK_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.GenerateKeyWithEPK_ECC, "SDF_GenerateKeyWithEPK_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.ImportKeyWithISK_ECC, "SDF_ImportKeyWithISK_ECC")

    DSO_LOAD_FUNC(pLib, tMeth.GenerateAgreementDataWithECC, "SDF_GenerateAgreementDataWithECC")
    DSO_LOAD_FUNC(pLib, tMeth.GenerateKeyWithECC, "SDF_GenerateKeyWithECC")
    DSO_LOAD_FUNC(pLib, tMeth.GenerateAgreementDataAndKeyWithECC, "SDF_GenerateAgreementDataAndKeyWithECC")
    DSO_LOAD_FUNC(pLib, tMeth.ExchangeDigitEnvelopeBaseOnECC, "SDF_ExchangeDigitEnvelopeBaseOnECC")

    DSO_LOAD_FUNC(pLib, tMeth.GenerateKeyWithKEK, "SDF_GenerateKeyWithKEK")
    DSO_LOAD_FUNC(pLib, tMeth.ImportKeyWithKEK, "SDF_ImportKeyWithKEK")
    DSO_LOAD_FUNC(pLib, tMeth.ImportKey, "SDF_ImportKey")
    DSO_LOAD_FUNC(pLib, tMeth.DestroyKey, "SDF_DestroyKey")

    DSO_LOAD_FUNC(pLib, tMeth.ExternalSign_ECC, "SDF_ExternalSign_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.ExternalVerify_ECC, "SDF_ExternalVerify_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.InternalSign_ECC, "SDF_InternalSign_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.InternalVerify_ECC, "SDF_InternalVerify_ECC")

    DSO_LOAD_FUNC(pLib, tMeth.ExternalEncrypt_ECC, "SDF_ExternalEncrypt_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.ExternalDecrypt_ECC, "SDF_ExternalDecrypt_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.InternalEncrypt_ECC, "SDF_InternalEncrypt_ECC")
    DSO_LOAD_FUNC(pLib, tMeth.InternalDecrypt_ECC, "SDF_InternalDecrypt_ECC")

    DSO_LOAD_FUNC(pLib, tMeth.Encrypt, "SDF_Encrypt")
    DSO_LOAD_FUNC(pLib, tMeth.Decrypt, "SDF_Decrypt")
    DSO_LOAD_FUNC(pLib, tMeth.CalculateMAC, "SDF_CalculateMAC")

    DSO_LOAD_FUNC(pLib, tMeth.HashInit, "SDF_HashInit")
    DSO_LOAD_FUNC(pLib, tMeth.HashUpdate, "SDF_HashUpdate")
    DSO_LOAD_FUNC(pLib, tMeth.HashFinal, "SDF_HashFinal")

    return GMCM_OK;
}

int sdfMeth::OpenDevice(session_meth *pSessionMeth, key_mgmt_meth *pKeyMeth)
{
    if (pDevHandle == NULL)
    {
        int iRet;
        if (pSessionMeth || pKeyMeth)
        {
            DSO_LOAD_FUNC(pLib, tMeth.OpenDeviceWithCb, "SDF_OpenDeviceWithCb")
            iRet = this->tMeth.OpenDeviceWithCb(&pDevHandle, pSessionMeth, pKeyMeth, 0);
        }
        else
        {
            iRet = this->tMeth.OpenDevice(&pDevHandle);
        }
        if (iRet)
        {
            gmcmLog::LogError() << pLib->getLibPath() << " OpenDevice return err " << iRet << "." << endl;
            return iRet;
        }
        else
        {
            gmcmLog::LogInfo() << pLib->getLibPath() << " OpenDevice success " << iRet << "." << endl;
        }
    }

    void *pSession = getSession();
    if(pSession == NULL)
    {

    }
    else
    {
        realseSession(pSession);
    }

    return GMCM_OK;
}

void *sdfMeth::getSession()
{
    if (pDevHandle == NULL)
    {
        gmcmLog::LogError() << "lib not open device." << endl;
        return NULL;
    }

    void *pSession = NULL;
    // if (pSessions.try_dequeue(pSession) == false)
    if (pSessions.pop_front(pSession) == false)
    {
        int iRet = this->tMeth.OpenSession(pDevHandle, &pSession);
        if (iRet)
        {
            gmcmLog::LogError() << pLib->getLibPath() << " OpenSession return err " << iRet << "." << endl;
            return NULL;
        }
    }

    return pSession;
}

void sdfMeth::realseSession(void * pSession)
{
    // if (pSessions.enqueue(pSession) == false)
    // {
    //     tMeth.CloseSession(pSession);
    // }
    pSessions.push_back(pSession);
}

sdfMeth::~sdfMeth()
{
    void *pSession = NULL;
    // while (pSessions.try_dequeue(pSession))
    while (pSessions.pop_front(pSession))
    {
        tMeth.CloseSession(pSession);
    }

    tMeth.CloseDevice(pDevHandle);
    pDevHandle = NULL;
}

int sdfMeth::GenerateKeyPair_ECC(ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    void * pSession = NULL;
    pSession = this->getSession();
    if(pSession == NULL)
    {
        return GMCM_ERR_OPEN_SESSION;
    }

    int iRet = tMeth.GenerateKeyPair_ECC(pSession, SGD_SM2, 256, pucPublicKey, pucPrivateKey);
    this->realseSession(pSession);
    return iRet;
}

int sdfMeth::GenerateRandom(SGD_UINT32 uiLength, SGD_UCHAR *pucRandom)
{
    void *pSession = NULL;
    pSession = this->getSession();
    if (pSession == NULL)
    {
        return GMCM_ERR_OPEN_SESSION;
    }

    int iRet = tMeth.GenerateRandom(pSession, uiLength, pucRandom);
    this->realseSession(pSession);
    return iRet;
}

int sdfMeth::ImportKey(SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, unsigned char *handleStr, unsigned short *length)
{
    void *pSession = NULL;
    pSession = this->getSession();
    if (pSession == NULL)
    {
        return GMCM_ERR_OPEN_SESSION;
    }
    void *handlPtr = NULL;

    int iRet = tMeth.ImportKey(pSession, pucKey, uiKeyLength, &handlPtr);
    this->realseSession(pSession);
    if (iRet)
    {
    }
    else
    {
        HANDLE_TO_STR(handlPtr, handleStr, *length)
    }
    return iRet;
}

int sdfMeth::DestroyKey(unsigned char *handleStr, unsigned short length)
{
    void *pSession = NULL;
    pSession = this->getSession();
    if (pSession == NULL)
    {
        return GMCM_ERR_OPEN_SESSION;
    }
    void * handPtr = NULL;
    STR_TO_HANDLE(handleStr, length, handPtr)
    int iRet = tMeth.DestroyKey(pSession, handPtr);
    this->realseSession(pSession);
    return iRet;
}

int sdfMeth::encrypt(unsigned char *handleStr, unsigned short length,
                     SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV,
                     SGD_UCHAR *pucData, unsigned short uiDataLength,
                     SGD_UCHAR *pucEncData, unsigned short *puiEncDataLength)
{
    void *pSession = NULL;
    pSession = this->getSession();
    if (pSession == NULL)
    {
        return GMCM_ERR_OPEN_SESSION;
    }

    void * handPtr = NULL;
    unsigned int encLength = 0;
    STR_TO_HANDLE(handleStr, length, handPtr)
    int iRet = tMeth.Encrypt(pSession, handPtr, uiAlgID, pucIV, pucData,
                             uiDataLength, pucEncData, &encLength);
    if (iRet)
    {
    }
    else
    {
        *puiEncDataLength = encLength;
    }

    this->realseSession(pSession);
    FREE_HANDLE(handPtr)
    return iRet;
}

int sdfMeth::decrypt(unsigned char *handleStr, unsigned short length,
                     SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV,
                     SGD_UCHAR *pucEncData, unsigned short uiEncDataLength,
                     SGD_UCHAR *pucData, unsigned short *puiDataLength)
{
    void *pSession = NULL;
    pSession = this->getSession();
    if (pSession == NULL)
    {
        return GMCM_ERR_OPEN_SESSION;
    }

    void * handPtr = NULL;
    unsigned int dataLength = 0;
    STR_TO_HANDLE(handleStr, length, handPtr)

    int iRet = tMeth.Decrypt(pSession, handPtr, uiAlgID, pucIV, pucEncData,
                             uiEncDataLength, pucData, &dataLength);
    if (iRet)
    {
    }
    else
    {
        *puiDataLength = dataLength;
    }

    this->realseSession(pSession);
    FREE_HANDLE(handPtr)
    return iRet;

}