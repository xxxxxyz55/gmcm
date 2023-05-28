#include <iostream>
#include "gmcmSdkClv.h"
#include "../include/gmcmSdkApi.h"
#include "../../server/gmcmErr.h"
#include "../../server/api/hsm/hsmPkt.h"
#include "utilFunc.h"

using namespace std;
using namespace tars;

int SDF_OpenDevice(void **phDeviceHandle)
{
    *phDeviceHandle = new gmcmSdkDev();
    return 0;
}

int SDF_OpenDeviceWithIp(void **phDeviceHandle, const char * ip, unsigned short port)
{
    *phDeviceHandle = new gmcmSdkDev(ip, port);
    return 0;
}

int SDF_CloseDevice(void *hDeviceHandle)
{
    if (hDeviceHandle)
    {
        delete (gmcmSdkDev *)hDeviceHandle;
    }
    return 0;
}

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    if (hDeviceHandle == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }
    gmcmSdkSession * pSession = new gmcmSdkSession();
    gmcmSdkDev *pDev = (gmcmSdkDev *)hDeviceHandle;
    int iRet = 0;

    pSession->init(pDev->serverIp, pDev->serverPort, 3000);

    if ((iRet = pSession->checkSocket()))
    {
        SDK_LOG_ERROR("conn to server fail  %d.", iRet);
        delete pSession;
        return SDK_ERR_CONN;
    }
    else
    {
        SDK_LOG_DEBUG("conn to server success .");
    }
    
    *phSessionHandle = (void *)pSession;
    return 0;
}

int SDF_CloseSession(void *hSessionHandle)
{
    if (hSessionHandle == NULL)
    {
        return 0;
    }

    delete (gmcmSdkSession *)hSessionHandle;
    return 0;
}

int32_t gmcmSdkSession::sendCb(void *data, uint16_t len)
{
    return send((char *)data, len);
}

int32_t gmcmSdkSession::recvClv()
{
    respStrLen = 0;
    // 0xFFFFFFFF 4 ext 4 len 2 ...
    int ret = recvLength((char *)respStr, 10);
    if (ret < 0)
    {
        SDK_LOG_ERROR("recv clv fail.");
        return ret;
    }
    respStrLen += 10;

    int16_t *pTotalLen = (int16_t *)(respStr + 8);
    ret = recvLength((char *)respStr + respStrLen, *pTotalLen);
    if (ret < 0)
    {
        SDK_LOG_ERROR("recv clv fail total = %d.", *pTotalLen);
        return ret;
    }
    respStrLen += *pTotalLen;

    // utilTool::printHex(respStr, respStrLen);

    return 0;
}

template <typename T, typename K>
class gmcmSdkCtx
{
private:
public:
    T req;
    K resp;
    const char * _cmd;
    gmcmSdkSession *pSession;
    gmcmSdkCtx(void *hSessionHandle, const char *cmd)
    {
        pSession = (gmcmSdkSession *)hSessionHandle;
        _cmd = cmd;
    }

    int sendRecv()
    {
        int32_t ret;
        string reqStr = req.tostring((uint8_t *)_cmd);
        ret = pSession->send(reqStr.c_str(), reqStr.length());
        if (ret)
        {
            SDK_LOG_ERROR("req send fail %d.", ret);
            return SDK_ERR_SEND;
        }

        ret = pSession->recvClv();
        if(ret)
        {
            SDK_LOG_ERROR("req recv fail %d.", ret);
            return SDK_ERR_RECV;
        }

        if(*(uint32_t *)(pSession->respStr + 4))
        {
            ret = resp.mapping(pSession->respStr, pSession->respStrLen);
            if(ret)
            {
                SDK_LOG_ERROR("req mapping fail %d.", ret);
                return SDK_ERR_RECV;
            }
        }
        else
        {
            return *(int32_t *)(pSession->respStr + 12);
        }
        
        return 0;
    }

    ~gmcmSdkCtx(){};
};

int SDF_GenerateRandom(void *hSessionHandle, SGD_UINT32 uiLength, SGD_UCHAR *pucRandom)
{
    if (hSessionHandle == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }

    gmcmSdkCtx<reqRandom, respRandom> ctx(hSessionHandle, "0002");

    *ctx.req.length.alloc() = uiLength;
    SDK_LOG_DEBUG("random len = %d", ctx.req.length.val());
    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucRandom, ctx.resp.rand.ptr(), ctx.resp.rand.len());
    return 0;
}

int SDF_GenerateKeyPair_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits,
                            ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    if (hSessionHandle == NULL || pucPublicKey == NULL || pucPrivateKey == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }

    gmcmSdkCtx<reqGenEccPair, respGenEccPair> ctx(hSessionHandle, "0007");

    *ctx.req.algid.alloc() = uiAlgID;
    *ctx.req.bits.alloc() = uiKeyBits;

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucPublicKey, ctx.resp.pub.ptr(), sizeof(ECCrefPublicKey));
    memcpy(pucPrivateKey, ctx.resp.pri.ptr(), sizeof(ECCrefPrivateKey));
    return 0;
}

static unsigned int gHandleSize = 4;

int SDF_ImportKey(void *hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, void **phKeyHandle)
{
    if (hSessionHandle == NULL || phKeyHandle == NULL || pucKey == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }

    if(uiKeyLength != 16)
    {
        return SDK_ERR_LENGTH;
    }

    gmcmSdkCtx<reqImportKey, respImportKey> ctx(hSessionHandle, "0017");

    ctx.req.uikey.ref(pucKey, uiKeyLength);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    *phKeyHandle = new unsigned char[ctx.resp.hd.len()];
    memcpy(*phKeyHandle, ctx.resp.hd.ptr(), ctx.resp.hd.len());
    if (ctx.resp.hd.len() != gHandleSize)
    {
        gHandleSize = ctx.resp.hd.len();
    }
    return 0;
}

int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }

    gmcmSdkCtx<reqDestroyKey, respDestroyKey> ctx(hSessionHandle, "0018");

    ctx.req.hd.ref((uint8_t *)hKeyHandle, gHandleSize);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    delete[] (unsigned char *)hKeyHandle;

    return 0;
}

//27
int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV,
                SGD_UCHAR *pucData, SGD_UINT32 uiDataLength,
                SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLength)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL || pucData == NULL || pucEncData == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }

    gmcmSdkCtx<reqEncrypt, respEncrypt> ctx(hSessionHandle, "0027");

    ctx.req.hd.ref((uint8_t *)hKeyHandle, gHandleSize);
    *ctx.req.algid.alloc() = uiAlgID;
    if(pucIV)
    {
        ctx.req.iv.ref(pucIV, 16);
    }
    else
    {
        ctx.req.iv.ref(pucIV, 0);
    }

    ctx.req.data.ref(pucData, uiDataLength);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucEncData, ctx.resp.encData.ptr(), ctx.resp.encData.len());
    *puiEncDataLength = ctx.resp.encData.len();
    if(pucIV)
    {
        memcpy(pucIV, ctx.resp.iv.ptr(), ctx.resp.iv.len());
    }

    return 0;
}

//28
int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV,
                SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength,
                SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength)
{
    if (hSessionHandle == NULL || hKeyHandle == NULL || pucEncData  == NULL || pucData == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }

    gmcmSdkCtx<reqDecrypt, respDecrypt> ctx(hSessionHandle, "0028");
    ctx.req.hd.ref((uint8_t *)hKeyHandle, gHandleSize);
    *ctx.req.algid.alloc() = uiAlgID;
    if(pucIV)
    {
        ctx.req.iv.ref(pucIV, 16);
    }
    else
    {
        ctx.req.iv.ref(pucIV, 0);
    }

    ctx.req.encData.ref(pucEncData, uiEncDataLength);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucData, ctx.resp.decData.ptr(), ctx.resp.decData.len());
    *puiDataLength = ctx.resp.decData.len();
    if (pucIV)
    {
        memcpy(pucIV, ctx.resp.iv.ptr(), ctx.resp.iv.len());
    }

    return 0;
}