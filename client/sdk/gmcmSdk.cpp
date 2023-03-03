#include <iostream>
#include "gmcmSdk.h"
#include "../include/gmcmSdkApi.h"
#include "pst.h"
#include "../../server/src/gmcmErr.h"
#include "../../server/src/package/packageDefine.h"

using namespace std;
using namespace tars;
using namespace pst;

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

    pSession->pkt.setRecvFunc(std::bind(&gmcmSdkSession::recv_cb, pSession, std::placeholders::_1, std::placeholders::_2));
    pSession->pkt.setSendFunc(std::bind(&gmcmSdkSession::send_cb, pSession, std::placeholders::_1, std::placeholders::_2));

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

template <typename T, typename K>
class gmcmSdkCtx
{
private:
public:
    T req;
    K resp;
    gmcmSdkSession *pSession;
    gmcmSdkCtx(void * hSessionHandle, const char *cmd)
    {
        pSession = (gmcmSdkSession *)hSessionHandle;
        req.pointToBase(pSession->pkt.getReqBase());
        pSession->pkt.setCmd(cmd);
    }

    int sendRecv()
    {
        if (pSession->pkt.sendReq())
        {
            return SDK_ERR_SEND;
        }

        if (pSession->pkt.recvResp())
        {
            int ret = pSession->pkt.getError();
            if (ret)
            {
                SDK_LOG_ERROR("sever return err [%d][%s]", ret, errGetReason(ret));
                return ret;
            }
            else
            {
                return SDK_ERR_RECV;
            }
        }

        resp.pointToBuffer(pSession->pkt.getRespStr(), pSession->pkt.getRespStrLen());
        // resp.print();
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

    gmcmSdkCtx<reqRandBytes, respRandBytes> ctx(hSessionHandle, "0002");

    ctx.req.length.setVal(uiLength);
    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucRandom, ctx.resp.random.uStrVal(), ctx.resp.random.length());
    return 0;
}

int SDF_GenerateKeyPair_ECC(void *hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits,
                            ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    if (hSessionHandle == NULL || pucPublicKey == NULL || pucPrivateKey == NULL)
    {
        return SDK_ERR_PARAM_NULL;
    }

    gmcmSdkCtx<reqGenEccKeyPair, respGenEccKeyPair> ctx(hSessionHandle, "0007");

    ctx.req.algid.setVal(uiAlgID);
    ctx.req.bits.setVal(uiKeyBits);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucPublicKey, ctx.resp.pub.uStrVal(), sizeof(ECCrefPublicKey));
    memcpy(pucPrivateKey, ctx.resp.pri.uStrVal(), sizeof(ECCrefPrivateKey));
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

    ctx.req.uikey.setVal(pucKey, uiKeyLength);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }
    *phKeyHandle = new unsigned char[ctx.resp.handle.length()];
    memcpy(*phKeyHandle, ctx.resp.handle.uStrVal(), ctx.resp.handle.length());
    if (ctx.resp.handle.length() != gHandleSize)
    {
        gHandleSize = ctx.resp.handle.length();
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

    ctx.req.handle.setVal((unsigned char *)hKeyHandle, gHandleSize);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    delete (unsigned char *)hKeyHandle;

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

    ctx.req.handle.setVal((unsigned char *)hKeyHandle, gHandleSize);
    ctx.req.algid.setVal(uiAlgID);
    if(pucIV)
    {
        ctx.req.iv.setVal(pucIV, (unsigned int)16);
    }
    else
    {
        ctx.req.iv.setVal(pucIV, (unsigned int)0);
    }

    ctx.req.data.setVal(pucData, uiDataLength);

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucEncData, ctx.resp.encData.uStrVal(), ctx.resp.encData.length());
    *puiEncDataLength = ctx.resp.encData.length();
    if(pucIV)
    {
        memcpy(pucIV, ctx.resp.iv.uStrVal(), ctx.resp.iv.length());
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
    ctx.req.handle.setVal((unsigned char *)hKeyHandle, gHandleSize);
    ctx.req.algid.setVal(uiAlgID);
    if(pucIV)
    {
        ctx.req.iv.setVal(pucIV, (unsigned int)16);
    }
    else
    {
        ctx.req.iv.setVal(pucIV, (unsigned int)0);
    }
    
    ctx.req.encData.setVal(pucEncData, uiEncDataLength);

    

    int ret = ctx.sendRecv();
    if (ret)
    {
        return ret;
    }

    memcpy(pucData, ctx.resp.decData.uStrVal(), ctx.resp.decData.length());
    *puiDataLength = ctx.resp.decData.length();
    if (pucIV)
    {
        memcpy(pucIV, ctx.resp.iv.uStrVal(), ctx.resp.iv.length());
    }

    return 0;
}