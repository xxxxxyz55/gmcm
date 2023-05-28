#ifndef _ALG_PROVIDER_H_
#define _ALG_PROVIDER_H_

#include <iostream>
#include "sdf_ex.h"
#include "util/tc_cas_queue.h"

using namespace std;
using namespace tars;

class dso
{
private:
    void * pLib = NULL;
    string sPath;
public:
    int load_so_lib(const char *soPath);
    string getLibPath() { return sPath; }
    void * getFuncPointer(const char *funcName);
    void *getSoPointer() { return pLib; }
    dso(const char *soPath);
    dso(){};
    ~dso();
};

class sdfMeth
{
private:
    TC_CasQueue<void *> pSessions;
    void * pDevHandle = NULL;
    dso * pLib = NULL;
    void *getSession();
    void realseSession(void *pSession);

public:
    SDF_METHOD tMeth;
    int load_all_sdf_func();
    void set_dso(dso *pSoLib) { pLib = pSoLib; }

    int OpenDevice(session_meth *pSessionMeth = NULL, key_mgmt_meth *pKeyMeth = NULL);
    int GenerateKeyPair_ECC(ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
    int GenerateRandom(SGD_UINT32 uiLength, SGD_UCHAR *pucRandom);
    int ImportKey(SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, unsigned char *handleStr, unsigned short *length);
    int DestroyKey(unsigned char *handleStr, unsigned short length);

    int encrypt(unsigned char *handleStr, unsigned short length,
                SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV,
                SGD_UCHAR *pucData, unsigned short uiDataLength,
                SGD_UCHAR *pucEncData, unsigned short *puiEncDataLength);
    int decrypt(unsigned char *handleStr, unsigned short length,
                SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV,
                SGD_UCHAR *pucEncData, unsigned short uiEncDataLength,
                SGD_UCHAR *pucData, unsigned short *puiDataLength);

    //alg func

    sdfMeth()
    {
    }
    sdfMeth(dso *pSoLib)
    {
        pLib = pSoLib;
    }
    ~sdfMeth();
};

#endif