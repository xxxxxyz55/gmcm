#ifndef _GMCM_TCP_PROCESS_FUNC_H_
#define _GMCM_TCP_PROCESS_FUNC_H_

#include <iostream>
#include <map>
#include <string>
#include "protostruct.h"

using namespace std;

typedef struct tcpDealFunc_st
{
    char cmd[5];
    processFuncCallback func;
} tcpDealFunc;

class tcpApiEngine
{
private:
    tcpApiEngine(/* args */){};
    map<string, tcpDealFunc> apiMap;
    static tcpApiEngine *gmcmApiFuncs;

public:
    static map<string, tcpDealFunc> *getMap();
    ~tcpApiEngine(){
        apiMap.clear();
    };
};

#define ADD_API_FUNC(func) unsigned int func(unsigned char *reqStr, unsigned int reqStrLen, protoBase *respBase);

ADD_API_FUNC(randBytes)
ADD_API_FUNC(genEccKeyPair)
ADD_API_FUNC(importKey)
ADD_API_FUNC(destroyKey)
ADD_API_FUNC(encrypt)
ADD_API_FUNC(decrypt)

#endif