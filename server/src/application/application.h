#ifndef _GMCM_APPLICATION_H_
#define _GMCM_APPLICATION_H_
#include "../algProvider/algProvider.h"
#include "../keyMgmt/keyMgmt.h"
#include <map>
using namespace std;

/*
app  appinfo
     key
     usr1
     user2

app"_user" 
app"_keys" 
app"_info"
*/

#define APP_HASH_NAME   "application"

#define APP_HSM_DEF     "GMCM_HSM"
#define APP_SVS_DEF     "GMCM_SVS"

class appInfo
{
public:
    char appName[128];
    char algLib[128];
    enum
    {
        APP_DISABLE = 0,
        APP_ENABLE,
    };
    char enable;

    enum
    {
        APP_TYPE_HSM,
        APP_TYPE_SVS,
    };
    char appType;
};


class application
{
private:
    appInfo _appInfo;
    typedef struct algMeth_st
    {
        sdfMeth *_sdfMeth;
    } algMeth;

    algMeth _algMeth;
    keyMgmt *_keyMgmt = NULL;
    int loadHsm();
    int loadSvs();

public:
    int add(const char *name, const char type, const char *lib);
    int load(const char *appName);
    void clear();
    int reload();
    sdfMeth *getSdfMeth();
    ~application();
};

class applicationList
{
private:
    map<string, application *> _appList;

    applicationList(/* args */);
    static applicationList *gApplicationList;
public:
    static applicationList * getAppList();
    static int loadAllApp();
    static application *getApp(string name);
    static sdfMeth * getSdfMeth(string appName);
    ~applicationList();
};

#endif