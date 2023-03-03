#include "application.h"
#include "../tool/redisConn.h"
#include "../tool/gmcmLog.h"
#include "../keyMgmt/keyMgmt.h"
#include "../serverConf.h"
#include "../gmcmErr.h"

int application::load(const char *appName)
{
    int ret;
    unsigned int size = sizeof(this->_appInfo);
    ret = redisConn::hashGetData(APP_HASH_NAME, appName, (unsigned char *)&this->_appInfo, size);
    if (ret)
    {
    }
    else
    {
        if (_appInfo.enable == appInfo::APP_DISABLE)
        {
            return 0;
        }

        if (_appInfo.appType == appInfo::APP_TYPE_HSM)
        {
            ret = loadHsm();
        }
        else if (_appInfo.appType == appInfo::APP_TYPE_SVS)
        {
            ret = loadSvs();
        }
    }
    return ret;
}

int application::loadHsm()
{
    int ret;
    dso *pDso = new dso();
    ret = pDso->load_so_lib(_appInfo.algLib);
    if (ret)
    {
        delete pDso;
    }
    else
    {
        this->_algMeth._sdfMeth = new sdfMeth(pDso);
        ret = _algMeth._sdfMeth->load_all_sdf_func();
        if (ret)
        {
        }
        else
        {
            _keyMgmt = new keyMgmt(_algMeth._sdfMeth, _appInfo.appName);
            if (_keyMgmt == NULL)
            {
            }
            else
            {
                if (strstr(_appInfo.algLib, SDF_API_LIB))
                {
                    _algMeth._sdfMeth->OpenDevice(NULL, &_keyMgmt->_keyMgmtMeth);
                }
                else
                {
                    _algMeth._sdfMeth->OpenDevice();
                }
            }
        }
    }

    return ret;
}

int application::loadSvs()
{
    return loadHsm();
}

void application::clear()
{
    if (_algMeth._sdfMeth)
    {
        delete _algMeth._sdfMeth;
    }
    if(_keyMgmt)
    {
        delete _keyMgmt;
    }
}

int application::reload()
{
    clear();
    return load(_appInfo.appName);
}

sdfMeth *application::getSdfMeth()
{
    if (_appInfo.appType == appInfo::APP_TYPE_HSM || _appInfo.appType == appInfo::APP_TYPE_SVS)
    {
        return _algMeth._sdfMeth;
    }
    else
    {
        return NULL;
    }
}

application::~application()
{
    clear();
}

int application::add(const char *name, const char type, const char *lib)
{
    snprintf(_appInfo.appName, sizeof(_appInfo.appName), "%s", name);
    snprintf(_appInfo.algLib, sizeof(_appInfo.algLib), "%s", lib);
    _appInfo.appType = type;
    _appInfo.enable = 1;

    int ret = redisConn::hashSetData(APP_HASH_NAME, name, (unsigned char *)&_appInfo, sizeof(_appInfo));
    if(ret)
    {
        return ret;
    }
    else
    {
        ret = load(name);
    }

    return ret;
}

applicationList *applicationList::gApplicationList = NULL;

applicationList::applicationList(/* args */)
{
    _appList.clear();
}

applicationList::~applicationList()
{
    map<string, application *>::iterator iter;
    for (iter = _appList.begin(); iter != _appList.end(); iter++)
    {
        delete iter->second;
    }
}

applicationList *applicationList::getAppList()
{
    if (gApplicationList == NULL)
    {
        gApplicationList = new applicationList();
    }
    return gApplicationList;
}

int applicationList::loadAllApp()
{
    vector<string> keys;
    int ret;

    ret = redisConn::hashKeys(APP_HASH_NAME, &keys);
    if (ret && ret != GMCM_ERR_REPLY_EMPTY)
    {
    }
    else
    {
        ret = GMCM_OK;
        for (size_t i = 0; i < keys.size(); i++)
        {
            application *pApp = new application;
            ret = pApp->load(keys[i].c_str());
            if (ret)
            {
                delete pApp;
            }
            else
            {
                getAppList()->_appList.insert(pair<string, application *>(keys[i], pApp));
            }
        }

        if(getApp(APP_HSM_DEF) == NULL)
        {
            application *pApp = new application;
            ret = pApp->add(APP_HSM_DEF, appInfo::APP_TYPE_HSM, SDF_API_LIB);
            if(ret)
            {
                gmcmLog::LogError() << "add def hsm fail." << endl;
            }
            else
            {
                gmcmLog::LogDebug() << "add def hsm success." << endl;
                getAppList()->_appList.insert(pair<string, application *>(APP_HSM_DEF, pApp));
            }
        }

        if (getApp(APP_SVS_DEF) == NULL)
        {
            application *pApp = new application;
            ret = pApp->add(APP_SVS_DEF, appInfo::APP_TYPE_SVS, SDF_API_LIB);
            if (ret)
            {
                gmcmLog::LogError() << "add def svs fail." << endl;
            }
            else
            {
                gmcmLog::LogDebug() << "add def svs success." << endl;
                getAppList()->_appList.insert(pair<string, application *>(APP_SVS_DEF, pApp));
            }
        }
    }
    return ret;
}

application *applicationList::getApp(string name)
{
    try
    {
        return getAppList()->_appList.at(name);
    }
    catch (const std::exception &e)
    {
        return NULL;
    }
}

sdfMeth *applicationList::getSdfMeth(string appName)
{
    application *pApp = getApp(appName);
    if (pApp)
    {
        return pApp->getSdfMeth();
    }
    else
    {
        return NULL;
    }
}