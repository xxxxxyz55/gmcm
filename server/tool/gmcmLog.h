#ifndef _GMCM_LOG_H_
#define _GMCM_LOG_H_

#include "util/tc_logger.h"
#include "globalClass.h"
using namespace  std;
using namespace tars;


class gmcmLog: public globalClass<gmcmLog>
{
private:
    TC_LoggerThreadGroup _logGroup;
    TC_RollLogger _roolLogger;

public:
    //建议从配置读
    gmcmLog(int level = DEBUG_LOG_LEVEL)
    {
        _logGroup.start(1);
        _roolLogger.init("./gmcm", 1024 * 1024, 100);
        _roolLogger.modFlag(TC_RollLogger::HAS_LEVEL | TC_RollLogger::HAS_PID, true);
        _roolLogger.setLogLevel(level);
        _roolLogger.setupThread(&_logGroup);
    }

    ~gmcmLog()
    {
        _roolLogger.unSetupThread();
    }


    static TC_RollLogger *getRollLogger()
    {
        return &globalClass<gmcmLog>::getGlobalClass()->_roolLogger;
    }

    static void setLogLevel(int level)
    {
        getRollLogger()->setLogLevel(level);
    }

    enum
    {
        NONE_LOG_LEVEL = 1,
        ERROR_LOG_LEVEL = 2,
        WARN_LOG_LEVEL = 3,
        INFO_LOG_LEVEL = 4,
        DEBUG_LOG_LEVEL = 5,
        TARS_LOG_LEVEL = 6,
    };

    static LoggerStream LogDebug()
    {
        return getRollLogger()->debug();
    }

    static LoggerStream LogError()
    {
        return getRollLogger()->error();
    }

    static LoggerStream LogInfo()
    {
        return getRollLogger()->info();
    }
};

#endif