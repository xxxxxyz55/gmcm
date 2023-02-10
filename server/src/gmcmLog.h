
#ifndef _GMCM_LOG_H_
#define _GMCM_LOG_H_

#include "util/tc_logger.h"
using namespace  std;
using namespace tars;

static TC_LoggerThreadGroup gGroup;
static TC_RollLogger gLogger;

class gmcmLog
{
private:
public:
    enum
    {
        NONE_LOG_LEVEL = 1,
        ERROR_LOG_LEVEL = 2,
        WARN_LOG_LEVEL = 3,
        INFO_LOG_LEVEL = 4,
        DEBUG_LOG_LEVEL = 5,
        TARS_LOG_LEVEL = 6,
    };

    gmcmLog(int level = INFO_LOG_LEVEL){
        gGroup.start(1);
        gLogger.init("./gmcm", 1024 * 1024, 100);
        gLogger.modFlag(TC_RollLogger::HAS_LEVEL | TC_RollLogger::HAS_PID, true);
        gLogger.setLogLevel(level);
        gLogger.setupThread(&gGroup);
    }
    ~gmcmLog()
    {
        gLogger.unSetupThread();
    }

    static LoggerStream LogDebug()
    {
        return gLogger.debug();
    }

    static LoggerStream LogError()
    {
        return gLogger.error();
    }

    static LoggerStream LogInfo()
    {
        return gLogger.info();
    }

    static char * toHex(unsigned char * str, unsigned int len)
    {
        static char hexLog[8192*8] = {0};
        for (size_t i = 0; i < len && i < sizeof(hexLog) / 2; i++)
        {
            sprintf(hexLog + i * 2, "%02X", str[i]);
        }
        return hexLog;
    }
};

#endif