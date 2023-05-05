
#ifndef _GMCM_TIME_H_
#define _GMCM_TIME_H_

#include <iostream>
#include <time.h>

class gmcmTime
{
private:
public:
    static time_t getTime()
    {
        return time(NULL);
    }

    static string getTimeStr()
    {
        time_t tmNow;
        time(&tmNow);
        return ctime(&tmNow);
    }

    gmcmTime(){};
    ~gmcmTime(){};
};

#endif