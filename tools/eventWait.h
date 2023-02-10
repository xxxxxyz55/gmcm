
#ifndef _EVENT_WAIT_H_
#define _EVENT_WAIT_H_

#ifndef _GLIBCXX_HAS_GTHREADS
#define _GLIBCXX_HAS_GTHREADS
#endif

#include <condition_variable>
#include <mutex>
/*
eventfd
事件等待
*/
using namespace std;

class eventWait
{
private:
    std::condition_variable condVar;
    std::mutex cvMutex;
    bool hasNotified = false;

public:
    //waitAllTime 如果为true，只要唤醒过就返回ture
    static bool wait_for(eventWait *pEvent, int ms, bool waitAllTime = false)
    {
        if(pEvent == NULL) return true;
        if(waitAllTime && pEvent->hasNotified)
        {
            return true;
        }

        unique_lock<mutex> lck(pEvent->cvMutex);
        if (pEvent->condVar.wait_for(lck, chrono::milliseconds(ms)) == cv_status::timeout)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    static void wait(eventWait *pEvent)
    {
        if(pEvent == NULL) return;
        unique_lock<mutex> lck(pEvent->cvMutex);
        pEvent->condVar.wait(lck);
    }

    static void notify_all(eventWait *pEvent)
    {
        if(pEvent == NULL) return;
        unique_lock<mutex> lck(pEvent->cvMutex);
        pEvent->condVar.notify_all();
        if (pEvent->hasNotified == false)
        {
            pEvent->hasNotified = true;
        }
    }

    static void notify_one(eventWait *pEvent)
    {
        if(pEvent == NULL) return;
        unique_lock<mutex> lck(pEvent->cvMutex);
        pEvent->condVar.notify_one();
        if (pEvent->hasNotified == false)
        {
            pEvent->hasNotified = true;
        }
    }

    eventWait(){};
    ~eventWait(){};
};



#endif