
#ifndef _EVENT_WAIT_H_
#define _EVENT_WAIT_H_

#include <condition_variable>
#include <mutex>
/*
eventfd
事件等待
*/

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

        std::unique_lock<std::mutex> lck(pEvent->cvMutex);
        if (pEvent->condVar.wait_for(lck, std::chrono::milliseconds(ms)) == std::cv_status::timeout)
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
        std::unique_lock<std::mutex> lck(pEvent->cvMutex);
        pEvent->condVar.wait(lck);
    }

    //确保再唤醒前其他线程已经开始等待
    static void notify_all(eventWait *pEvent)
    {
        if(pEvent == NULL) return;
        std::unique_lock<std::mutex> lck(pEvent->cvMutex);
        pEvent->condVar.notify_all();
        if (pEvent->hasNotified == false)
        {
            pEvent->hasNotified = true;
        }
    }

    static void notify_one(eventWait *pEvent)
    {
        if(pEvent == NULL) return;
        std::unique_lock<std::mutex> lck(pEvent->cvMutex);
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