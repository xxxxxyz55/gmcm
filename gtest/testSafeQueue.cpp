#include "concurrentqueue.h"
#include <iostream>
#include "eventWait.h"
#include "utilFunc.h"
#include <thread>
#include <vector>
#include <mutex>
#include "util/tc_cas_queue.h"

using namespace std;
using namespace moodycamel;
using namespace tars;

ConcurrentQueue<int> gQueue;
TC_CasQueue<int> tcQueue;
bool threadFlag = false;
atomic<int> gCount;
mutex start;
int gType = 0;
int gMode = 0;
int gItemNum = 8;

void queue_push_and_pop(int val)
{
    int item = val;
    int out;
    start.lock();
    start.unlock();
    if (gType == 0)
    {
        while (threadFlag)
        {
            if (gQueue.enqueue(item) == false)
            {
                cout << "enqueue fail." << endl;
                continue;
            }

            if (gQueue.try_dequeue(out) == false)
            {
                cout << "dequeue fail." << endl;
            }
            gCount++;
        }
    }
    else
    {
        while (threadFlag)
        {
            tcQueue.push_back(item);

            if (tcQueue.pop_front(out) == false)
            {
                cout << "dequeue fail." << endl;
            }

            gCount++;
        }
    }
}

void queue_push_or_pop(int val)
{
    int item = val;
    int out;
    start.lock();
    start.unlock();
    if (gType == 0)
    {
        if (val % 2 == 0)
        {
            while (threadFlag)
            {
                if (gQueue.enqueue(item) == false)
                {
                    cout << "enqueue fail." << endl;
                    continue;
                }
            }
        }
        else
        {
            while (threadFlag)
            {
                if (gQueue.try_dequeue(out) == false)
                {
                    // cout << "dequeue fail." << endl;
                    continue;
                }
                else
                {
                    gCount++;
                }
            }
        }
    }
    else
    {
        if (val % 2 == 0)
        {
            while (threadFlag)
            {
                tcQueue.push_back(item);
            }
        }
        else
        {
            while (threadFlag)
            {
                if (tcQueue.pop_front(out) == false)
                {
                    // cout << "dequeue fail." << endl;
                    continue;
                }
                else
                {
                    gCount++;
                }
            }
        }
    }
}

void queue_push_after_pop(int val)
{
    int item = val;
    int out;
    start.lock();
    start.unlock();
    if (gType == 0)
    {
        while (threadFlag)
        {
            if (gQueue.try_dequeue(out) == false)
            {
                // cout << "dequeue fail." << endl;
                continue;
            }
            else
            {
                while (gQueue.enqueue(out) == false)
                {

                }
                gCount++;
            }
        }
    }
    else
    {

        while (threadFlag)
        {
            if (tcQueue.pop_front(out) == false)
            {
                cout << "dequeue fail." << endl;
                continue;
            }
            else
            {
                tcQueue.push_back(out);
                gCount++;
            }
        }
    }

}


int main(int argc, char const *argv[])
{
    gType = utilTool::stdGetInt("0 concurrentqueue \n1 tc queue\n");
    gMode = utilTool::stdGetInt("0 merge \n1 detach\n2 compete\n");

    vector<thread *> vtThread;
    start.lock();
    int threadNum = 8;
    if(gMode == 1)
    {
        threadNum *= 2;
    }

    if(gMode == 2)
    {
        if (gType == 0)
        {
            for (int i = 0; i < gItemNum; i++)
            {
                gQueue.enqueue(i);
            }
        }
        else
        {
            for (int i = 0; i < gItemNum; i++)
            {
                tcQueue.push_back(i);
            }
        }
    }

    for (int i = 0; i < threadNum; i++)
    {
        if (gMode == 0)
        {
            vtThread.push_back(new thread(&queue_push_and_pop, i));
        }
        else if (gMode == 1)
        {
            vtThread.push_back(new thread(&queue_push_or_pop, i));
        }
        else if (gMode == 2)
        {
            vtThread.push_back(new thread(&queue_push_after_pop, i));
        }
    }

    gCount = 0;
    threadFlag = true;
    start.unlock();
    int tm = 3;
    utilTool::Msleep(tm * 1000);
    threadFlag = false;

    for (size_t i = 0; i < vtThread.size(); i++)
    {
        vtThread[i]->join();
        delete vtThread[i];
    }

    cout << "thread num " << threadNum << " speed " << gCount / tm << " tps" << endl;

    return 0;
}
