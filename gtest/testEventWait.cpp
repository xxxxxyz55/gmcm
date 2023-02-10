#include <iostream>
#include "eventWait.h"
#include "utilFunc.h"
#include <thread>

using namespace std;

eventWait *pExitEvent = NULL;

void* waitRoute(int id)
{
    int count = 10;
    cout << "wait for start " << time(NULL) << endl;
    while (count--)
    {
        if (eventWait::wait_for(pExitEvent, 100, true) == true)
        {
            cout << "wait for event ok." << time(NULL) << endl;
        }
        else
        {
            cout << "wait for event fail." << time(NULL) << endl;
        }

        utilTool::Msleep(1000);
    }

   return NULL;
}

int main(int argc, char const *argv[])
{
    pExitEvent = new eventWait();

    std::thread threadId = std::thread(waitRoute, 0);

    utilTool::Msleep(5000);
    cout << "notify_all " << time(NULL) << endl;
    eventWait::notify_all(pExitEvent);

    threadId.join();

    delete pExitEvent;
    return 0;
}
