#ifndef _GMCM_GTEST_H_
#define _GMCM_GTEST_H_

#include <iostream>
#include <map>
#include "eventWait.h"
#include <thread>
#include <atomic>
#include <vector>


typedef void (*Gtest_case)();
class Gtest
{
private:
    std::map<int, std::pair<std::string, Gtest_case>> mpTests;
    int _key = 1;

public:
    void pushTest(Gtest_case func, std::string desc)
    {
        mpTests.insert(std::pair<int, std::pair<std::string, Gtest_case>>(_key++, std::pair<std::string, Gtest_case>(desc, func)));
    }

    void printMenu()
    {
        std::cout << "\n0 exit\n";
        for (auto iter = mpTests.begin(); iter != mpTests.end(); iter++)
        {
            std::cout << iter->first << " " << iter->second.first << "\n";
        }
    }

    void run()
    {
        int val = 0;
        Gtest_case pTest = NULL;
        do
        {
            printMenu();
            std::cin >> val;
            if (val)
            {
                try
                {
                    pTest = mpTests.at(val).second;
                }
                catch (const std::exception &e)
                {
                    std::cout << "key " << val << "test not found.\n";
                    val = 0;
                }

                if (pTest)
                {
                    std::cout << "\nkey " << val << "  run " << mpTests.at(val).first << ".\n";
                    pTest();
                }
            }
        } while (val != 0);
    }


public:
    class GtestLoop
    {
        friend class Gtest;

    private:
        void start()
        {
            _count = 0;
            _cond = true;
            eventWait::notify_all(&_start);
        }

        void stop()
        {
            _cond = false;
        }

        std::atomic<uint64_t> _count;
        bool _cond = true;
        virtual void init(size_t i = 0){};
        virtual void run(size_t i = 0){};
        size_t _threadNum;
        eventWait _start;
        size_t _loopBytes = 0;

    public:
        void setThreadNum(size_t threadNum)
        {
            _threadNum = threadNum;
        }
        void setDataLength(size_t bytes)
        {
            _loopBytes = bytes;
        }

        GtestLoop(size_t threadNum = 1) : _threadNum(threadNum)
        {
        }
        ~GtestLoop() {}
    };

    static int gtestLoopInMs(int ms, GtestLoop *loop)
    {
        if (loop == NULL)
        {
            return -1;
        }

        std::vector<std::thread *> vtThread;
        for (size_t i = 0; i < loop->_threadNum; i++)
        {
            vtThread.push_back(new std::thread(gtest_loop, loop, i));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        loop->start();
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        loop->stop();
        for (size_t i = 0; i < vtThread.size(); i++)
        {
            vtThread[i]->join();
        }
        std::cout << "SPEED " << loop->_count * 1000 / ms << "  Tps\n";
        if (loop->_loopBytes)
        {
            std::cout << "SPEED " << loop->_count * loop->_loopBytes * 1000 * 8 / ms / 1024 / 1024 << " Mbps\n";
        }
        return loop->_count;
    }

private:
    static void gtest_loop(GtestLoop *loop, size_t i)
    {
        eventWait::wait(&loop->_start);
        loop->init(i);
        while (loop->_cond)
        {
            loop->run(i);
            loop->_count++;
        }
    }

public:
    Gtest(/* args */){};
    ~Gtest() { mpTests.clear(); }
};


#endif 