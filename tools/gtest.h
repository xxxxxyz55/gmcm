#ifndef _GMCM_GTEST_H_
#define _GMCM_GTEST_H_

#include <iostream>
#include <map>
#include "eventWait.h"
#include <thread>
#include <atomic>
#include <vector>
#include <pthread.h>
#include <unistd.h>
#include <iomanip>

typedef void (*Gtest_case)();
class Gtest
{
private:
    std::map<int, std::pair<std::string, Gtest_case>> mpTests;
    int _key = 1;

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
    void pushTest(Gtest_case func, std::string desc)
    {
        mpTests.insert(std::pair<int, std::pair<std::string, Gtest_case>>(_key++, std::pair<std::string, Gtest_case>(desc, func)));
    }

public:
    Gtest(/* args */){};
    ~Gtest()
    {
        run();
        mpTests.clear();
    }
};

class GtestLoop
{
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
    virtual int init(size_t i = 0) { return 0; }
    virtual int run(size_t i = 0) = 0;
    size_t _threadNum;
    eventWait _start;
    size_t _loopBytes = 0;

    void gtest_loop(size_t i)
    {
        if (init(i))
        {
            return;
        }
        cpu_set_t mask;
        uint32_t cpu_num = sysconf(_SC_NPROCESSORS_CONF);
        CPU_ZERO(&mask);
        CPU_SET(i % cpu_num, &mask);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask);

        eventWait::wait(&_start);

        while (_cond)
        {
            if (run(i))
            {
                continue;
            }
            _count++;
        }
    }

    void show_route()
    {
        eventWait::wait(&_start);

        while (_cond)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            uint64_t tCount = _count;
            _count = 0;
            std::cout << "\nSPEED " << std::setw(10) << tCount << "    Tps\n";
            if (_loopBytes)
            {
                std::cout << "SPEED " << std::setw(10) << tCount * _loopBytes * 8 / 1024 / 1024 << "   Mbps\n";
            }
        }
    }

public:
    void setThreadNum(size_t threadNum)
    {
        _threadNum = threadNum;
    }

    void setDataLength(size_t bytes)
    {
        _loopBytes = bytes;
    }

    int loopFor(int sec = 0)
    {
        std::vector<std::thread *> vtThread;
        for (size_t i = 0; i < _threadNum; i++)
        {
            vtThread.push_back(new std::thread(&GtestLoop::gtest_loop, this, i));
        }

        if (!sec)
        {
            vtThread.push_back(new std::thread(&GtestLoop::show_route, this));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        start();
        if(sec)
        {
            std::this_thread::sleep_for(std::chrono::seconds(sec));
            stop();
        }
        else
        {
            int val = 1;
            std::cout << "input 0 to exit:";
            fflush(stdout);
            while (val)
            {
                std::cin >> val;
            }
            stop();
        }

        for (size_t i = 0; i < vtThread.size(); i++)
        {
            vtThread[i]->join();
        }

        if(sec)
        {
            std::cout << "\nSPEED " << std::setw(10) << _count / sec << "    Tps\n";
            if (_loopBytes)
            {
                std::cout << "SPEED " << std::setw(10) << _count * _loopBytes * 8 / sec / 1024 / 1024 << "   Mbps\n";
            }
        }

        return _count;
    }

    GtestLoop(size_t threadNum = 1) : _threadNum(threadNum)
    {
    }
    ~GtestLoop() {}
};

#endif