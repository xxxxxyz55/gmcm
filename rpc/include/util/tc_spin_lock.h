#ifndef __TC_SPIN_LOCK_H
#define __TC_SPIN_LOCK_H

#include "util/tc_platform.h"
#include <atomic>
#include <memory>
// #ifndef _GLIBCXX_HAS_GTHREADS
// #define _GLIBCXX_HAS_GTHREADS
// #endif
#include <thread>

using namespace std;

#define TRYS_COUNT 10
#define TRYS_SLEEP 1

namespace tars
{

/**
 * 自旋锁
 * 不能阻塞wait, 只能快速加解锁, 适用于锁粒度非常小的情况, 减小线程切换的开销
 * 不支持trylock
 */
class TC_SpinLock
{
public:

	TC_SpinLock()
    {
        _flag.clear(std::memory_order_release);
    }
	virtual ~TC_SpinLock()
    {

    }

	void lock() const
    {
        for (size_t i = 1; _flag.test_and_set(std::memory_order_acquire); i++)
        {
            if (i % TRYS_COUNT == 0)
            {
                // TC_Common::msleep(TRYS_SLEEP);
                std::this_thread::sleep_for(std::chrono::milliseconds(TRYS_SLEEP));
            }
            else
            {
                std::this_thread::yield();
            }
        }
    }

    bool tryLock() const
    {
        int trys = TRYS_COUNT;
        for (; trys > 0 && _flag.test_and_set(std::memory_order_acquire); --trys)
        {
            std::this_thread::yield();
        }

        if (trys > 0)
            return true;

        return false;
    }

    void unlock() const
    {
        _flag.clear(std::memory_order_release);
    }

private:

	TC_SpinLock(const TC_SpinLock&) = delete;
	TC_SpinLock(TC_SpinLock&&) = delete;
	TC_SpinLock& operator=(const TC_SpinLock&) = delete;
	TC_SpinLock& operator=(TC_SpinLock&&) = delete;

private:

	mutable std::atomic_flag _flag;
};

}
#endif
