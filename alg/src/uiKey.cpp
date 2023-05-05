#include "uiKey.h"
#include <iostream>
#include "gmcmTime.h"
#include <string.h>

int uiKeyArray::deal_with_uikey_timeout_route(int uikey_timeout)
{
    while (eventWait::wait_for(&this->ukeyTimeouThreadExit, uikey_timeout, true) == false)
    {
        for (size_t i = 0; i < MAX_UIKEY_NUM; i++)
        {
            this->_lock.readLock();
            if (this->keyArrayUsing[i] &&
                gmcmTime::getTime() - this->keyArrayUsing[i]->updateTime > uikey_timeout / 1000)
            {
                this->_lock.unReadLock();
                this->_lock.writeLock();

                // if (this->keyQueueIdle.enqueue(this->keyArrayUsing[i]) == false)
                // {
                //     ALG_LOG_ERROR("timeout uikey enqueue fail.")
                //     delete this->keyArrayUsing[i];
                // }
                keyQueueIdle.push_back(this->keyArrayUsing[i]);
                this->keyArrayUsing[i] = NULL;
                this->_lock.unWriteLock();
            }
            else
            {
                this->_lock.unReadLock();
            }
        }
    }
    return GMCM_OK;
}

uiKeyArray::uiKeyArray(int uikey_timeout)
{
    _lock.writeLock();
    for (size_t i = 0; i < MAX_UIKEY_NUM; i++)
    {
        keyArrayUsing[i] = new uikey;
        keyArrayUsing[i]->index = i;
        // if (keyQueueIdle.enqueue(keyArrayUsing[i]) == false)
        // {
        //     ALG_LOG_ERROR("uikey queue enqueue fail.");
        // }
        keyQueueIdle.push_back(keyArrayUsing[i]);
        keyArrayUsing[i] = NULL;
    }
    _lock.unWriteLock();

    if (uikey_timeout)
    {
        ukeyTimeoutThread = new std::thread(std::bind(&uiKeyArray::deal_with_uikey_timeout_route, this, std::placeholders::_1), uikey_timeout);
    }
}

int uiKeyArray::import_key(unsigned char *key, unsigned int length, void **handle)
{
    uikey * pUikey = NULL;
    // if (keyQueueIdle.try_dequeue(pUikey) == false)
    if (keyQueueIdle.pop_front(pUikey) == false)
    {
        ALG_LOG_ERROR("uikey queue empty.");
        return GMCM_FAIL;
    }
    else
    {
        _lock.writeLock();
        keyArrayUsing[pUikey->index] = pUikey;
        memcpy(pUikey->key, key, length);
        pUikey->length = length;
        *((unsigned int **)handle) = new unsigned int;
        **((unsigned int **)handle) = pUikey->index;
        pUikey->updateTime = gmcmTime::getTime();
        _lock.unWriteLock();
        // utilTool::printHex( key, length, "import key");
        return GMCM_OK;
    }
}

int uiKeyArray::getKey(void *handle, unsigned char *key, unsigned int *length)
{
    if (handle == NULL || *((unsigned int *)handle) > MAX_UIKEY_NUM)
    {
        return GMCM_FAIL;
    }

    _lock.readLock();
    if (keyArrayUsing[*((unsigned int *)handle)] == NULL)
    {
        _lock.unReadLock();
        return GMCM_FAIL;
    }

    memcpy(key, keyArrayUsing[*((unsigned int *)handle)]->key, keyArrayUsing[*((unsigned int *)handle)]->length);
    *length = keyArrayUsing[*((unsigned int *)handle)]->length;
    keyArrayUsing[*((unsigned int *)handle)]->updateTime = gmcmTime::getTime();
    _lock.unReadLock();

    // utilTool::printHex(key, *length,"get key");
    return GMCM_OK;
}

int uiKeyArray::delKey(void *handle)
{
    if (handle == NULL || *((unsigned int *)handle) > MAX_UIKEY_NUM)
    {
        return GMCM_FAIL;
    }

    _lock.readLock();
    if (keyArrayUsing[*((unsigned int *)handle)] == NULL)
    {
        _lock.unReadLock();
        delete (unsigned int *)handle;
        return GMCM_OK;
    }
    else
    {
        _lock.unReadLock();
        _lock.writeLock();
        // if (keyQueueIdle.enqueue(keyArrayUsing[*((unsigned int *)handle)]) == false)
        // {
        //     ALG_LOG_ERROR("uikey enqueue fail.");
        //     delete keyArrayUsing[*((unsigned int *)handle)];
        // }
        keyQueueIdle.push_back(keyArrayUsing[*((unsigned int *)handle)]);
        keyArrayUsing[*((unsigned int *)handle)] = NULL;
        delete (unsigned int *)handle;
        _lock.unWriteLock();
    }

    return GMCM_OK;
}

uiKeyArray::~uiKeyArray()
{
    uikey * pUikey = NULL;
    // while (keyQueueIdle.try_dequeue(pUikey))
    while (keyQueueIdle.pop_front(pUikey))
    {
        delete pUikey;
    }

    _lock.writeLock();
    for (size_t i = 0; i < MAX_UIKEY_NUM; i++)
    {
        if (keyArrayUsing[i])
        {
            delete keyArrayUsing[i];
            keyArrayUsing[i] = NULL;
        }
    }
    _lock.unWriteLock();

    if (ukeyTimeoutThread)
    {
        exit_ukey_timeout_thread();
    }
}

void uiKeyArray::exit_ukey_timeout_thread()
{
    if (ukeyTimeoutThread)
    {
        eventWait::notify_all(&ukeyTimeouThreadExit);
        if (ukeyTimeoutThread->joinable())
        {
            ukeyTimeoutThread->join();
            delete ukeyTimeoutThread;
            ukeyTimeoutThread = NULL;
        }
    }
}