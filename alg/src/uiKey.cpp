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
            this->_lock.rlock();
            if (this->keyArrayUsing[i] &&
                gmcmTime::getTime() - this->keyArrayUsing[i]->updateTime > uikey_timeout / 1000)
            {
                this->_lock.unlock();
                this->_lock.wlock();

                if (this->keyQueueIdle.enqueue(this->keyArrayUsing[i]) == false)
                {
                    ALG_LOG_ERROR("timeout uikey enqueue fail.")
                    delete this->keyArrayUsing[i];
                }
                this->keyArrayUsing[i] = NULL;
                this->_lock.unlock();
            }
            this->_lock.unlock();
        }
    }
    return GMCM_OK;
}

uiKeyArray::uiKeyArray(int uikey_timeout)
{
    _lock.wlock();
    for (size_t i = 0; i < MAX_UIKEY_NUM; i++)
    {
        keyArrayUsing[i] = new uikey;
        keyArrayUsing[i]->index = i;
        if (keyQueueIdle.enqueue(keyArrayUsing[i]) == false)
        {
            ALG_LOG_ERROR("uikey queue enqueue fail.");
        }
        keyArrayUsing[i] = NULL;
    }
    _lock.unlock();

    if (uikey_timeout)
    {
        ukeyTimeoutThread = new std::thread(std::bind(&uiKeyArray::deal_with_uikey_timeout_route, this, std::placeholders::_1), uikey_timeout);
    }
}

int uiKeyArray::import_key(unsigned char *key, unsigned int length, void **handle)
{
    uikey * pUikey = NULL;
    if (keyQueueIdle.try_dequeue(pUikey) == false)
    {
        ALG_LOG_ERROR("uikey queue empty.");
        return GMCM_FAIL;
    }
    else
    {
        _lock.wlock();
        keyArrayUsing[pUikey->index] = pUikey;
        memcpy(pUikey->key, key, length);
        pUikey->length = length;
        *((unsigned int **)handle) = new unsigned int;
        **((unsigned int **)handle) = pUikey->index;
        pUikey->updateTime = gmcmTime::getTime();
        _lock.unlock();
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

    _lock.rlock();
    if (keyArrayUsing[*((unsigned int *)handle)] == NULL)
    {
        _lock.unlock();
        return GMCM_FAIL;
    }

    memcpy(key, keyArrayUsing[*((unsigned int *)handle)]->key, keyArrayUsing[*((unsigned int *)handle)]->length);
    *length = keyArrayUsing[*((unsigned int *)handle)]->length;
    keyArrayUsing[*((unsigned int *)handle)]->updateTime = gmcmTime::getTime();
    _lock.unlock();

    // utilTool::printHex(key, *length,"get key");
    return GMCM_OK;
}

int uiKeyArray::delKey(void *handle)
{
    if (handle == NULL || *((unsigned int *)handle) > MAX_UIKEY_NUM)
    {
        return GMCM_FAIL;
    }

    _lock.rlock();
    if (keyArrayUsing[*((unsigned int *)handle)] == NULL)
    {
        _lock.unlock();
        delete (unsigned int *)handle;
        return GMCM_OK;
    }
    else
    {
        _lock.unlock();
        _lock.wlock();
        if (keyQueueIdle.enqueue(keyArrayUsing[*((unsigned int *)handle)]) == false)
        {
            ALG_LOG_ERROR("uikey enqueue fail.");
            delete keyArrayUsing[*((unsigned int *)handle)];
        }
        keyArrayUsing[*((unsigned int *)handle)] = NULL;
        delete (unsigned int *)handle;
        _lock.unlock();
    }

    return GMCM_OK;
}

uiKeyArray::~uiKeyArray()
{
    uikey * pUikey = NULL;
    while (keyQueueIdle.try_dequeue(pUikey))
    {
        delete pUikey;
    }

    _lock.wlock();
    for (size_t i = 0; i < MAX_UIKEY_NUM; i++)
    {
        if (keyArrayUsing[i])
        {
            delete keyArrayUsing[i];
            keyArrayUsing[i] = NULL;
        }
    }
    _lock.unlock();

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