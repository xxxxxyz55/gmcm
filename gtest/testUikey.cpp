#include <iostream>
#include "../alg/src/uiKey.h"
#include "string.h"

using namespace std;

void import_key_route(int * exitFlag)
{
    uiKeyArray *pUikeyArray = uiKeyArray::get_uikey_array();
    unsigned char key[16];
    unsigned int keyLen = 16;
    unsigned char keyGet[16];
    unsigned int keyGetLen = 16;
    void *handle = NULL;
    int count = 0;

    memset(key, 0x01, 16);

    while (!*exitFlag)
    {
        if(pUikeyArray->import_key(key, keyLen, &handle))
        {
            cout << "import key fail" << endl;
            break;
        }

        if (pUikeyArray->getKey(handle, keyGet, &keyGetLen))
        {
            cout << "get key fail" << endl;
            break;
        }

        if(memcmp(keyGet, key, keyLen))
        {
            cout << "compair key fail" << endl;
            break;
        }

        if(pUikeyArray->delKey(handle))
        {
            cout << "delete key fail" << endl;
            break;
        }
        count ++;
    }

    cout << pthread_self() << " loop = " << count << endl;
}

int main(int argc, char const *argv[])
{
    uiKeyArray::get_uikey_array();
    unsigned int threadNum = 8;
    std::thread * threads[32];
    int threadExit = 0;

    for(size_t i = 0; i < threadNum; i++)
    {
        threads[i] = new std::thread(import_key_route, &threadExit);
    }

    utilTool::Msleep(10000);
    threadExit = 1;

    for (size_t i = 0; i < threadNum; i++)
    {
        threads[i]->join();
        delete threads[i];
    }

    return 0;
}
