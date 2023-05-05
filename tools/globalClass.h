#ifndef _GMCM_GLOBAL_CLASS_H_
#define _GMCM_GLOBAL_CLASS_H_
#include <mutex>
/*
usage:
1. 使用getGlobalClass 将一个类构建为全局类，该类无需使用glocalClass 
2. 继承getGlobalClass

*/
template <typename T>
class globalClass
{
private:
    static void atExit()
    {
        delete getGlobalClass();
    }

public:
    static T *getGlobalClass()
    {
        static std::mutex _lock;
        static T *_obj = NULL;
        if (!_obj)
        {
            std::lock_guard<std::mutex> lock(_lock);
            if (!_obj)
            {
                _obj = new T;
                atexit(atExit);
            }
        }
        return _obj;
    }
};

#define DECLEAR_SIGLETON_TYPE(type) \
    type *get_global_##type();

#define DEFINE_SIGLETON_TYPE(type)      \
    void free_global_##type()           \
    {                                   \
        delete get_global_##type();     \
    }                                   \
    type *get_global_##type()           \
    {                                   \
        static type *_obj = NULL;       \
        if (!_obj)                      \
        {                               \
            _obj = new type;            \
            atexit(free_global_##type); \
        }                               \
        return _obj;                    \
    }

#endif