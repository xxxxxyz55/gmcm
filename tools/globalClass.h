#ifndef _GMCM_GLOBAL_CLASS_H_
#define _GMCM_GLOBAL_CLASS_H_

/*
usage:
1. 使用getGlobalClass 将一个类构建为全局类，该类无需使用glocalClass 

2. 使用getGlobalClass 编写类的静态方法,调用方法时无需使用glocalClass

*/
template <typename T>
class globalClass : public T
{
private:
    globalClass(){};
    ~globalClass(){};

public:
    /*
    constructor 首次调用 getGlobalClass 会构造结构
    destructor  flag = false 会析构
    */
    static globalClass *getGlobalClass(bool flag = true)
    {
        static globalClass *_globalClass = NULL;
        if (!_globalClass && flag)
        {
            _globalClass = new globalClass();
        }
        else if (!flag && _globalClass)
        {
            delete _globalClass;
            _globalClass = NULL;
        }
        return _globalClass;
    }
};

#endif