#ifndef _VERIFY_VAR_H_
#define _VERIFY_VAR_H_
#include <stdint.h>
#include <vector>

/**
 * 参数验证模板
 * 通过模板类型调用参数检查
 * 注册全局参数检查
 * VerifyVar::RegisterVar<VERIFY_DATALEN>({{0, check_datalen}});
 * 检查参数
 * VerifyVar::verify((VERIFY_DATALEN *)&dataLen);
*/

using verifyVarCb = int32_t (*)(const char *);

class VerifyCtx
{

public:
    uint16_t _offset; //相对偏移 offsetof
    void *_pf;        //检查函数
    template <typename T>
    VerifyCtx(uint16_t offset, T pf) : _offset(offset), _pf((void *)pf)
    {
    }
};

class VerifyVar
{
private:
    template <typename T>
    class VerifyBase
    {
    public:
        std::vector<VerifyCtx> _vt;
        VerifyBase(std::initializer_list<VerifyCtx> vt)
        {
            for (auto ctx : vt)
            {
                _vt.push_back(ctx);
            }
        }

        int32_t check(T *pkt)
        {
            int32_t ret = 0;
            for (size_t i = 0; i < _vt.size(); i++)
            {
                ret = ((verifyVarCb)_vt.at(i)._pf)((const char *)pkt + _vt.at(i)._offset);
                if (ret)
                {
                    return ret;
                }
            }
            return 0;
        }
    };

    template <typename T>
    static T *GlobalVar(T *initObj = NULL)
    {
        static T *_obj = NULL;
        if (initObj)
        {
            _obj = initObj;
        }
        return _obj;
    }

public:
    template <typename T>
    static void RegisterVar(std::initializer_list<VerifyCtx> vt)
    {
        if (GlobalVar<VerifyBase<T>>())
        {
            throw "double register.";
        }
        else
        {
            static VerifyBase<T> verify{vt};
            GlobalVar(&verify);
        }
    }

    template <typename T>
    static int32_t verify(T *pkt)
    {
        auto p =  GlobalVar<VerifyBase<T>>();
        if (p == NULL)
        {
            // throw "verify func not found.";
            return -1;
        }
        else
        {
            return p->check(pkt);
        }
    }
};




#endif