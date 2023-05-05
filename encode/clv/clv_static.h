#ifndef _GMCM_CLV_STATIC_H_
#define _GMCM_CLV_STATIC_H_
#include <stdint.h>
#include <iostream>
#include <functional>

#define PADINFO 0xFFFFFFFF
#define CLV_ERR_LESS_IN_LEN     1
#define CLV_ERR_PKT_UNCOMPLETE  2
#define CLV_ERR_PKT_TOO_LONG    3
#define CLV_ERR_PARSE_FUNC      4
#define CLV_ERR_PKT_ERR         5

#define CLV_TYPE_NULL 0
#define CLV_TYPE_USTR 1
#define CLV_TYPE_INT 2
#define CLV_TYPE_OBJ 3
#define CLV_TYPE_ST 4

#define EXT_LEN 4

typedef int32_t (*checkUstr)(uint16_t length, uint8_t *val);
typedef int32_t (*checkInt)(uint16_t length, int32_t val);
typedef int32_t (*checkObj)(uint16_t length, void *val);

typedef struct
{
    char _type;
    uint16_t _len;
    void *_pVal;
    bool _alloc;
    checkObj _check;
} clv_field;

class clv_ustr
{
private:
    clv_field _ctx;

public:
    uint8_t *alloc(uint16_t size);
    uint8_t *ptr();
    uint16_t len();
    void setLen(uint16_t len);
    void ref(uint8_t *val, uint16_t len);
    clv_ustr(checkUstr check);
    ~clv_ustr();
};

template <typename T>
class clv_st
{
private:
    clv_field _ctx;

public:
    T *alloc(uint16_t size = sizeof(T))
    {
        _ctx._pVal = new uint8_t[size]();
        _ctx._len = size;
        _ctx._alloc = true;
        return (T *)_ctx._pVal;
    }

    T *ptr()
    {
        return (T *)_ctx._pVal;
    }

    uint16_t len()
    {
        return _ctx._len;
    }

    void ref(T *val, uint16_t len = sizeof(T))
    {
        _ctx._pVal = val;
        _ctx._len = len;
    }

    clv_st(int32_t (*check)(uint16_t size, T *)) : _ctx{CLV_TYPE_ST, 0, NULL, false, (checkObj)check}
    {
    }

    ~clv_st()
    {
        if (_ctx._alloc)
        {
            delete[] (uint8_t *)_ctx._pVal;
        }
    }
};

class clv_i32
{
private:
    clv_field _ctx;


public:
    int32_t * alloc();
    int32_t *ptr();
    int32_t val();
    void ref(int32_t *val);
    clv_i32(checkInt check);
    ~clv_i32();
};


class clv_obj
{
private:
    clv_field _ctx;

protected:
    static int32_t clv_send(clv_field *pctx, size_t size, uint8_t *ext, int32_t (*writeCb)(void *buf, size_t len));
    static int32_t clv_send_ex(clv_field *pctx, size_t size, uint8_t *ext, int32_t (*writeCb)(void *buf, size_t len, void *param), void *param);
    static int32_t clv_send_cxx(clv_field *pctx, size_t size, uint8_t *ext, std::function<int32_t(void *, uint16_t)> writeCb);
    static int32_t clv_mapping(clv_field *pctx, size_t size, uint8_t *str, uint16_t len, bool check = false);

public:
    static int32_t isCompleteClvPkt(uint8_t *str, uint16_t len);
    static uint8_t *clvPktGetExt(uint8_t *str);

    clv_obj();
    ~clv_obj(){};
};

#define CLV_USTR(name, check) \
    clv_ustr name{check};

#define CLV_INT(name, check) \
    clv_i32 name{check};

#define CLV_OBJ(type, name) \
    type name{};

#define CLV_ST(type, name, check) \
    clv_st<type> name{check};

#define CLV_SEQ_REF(type)        \
    class type : public clv_obj  \
    {                            \
    private:                     \
        size_t size()            \
        {                        \
            return sizeof(type); \
        }                        \
                                 \
    public:                      \
        type() : clv_obj()       \
        {                        \
        }                        \
        ~type()                  \
        {                        \
        }

#define CLV_SEQ_END_REF(type)                                                                          \
    int32_t send(uint8_t *ext, int32_t (*writeCb)(void *buf, size_t len))                              \
    {                                                                                                  \
        return clv_obj::clv_send((clv_field *)this, sizeof(type), ext, writeCb);                       \
    }                                                                                                  \
    int32_t send_ex(uint8_t *ext, int32_t (*writeCb)(void *buf, size_t len, void *param), void *param) \
    {                                                                                                  \
        return clv_obj::clv_send_ex((clv_field *)this, sizeof(type), ext, writeCb, param);             \
    }                                                                                                  \
    int32_t send(uint8_t *ext, std::function<int32_t(void *, uint16_t)> writeCb)                       \
    {                                                                                                  \
        return clv_obj::clv_send_cxx((clv_field *)this, sizeof(type), ext, writeCb);                   \
    }                                                                                                  \
    int32_t mapping(uint8_t *str, uint16_t len, bool check = false)                                    \
    {                                                                                                  \
        return clv_obj::clv_mapping((clv_field *)this, sizeof(type), str, len, check);                 \
    }                                                                                                  \
    }                                                                                                  \
    ;

#endif