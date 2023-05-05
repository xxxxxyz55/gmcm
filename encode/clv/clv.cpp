#include "clv_static.h"

typedef int32_t (*clv_parse)(clv_field *pctx, uint8_t *str, uint16_t len, uint16_t *offset);
#define CLV_CTX ((clv_field *)this)

char getType(clv_field *pctx)
{
    return pctx->_type;
}

uint16_t *getLenPtr(clv_field *pctx)
{
    return &pctx->_len;
}

uint16_t getLen(clv_field *pctx)
{
    return pctx->_len;
}

void setVal(clv_field *pctx, uint16_t len, uint8_t *val)
{
    pctx->_pVal = val;
    pctx->_len = len;
}

typedef struct clv_meth_st
{
    clv_parse parse;
} clv_meth;

int32_t clv_ustr_parse(clv_field *pctx, uint8_t *str, uint16_t len, uint16_t *offset)
{
    if (len < (*offset + sizeof(uint16_t) + *(uint16_t *)(str + *offset)))
    {
        return CLV_ERR_LESS_IN_LEN;
    }

    setVal(pctx, *(uint16_t *)(str + *offset), str + *offset + sizeof(uint16_t));
    *offset += (sizeof(uint16_t) + *(uint16_t *)(str + *offset));
    if (pctx->_check)
    {
        return pctx->_check(pctx->_len, pctx->_pVal);
    }
    return 0;
}

uint8_t* clv_ustr::alloc(uint16_t size)
{
    setVal(&_ctx, size, new uint8_t[size]());
    _ctx._alloc = true;
    return (uint8_t *)_ctx._pVal;
}

uint8_t *clv_ustr::ptr()
{
    return (uint8_t *)_ctx._pVal;
}

uint16_t clv_ustr::len()
{
    return _ctx._len;
}
void clv_ustr::setLen(uint16_t len)
{
    _ctx._len = len;
}

void clv_ustr::ref(uint8_t *val, uint16_t len)
{
    setVal(&_ctx, len, val);
}

clv_ustr::clv_ustr(checkUstr check) : _ctx{CLV_TYPE_USTR, 0, NULL, false, (checkObj)check}
{
}

clv_ustr::~clv_ustr()
{
    if (_ctx._alloc)
    {
        delete[] (uint8_t *)_ctx._pVal;
    }
}

int32_t clv_int_parse(clv_field *pctx, uint8_t *str, uint16_t len, uint16_t *offset)
{
    if (len < (*offset + sizeof(uint16_t) + *(uint16_t *)(str + *offset)))
    {
        return CLV_ERR_LESS_IN_LEN;
    }

    setVal(pctx, *(uint16_t *)(str + *offset), str + *offset + sizeof(uint16_t));
    *offset += (sizeof(uint16_t) + *(uint16_t *)(str + *offset));
    if (pctx->_check)
    {
        return ((checkInt)pctx->_check)(pctx->_len, *(int32_t *)pctx->_pVal);
    }
    return 0;
}

int32_t *clv_i32::alloc()
{
    setVal(&_ctx, sizeof(int32_t), (uint8_t *)new int32_t());
    _ctx._alloc = true;
    return (int32_t *)_ctx._pVal;
}

int32_t *clv_i32::ptr()
{
    return (int32_t *)_ctx._pVal;
}

int32_t clv_i32::val()
{
    return *(int32_t *)_ctx._pVal;
}

void clv_i32::ref(int32_t *val)
{
    setVal(&_ctx, sizeof(int32_t), (uint8_t *)val);
}

clv_i32::clv_i32(checkInt check) : _ctx{CLV_TYPE_INT, 0, NULL, false, (checkObj)check}
{

}
clv_i32::~clv_i32()
{
    if (_ctx._alloc)
    {
        delete (int32_t *)_ctx._pVal;
    }
}

int32_t clv_obj::isCompleteClvPkt(uint8_t *str, uint16_t len)
{
    if (len < (sizeof(uint32_t) * 2 + EXT_LEN + sizeof(uint16_t)))
    {
        return CLV_ERR_PKT_UNCOMPLETE;
    }

    if (*(uint32_t *)str != PADINFO)
    {
        return CLV_ERR_PKT_ERR;
    }

    if(*(uint32_t *)(str + len - sizeof(uint32_t)) != PADINFO)
    {
        return CLV_ERR_PKT_UNCOMPLETE;
    }

    uint16_t pktLen = *(uint16_t *)(str + sizeof(uint32_t) + EXT_LEN);
    uint16_t tLen = len - (sizeof(uint32_t) * 2) - EXT_LEN - sizeof(uint16_t);
    if (pktLen == tLen)
    {
        return 0;
    }
    if (pktLen > tLen)
    {
        return CLV_ERR_PKT_ERR;
    }
    else
    {
        return CLV_ERR_PKT_UNCOMPLETE;
    }
}

uint8_t *clv_obj::clvPktGetExt(uint8_t *str)
{
    return str + sizeof(uint32_t);
}

uint16_t getTotalLen(clv_field * pctx, size_t size)
{
    size_t fieldNum = size / sizeof(clv_field);
    uint16_t len = 0;
    auto iter = pctx;
    for (size_t i = 0; i < fieldNum; i++, iter++)
    {
        if (iter->_type != CLV_TYPE_OBJ)
        {
            len += (sizeof(uint16_t) + iter->_len);
        }
    }

    return len;
}

int32_t clv_obj::clv_send(clv_field *pctx, size_t size, uint8_t *ext, int32_t (*writeCb)(void *buf, size_t len))
{
    int32_t ret;
    static uint32_t pad = PADINFO;
    ret = writeCb(&pad, sizeof(uint32_t));
    if (ret)
    {
        return ret;
    }

    ret = writeCb(ext, EXT_LEN);
    if (ret)
    {
        return ret;
    }

    uint16_t total = getTotalLen(pctx, size);
    ret = writeCb(&total, sizeof(uint16_t));
    if (ret)
    {
        return ret;
    }

    size_t fieldNum = size / sizeof(clv_field);
    auto iter = pctx;
    for (size_t i = 0; i < fieldNum; i++, iter++)
    {
        if (iter->_type != CLV_TYPE_OBJ)
        {
            ret = writeCb(&iter->_len, sizeof(uint16_t));
            if (ret)
            {
                return ret;
            }
            ret = writeCb(iter->_pVal, iter->_len);
            if (ret)
            {
                return ret;
            }
        }
    }

    ret = writeCb(&pad, sizeof(uint32_t));
    if (ret)
    {
        return ret;
    }

    return 0;
}

int32_t clv_obj::clv_send_ex(clv_field *pctx, size_t size, uint8_t *ext, int32_t (*writeCb)(void *buf, size_t len, void *param), void *param)
{
    int32_t ret;
    static uint32_t pad = PADINFO;
    ret = writeCb(&pad, sizeof(uint32_t), param);
    if (ret)
    {
        return ret;
    }

    ret = writeCb(ext, EXT_LEN, param);
    if (ret)
    {
        return ret;
    }

    uint16_t total = getTotalLen(pctx, size);
    ret = writeCb(&total, sizeof(uint16_t), param);
    if (ret)
    {
        return ret;
    }

    size_t fieldNum = size / sizeof(clv_field);
    auto iter = pctx;
    for (size_t i = 0; i < fieldNum; i++, iter++)
    {
        if (iter->_type != CLV_TYPE_OBJ)
        {
            ret = writeCb(&iter->_len, sizeof(uint16_t), param);
            if (ret)
            {
                return ret;
            }
            ret = writeCb(iter->_pVal, iter->_len, param);
            if (ret)
            {
                return ret;
            }
        }
    }

    ret = writeCb(&pad, sizeof(uint32_t), param);
    if (ret)
    {
        return ret;
    }

    return 0;
}

int32_t clv_obj::clv_send_cxx(clv_field *pctx, size_t size, uint8_t *ext, std::function<int32_t(void *, uint16_t)> writeCb)
{
    int32_t ret;
    static uint32_t pad = PADINFO;
    ret = writeCb(&pad, sizeof(uint32_t));
    if (ret)
    {
        return ret;
    }

    ret = writeCb(ext, EXT_LEN);
    if (ret)
    {
        return ret;
    }

    uint16_t total = getTotalLen(pctx, size);
    ret = writeCb(&total, sizeof(uint16_t));
    if (ret)
    {
        return ret;
    }

    size_t fieldNum = size / sizeof(clv_field);
    auto iter = pctx;
    for (size_t i = 0; i < fieldNum; i++, iter++)
    {
        if (iter->_type != CLV_TYPE_OBJ)
        {
            ret = writeCb(&iter->_len, sizeof(uint16_t));
            if (ret)
            {
                return ret;
            }

            ret = writeCb(iter->_pVal, iter->_len);
            if (ret)
            {
                return ret;
            }
        }
    }

    ret = writeCb(&pad, sizeof(uint32_t));
    if (ret)
    {
        return ret;
    }

    return 0;
}

static clv_parse func_parse[] = {
    NULL,           //CLV_TYPE_NULL
    clv_ustr_parse, //CLV_TYPE_USTR
    clv_int_parse,  //CLV_TYPE_INT
    NULL,           //CLV_TYPE_OBJ
    clv_ustr_parse, //CLV_TYPE_ST
};
clv_obj::clv_obj() : _ctx{CLV_TYPE_OBJ, 0, NULL, false, NULL}
{

}

int32_t clv_obj::clv_mapping(clv_field *pctx, size_t size, uint8_t *str, uint16_t len, bool check)
{
    uint16_t offset = 0;
    int32_t ret = 0;
    if (check)
    {
        ret = clv_obj::isCompleteClvPkt(str, len);
        if (ret)
        {
            printf("not complete clv pkt\n");
            return ret;
        }
    }

    size_t fieldNum = size / sizeof(clv_field);
    auto iter = pctx;
    size_t type;

    for (size_t i = 0; i < fieldNum; i++, iter++)
    {
        type = iter->_type;
        if (type != CLV_TYPE_OBJ)
        {
            if (func_parse[type])
            {
                ret = func_parse[type](iter,
                                       str + sizeof(uint32_t) + EXT_LEN + sizeof(uint16_t),
                                       *(uint16_t *)(str + sizeof(uint32_t) + EXT_LEN),
                                       &offset);
                if (ret)
                {
                    return ret;
                }
            }
            else
            {
                return CLV_ERR_PARSE_FUNC;
            }
        }
    }

    return 0;
}