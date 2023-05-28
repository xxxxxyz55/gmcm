#ifndef _CM_ERR_H_
#define _CM_ERR_H_
#include <iostream>

using namespace std;

#ifndef GMCM_OK
#define GMCM_OK 0
#define GMCM_FAIL 1
#endif

enum
{
    GMCM_RWLOCK = 2,
    GMCM_BUF_TOO_SMALL,
    GMCM_PARAM_NULL,
    GMCM_RAND_BYTES,
    GMCM_ERR_ALGID,
    GMCM_ERR_PARAM_LEN,
    GMCM_ERR_KEK_INDEX,
    GMCM_ERR_NO_DEF,
    GMCM_ERR_KEY_EXIST,
    GMCM_ERR_KEY_NOT_EXIST,
    GMCM_ERR_PACKAGE,
    GMCM_ERR_CMD_UNDEFINE,
    GMCM_ERR_CONNECT_FAIL,
    GMCM_ERR_SEND_FAIL,
    GMCM_ERR_TIMEOUT,
    GMCM_ERR_RECV_FAIL,
    GMCM_ERR_RECV_CMD,
    GMCM_ERR_RECV_LEN,
    GMCM_ERR_REQUIRED_PARAM,
    GMCM_ERR_HAS_WAIT,
    GMCM_ERR_NO_WAIT,
    GMCM_ERR_THREAD_FAIL_JOIN,
    GMCM_ERR_THREAD_FAIL_EXIT,
    GMCM_ERR_BUF_NOT_ENOUGH,
    GMCM_ERR_REDIS_CONN,
    GMCM_ERR_REDIS_EXEC,
    GMCM_ERR_PARAM_NULL,
    GMCM_ERR_DLOPEN,
    GMCM_ERR_FILE_PATH,
    GMCM_ERR_LIB_NOT_FOUND,
    GMCM_SDF_FUNC_FAIL,
    GMCM_ERR_SDF_KEY_NUM,
    GMCM_ERR_OPEN_SESSION,
    GMCM_ERR_REPLY_TYPE,
    GMCM_ERR_REPLY_EMPTY,
    GMCM_ERR_KEY_TYPE,
    GMCM_ERR_GEN_KEY,
    GMCM_ERR_GEN_CSR,
    GMCM_ERR_EXPORT_PEM,
    GMCM_ERR_JSON_DECODE,
    GMCM_ERR_JSON_TYPE,
    GMCM_ERR_KEY,
    GMCM_ERR_CERT_USAGE,
    GMCM_ERR_CERT,
    GMCM_ERR_SIGN_CERT,
    GMCM_ERR_METHOD,
    GMCM_ERR_END,
};

#define ERR_REASONS                          \
    {                                        \
        /*0*/ "success",                     \
            "fail",                          \
            "rwlock fail",                   \
            "buffer too small",              \
            "pass null param",               \
            "rand bytes fail",               \
            "err algid",                     \
            "param len err",                 \
            "kek index err",                 \
            "no define",                     \
            /*10*/ "key exist",              \
            "key not exist",                 \
            "recv err package",              \
            "cmd undefine",                  \
            "connect fail",                  \
            "send data fail",                \
            "timeout",                       \
            "recv fail",                     \
            "recv cmd err",                  \
            "recv len err",                  \
            /*20*/ "need necessarily param", \
            "has another wait",              \
            "no wait",                       \
            "thread fail join",              \
            "thread fail exit",              \
            "buffer not enough",             \
            "redis connect fail",            \
            "redis exec cmd fail",           \
            "param null",                    \
            "dlopen fail",                   \
            /*30*/ "err file path",          \
            "lib not found",                 \
            "sdf func return err",           \
            "sdf err key index",             \
            "sdf err open session",          \
            "invalid reply type",            \
            "reply empty",                   \
            "invalid key type",              \
            "gen key pair fail.",            \
            "gen csr fail.",                 \
            /*40*/ "export pem fail.",       \
            "json decode err.",              \
            "json value type err.",          \
            "invalied key.",                 \
            "invalied cert usage.",          \
            "invalied cert.",                \
            "sign cert fail.",               \
            "invalied request method.",      \
    }

inline const char *errGetReason(unsigned int err)
{
    static char errReasons[][128] = ERR_REASONS;
    if (err < GMCM_ERR_END)
    {
        return errReasons[err];
    }
    else
    {
        return "NULL";
    }
}

#endif