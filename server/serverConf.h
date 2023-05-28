#define SDF_API_LIB "/lib/libgmcmalg.so"

//兼容会话密钥句柄
#define HANDLE_TO_STR(hKeyHandle, handle, length) \
    do                                            \
    {                                             \
        memcpy(handle, hKeyHandle, 4);            \
        length = 4;                               \
        delete (unsigned int *)hKeyHandle;        \
    } while (0);

#define STR_TO_HANDLE(handle, length, hKeyHandle)              \
    do                                                         \
    {                                                          \
        hKeyHandle = new unsigned int;                         \
        *(unsigned int *)hKeyHandle = *(unsigned int *)handle; \
    } while (0);

#define FREE_HANDLE(hKeyHandle)            \
    do                                     \
    {                                      \
        delete (unsigned int *)hKeyHandle; \
    } while (0);

// TLS
#define GMCM_ENABLE_HTTPS 0
//0 rsa
//1 sm2
//不存在则生成一套
#define GMCM_CERT_TYPE 1
#define GMCM_CA_DIR    "./cert/ca"
#define GMCM_SIGN_CERT "./cert/sign.cer"
#define GMCM_SIGN_KEY  "./cert/sign.key"
#define GMCM_ENC_CERT  "./cert/enc.cer"
#define GMCM_ENC_KEY   "./cert/enc.key"

#if GMCM_ENABLE_HTTPS
#define GMCM_HTTP "ssl"
#else
#define GMCM_HTTP "tcp"
#endif

#define SERVICE_SDK_API "tcp -h 0.0.0.0 -p 8805 -t 0"
#define SERVICE_HTTP_API GMCM_HTTP " -h 0.0.0.0 -p 8806 -t 0"
#define SERVICE_MGMT_API GMCM_HTTP " -h 0.0.0.0 -p 8807 -t 0"