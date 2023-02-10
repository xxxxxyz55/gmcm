
#define SERVICE_SDK_API  "tcp -h 0.0.0.0 -p 8805 -t 0"
#define SERVICE_HTTP_API "tcp -h 0.0.0.0 -p 8806 -t 0"


#define SDF_API_LIB "../lib/libgmcmalg.so"

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
