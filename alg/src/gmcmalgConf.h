#ifndef _GMCM_ALG_CONF_
#define _GMCM_ALG_CONF_

#ifndef EXPORT_FUNC
#define EXPORT_FUNC __attribute__((visibility("default")))
#endif


#if SDF
#define SDF_EXPORT_FUNC EXPORT_FUNC
#else
#define SDF_EXPORT_FUNC
#endif

#define ALG_LOG_DEBUG(fmt, ...) fprintf(stdout, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);
#define ALG_LOG_ERROR(fmt, ...) fprintf(stderr, fmt "[%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__);

#endif