#include <iostream>
#include <netinet/tcp.h>
#include "server.h"
#include "signal.h"
#include "handle/hsmHandleClv.h"
#include "handle/svsHandle.h"
#include "handle/mgmtHandle.h"
#include "utilFunc.h"
#include "application/application.h"
#include "serverConf.h"
#include "globalClass.h"
#include "algApi.h"
#include <dirent.h>
#include "apiEngine/apiEngine.h"

using namespace std;

gmcmServer::gmcmServer()
{
    dealSignal([=] { serverExit(); }); //lambda 表达式
    if (init())
    {
        terminate();
    }
    else
    {
        openssl_err_stack();
        waitForShutdown();
    }
}

void gmcmServer::serverExit()
{
    terminate();
    utilTool::Msleep(1000);
    exit(1);
}

int gmcmServer::init()
{
    int ret = GMCM_OK;
    gmcmLog::setLogLevel(gmcmLog::DEBUG_LOG_LEVEL);
    setOpenCoroutine(TC_EpollServer::SERVER_OPEN_COROUTINE::NET_THREAD_MERGE_HANDLES_THREAD);
    // setOpenCoroutine(TC_EpollServer::SERVER_OPEN_COROUTINE::NET_THREAD_QUEUE_HANDLES_THREAD);
    // setThreadNum(sysconf(_SC_NPROCESSORS_CONF));//网络线程

    addService<mgmtHandle>(SERVICE_MGMT_API, "gmcm_mgmt_server", TC_NetWorkBuffer::parseHttp);
    addService<gmcmHsmClvHandle>(SERVICE_SDK_API, "gmcm_tcp_server", parseGmcmClv);
    addService<gmcmSvsHandle>(SERVICE_HTTP_API, "gmcm_http_server", TC_NetWorkBuffer::parseHttp);

    globalClass<hsmApiClvEngine>::getGlobalClass();
    globalClass<svsApiEngine>::getGlobalClass();
    globalClass<mgmtApiEngine>::getGlobalClass();

    if (!redisConn::getRedisConnPool())
    {
        gmcmLog::LogError() << "redis init fail." << endl;
        return GMCM_FAIL;
    }
    else
    {
        gmcmLog::LogInfo() << "redis init success." << endl;
    }

    
    ret = applicationList::loadAllApp();
    if (ret)
    {
        gmcmLog::LogError() << "load lib fail." << endl;
        return GMCM_FAIL;
    }
    else
    {
        gmcmLog::LogInfo() << "load lib success." << endl;
    }

    return GMCM_OK;
}

template <typename T>
int gmcmServer::addService(const char *host, const char *serviceName, const TC_NetWorkBuffer::protocol_functor &pf)
{
    int cpuNum = sysconf(_SC_NPROCESSORS_CONF);//handle线程
    TC_EpollServer::BindAdapterPtr adapter = this->createBindAdapter<T>(serviceName, host, cpuNum);
    setEmptyConnTimeout(0);
    adapter->setMaxConns(1024);         //设置最大连接数
    adapter->setProtocol(pf);           //设置判断收到完整包
    adapter->enableQueueMode();
    adapter->setQueueCapacity(100000);
#if TARS_SSL
    loadTls();
    adapter->setSSLCtx(_tlsCtx);
#endif
    bind(adapter);

    adapter->getSocket().setNoCloseWait();
    adapter->getSocket().setReuseAddr();
    int idle = 60;
    adapter->getSocket().setSockOpt(TCP_KEEPIDLE, &idle, sizeof(idle), SOL_TCP);
    int interval = 5;
    adapter->getSocket().setSockOpt(TCP_KEEPINTVL, &interval, sizeof(interval), SOL_TCP);
    int cnt = 3;
    adapter->getSocket().setSockOpt(TCP_KEEPCNT, &cnt, sizeof(cnt), SOL_TCP);
    return 0;
}

gmcmServer::~gmcmServer()
{
#if TARS_SSL
    alg_tls_free((void **)&_tlsCtx.get()->ctx);
#endif

    if (redisConn::getRedisConnPool())
    {
        delete redisConn::getRedisConnPool();
    }

    if (applicationList::getAppList())
    {
        delete applicationList::getAppList();
    }
}

void gmcmServer::dealSignal(std::function<void()> porcessExit)
{
    TC_Port::registerCtrlC(porcessExit);
    TC_Port::registerTerm(porcessExit);
    TC_Port::registerSig(SIGSEGV, porcessExit);
    TC_Common::ignorePipe();
}

#if TARS_SSL
void gmcmServer::checkCertFile()
{
    TC_File::makeDirRecursive(GMCM_CA_DIR);
    if(!TC_File::isFileExist(GMCM_SIGN_KEY))
    {
        char rootCert[8192];
        char rootKeyPem[8192];
        char usrCert[8192];
        char usrKeyPem[8192];
        void *caCert = NULL;
        if(GMCM_CERT_TYPE != 0)
        {
            ECCrefPublicKey rootPub;
            ECCrefPrivateKey rootPri;
            char rootCsr[8192];
            alg_sm2_gen_key_pair(&rootPub, &rootPri);
            alg_sm2_export(&rootPub, &rootPri, rootKeyPem);
            alg_csr_gen_sm2(&rootPub, &rootPri, (char *)"/CN=gmcmCA", rootCsr);
            alg_csr_sign_cert_sm2(rootCsr, NULL, &rootPub, &rootPri, 3650, USAGE_CA, NULL, 0, rootCert);

            ECCrefPublicKey usrPub;
            ECCrefPrivateKey usrPri;
            char usrCsr[8192];
            alg_sm2_gen_key_pair(&usrPub, &usrPri);
            alg_sm2_export(&usrPub, &usrPri, usrKeyPem);
            alg_csr_gen_sm2(&usrPub, &usrPri, (char *)"/CN=gmcm server sign", usrCsr);
            alg_pem_import_cert(rootCert, &caCert);
            alg_csr_sign_cert_sm2(usrCsr, caCert, &rootPub, &rootPri, 3650, USAGE_TLS, NULL, 0, usrCert);

            ECCrefPublicKey usrPub1;
            ECCrefPrivateKey usrPri1;
            char usrCsr1[8192];
            char usrCert1[8192];
            char usrKeyPem1[8192];
            alg_sm2_gen_key_pair(&usrPub1, &usrPri1);
            alg_sm2_export(&usrPub1, &usrPri1, usrKeyPem1);
            alg_csr_gen_sm2(&usrPub1, &usrPri1, (char *)"/CN=gmcm server enc", usrCsr1);
            alg_csr_sign_cert_sm2(usrCsr1, caCert, &rootPub, &rootPri, 3650, USAGE_TLS_ENC, NULL, 0, usrCert1);

            alg_free_cert(&caCert);

            TC_File::save2file(GMCM_ENC_CERT, usrCert1);
            TC_File::save2file(GMCM_ENC_KEY, usrKeyPem1);
        }
        else
        {
            RSArefPublicKey rootPub;
            RSArefPrivateKey rootPri;
            char rootCsr[8192];
            alg_rsa_gen_key_pair(1024, 0x10001, &rootPub, &rootPri);
            alg_rsa_export(&rootPri, rootKeyPem);
            alg_csr_gen_rsa(&rootPub, &rootPri, (char *)"/CN=gmcmCA", rootCsr);
            alg_csr_sign_cert_rsa(rootCsr, NULL, &rootPub, &rootPri, 3650, USAGE_CA, NULL, 0, rootCert);

            RSArefPublicKey usrPub;
            RSArefPrivateKey usrPri;
            char usrCsr[8192];
            alg_rsa_gen_key_pair(1024, 0x010001, &usrPub, &usrPri);
            alg_rsa_export(&usrPri, usrKeyPem);
            alg_csr_gen_rsa(&usrPub, &usrPri, (char *)"/CN=gmcm server", usrCsr);
            alg_pem_import_cert(rootCert, &caCert);
            alg_csr_sign_cert_rsa(usrCsr, caCert, &rootPub, &rootPri, 3650, USAGE_TLS, NULL, 0, usrCert);
            alg_free_cert(&caCert);
            
        }
        TC_File::save2file(GMCM_CA_DIR "/ca.cer", rootCert);
        TC_File::save2file(GMCM_CA_DIR "/ca.key", rootKeyPem);
        TC_File::save2file(GMCM_SIGN_CERT, usrCert);
        TC_File::save2file(GMCM_SIGN_KEY, usrKeyPem);
    }
}

void gmcmServer::loadTls()
{
    if (GMCM_ENABLE_HTTPS)
    {
        checkCertFile();
        // string signCert = TC_File::load2str(GMCM_SIGN_CERT);
        // string signKey = TC_File::load2str(GMCM_SIGN_KEY);
        // string encCert = TC_File::load2str(GMCM_ENC_CERT);
        // string encKey = TC_File::load2str(GMCM_ENC_KEY);

        if (GMCM_CERT_TYPE == 0)
        {
            _tlsCtx = TC_OpenSSL::newCtx("", GMCM_SIGN_CERT, GMCM_SIGN_KEY, "", "",
                                         true, false, "");
            // _tlsCtx = (SSL_CTX *)alg_tls_ctx_init(0, signCert.c_str(), signKey.c_str(), NULL, NULL);
            alg_tls_ctx_add_ca_dir(_tlsCtx.get()->ctx, GMCM_CA_DIR);
        }
        else
        {
            _tlsCtx = TC_OpenSSL::newCtx("", GMCM_SIGN_CERT, GMCM_SIGN_KEY,
                                         GMCM_ENC_CERT, GMCM_ENC_KEY,
                                         false, false, "");
            // _tlsCtx = (SSL_CTX *)alg_tls_ctx_init(0, signCert.c_str(), signKey.c_str(), encCert.c_str(), encCert.c_str());
            alg_tls_ctx_add_ca_dir(_tlsCtx.get()->ctx, GMCM_CA_DIR);
        }
    }
}
#endif

int main(int argc, char const *argv[])
{
    try
    {
        globalClass<gmcmServer>::getGlobalClass();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
    return 0;
}
