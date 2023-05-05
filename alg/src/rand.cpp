#include "./gmssl/sm3.h"
#include "./gmssl/hash_drbg.h"
#include "gmcmalgConf.h"
#include "util/tc_thread_rwlock.h"
#include "algApi.h"
#include  <math.h>
#include <sys/time.h>
#include "util/tc_cas_queue.h"
#include <unistd.h>
#include "globalClass.h"

using namespace tars;

#define BitSequence          unsigned char
int detec_longestrun(int n, unsigned char *epsilon, double * qValue1, double *qValue2, int m);
int BytesToBitSequence(unsigned char *in, int inl, BitSequence *outbuf, int bufsize);
int detec_serial(int n, unsigned char *epsilon, double * qValue1, double * qValue2, int m);

static int32_t urandom(uint8_t *buf, uint32_t len)
{
    FILE *fp;
	if (!buf) {
		return -1;
	}

    if (len > 4096)
    {
        return -1;
    }
    if (!len) {
		return 0;
	}

    if (!(fp = fopen("/dev/urandom", "rb")))
    {
        ALG_LOG_ERROR("fopen /dev/urandom fail.");
        return -1;
    }

    if (fread(buf, 1, len, fp) != len)
    {
        fclose(fp);
        ALG_LOG_ERROR("fread /dev/urandom fail len = %d.", len);
        return -1;
    }

    fclose(fp);
	return 1;
}

class Sm3Drbg
{

private:
    HASH_DRBG *pDrbg = NULL;
    uint8_t *_buffer = NULL;
    uint32_t  _length = 0;
    #define RANDOM_BUF_LEN 128*1024 //128k随机数

    void rseed()
    {
        if (pDrbg->reseed_counter > HASH_DRBG_RESEED_INTERVAL)
        {
            uint8_t entropy[16];
            uint8_t nonce[8];
            urandom(entropy, sizeof(entropy));
            urandom(nonce, sizeof(nonce));
            hash_drbg_reseed(pDrbg, entropy, sizeof(entropy), nonce, sizeof(nonce));
        }
    }

    void realRandom()
    {
        struct timeval val;
        gettimeofday(&val, 0);
        hash_drbg_generate(pDrbg, (uint8_t *)&val, sizeof(struct timeval), RANDOM_BUF_LEN, _buffer);

        rseed();

        {
            int bitLen = RANDOM_BUF_LEN * 8;
            double q;
            BitSequence *pSeq = new BitSequence[bitLen]();
            BytesToBitSequence(_buffer, RANDOM_BUF_LEN, pSeq, bitLen);
            if (!detec_longestrun(bitLen, pSeq, &q, &q, 10000) ||
                !detec_serial(bitLen, pSeq, &q, &q, 3))
            {
                // ALG_LOG_ERROR("random detec fail.");
                delete[] pSeq;
                return realRandom();
            }
            else
            {
                delete[] pSeq;
            }
        }

        _length = RANDOM_BUF_LEN;
    }


    bool copyRandom(uint8_t *buf, uint32_t len)
    {
        if (_length < len)
        {
            return false;
        }

        memcpy(buf, _buffer + RANDOM_BUF_LEN - _length, len);
        _length -= len;
        return true;
    }

public:

    Sm3Drbg()
    {
        _buffer = new uint8_t[RANDOM_BUF_LEN];
        if (pDrbg == NULL)
        {
            pDrbg = new HASH_DRBG();
            uint8_t entropy[16];
            uint8_t nonce[8];
            uint8_t personalstr[1];
            urandom(entropy, sizeof(entropy));
            urandom(nonce, sizeof(nonce));
            hash_drbg_init(pDrbg, DIGEST_sm3(), entropy, sizeof(entropy), nonce, sizeof(nonce), personalstr, 0);
            // random(nonce, sizeof(nonce));
            // drbg_add(pDrbg->V, nonce, sizeof(nonce));
        }
    }

    void randomWithoutDetec(uint8_t *buf, uint32_t len)
    {
        struct timeval val;
        gettimeofday(&val, 0);
        rseed();
        hash_drbg_generate(pDrbg, (uint8_t *)&val, sizeof(struct timeval), len, buf);
    }

    //最大128k
    void genRandom(uint8_t *buf, uint32_t len)
    {
        if (!copyRandom(buf, len))
        {
            realRandom();
            if(!copyRandom(buf, len))
            {
                ALG_LOG_ERROR("copy random fail.");
            }
        }
    }

    ~Sm3Drbg()
    {
        delete pDrbg;
    }
};

class Sm3DrbgList
{
private:
    TC_CasQueue<Sm3Drbg *> _drbgQueue;

public:
    Sm3DrbgList()
    {
        for (int i = 0; i < sysconf(_SC_NPROCESSORS_CONF); i++)
        {
            _drbgQueue.push_back(new Sm3Drbg);
        }
    }

    ~Sm3DrbgList()
    {
        Sm3Drbg *pDrbg = NULL;
        while (_drbgQueue.pop_front(pDrbg))
        {
            delete pDrbg;
        }
    }

    Sm3Drbg * getSm3Drbg()
    {
        Sm3Drbg * pDrbg = NULL;
        if (_drbgQueue.pop_front(pDrbg))
        {
            return pDrbg;
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(TRYS_SLEEP));
            return getSm3Drbg();
        }
    }

    void setSm3Drbg(Sm3Drbg * drbg)
    {
        _drbgQueue.push_front(drbg);
    }
};

int rand_bytes_with_detec(uint8_t *buf, uint32_t len)
{
    Sm3Drbg *pDrbg = globalClass<Sm3DrbgList>::getGlobalClass()->getSm3Drbg();
    if(pDrbg == NULL)
    {
        ALG_LOG_ERROR("get sm3drbg fail.");
        return -1;
    }
    else
    {
        pDrbg->genRandom(buf, len);
        globalClass<Sm3DrbgList>::getGlobalClass()->setSm3Drbg(pDrbg);
    }
    return 0;
}

void rand_bytes(uint8_t *buf, uint32_t len)
{
    static Sm3Drbg tDrbg;
    tDrbg.randomWithoutDetec(buf, len);
}

double cephes_lgam(double x);
double cephes_igam(double a, double x);
double cephes_igamc(double a, double x);
double cephes_polevl(double x, double *coef, int N);
double cephes_p1evl(double x, double *coef, int N);
double psi2(int m, int n, BitSequence *epsilon);

static const double rel_error = 1E-12;

double MACHEP = 1.11022302462515654042E-16;  // 2**-53
double MAXLOG = 7.09782712893383996732224E2; // log(MAXNUM)
double MAXNUM = 1.7976931348623158E308;      // 2**1024*(1-MACHEP)
double PI = 3.14159265358979323846;          // pi, duh!

static double big = 4.503599627370496e15;
static double biginv =  2.22044604925031308085e-16;

unsigned char   *rand_bits[100];
unsigned int    loop;
unsigned char   *bits_temp;

int sgngam = 0;
/* A[]: Stirling's formula expansion of log gamma
 * B[], C[]: log gamma function between 2 and 3
 */
static unsigned short A[] = {
    0x6661, 0x2733, 0x9850, 0x3f4a,
    0xe943, 0xb580, 0x7fbd, 0xbf43,
    0x5ebb, 0x20dc, 0x019f, 0x3f4a,
    0xa5a1, 0x16b0, 0xc16c, 0xbf66,
    0x554b, 0x5555, 0x5555, 0x3fb5};
static unsigned short B[] = {
    0x6761, 0x8ff3, 0x8901, 0xc095,
    0xb93e, 0x355b, 0xf234, 0xc0e2,
    0x89e5, 0xf890, 0x3d73, 0xc114,
    0xdb51, 0xf994, 0xbc82, 0xc131,
    0xf20b, 0x0219, 0x4589, 0xc13a,
    0x055e, 0x5418, 0x0c67, 0xc12a};
static unsigned short C[] = {
    /*0x0000,0x0000,0x0000,0x3ff0,*/
    0x12b2, 0x1cf3, 0xfd0d, 0xc075,
    0xd757, 0x7b89, 0xaa0d, 0xc0d0,
    0x4c9b, 0xb974, 0xeb84, 0xc10a,
    0x0043, 0x7195, 0x6286, 0xc131,
    0xf34c, 0x892f, 0x5255, 0xc143,
    0xe14a, 0x6a11, 0xce4b, 0xc13e};

#define MAXLGM 2.556348e305

#define STIN static
#define MAX(x,y)             ((x) <  (y)  ? (y)  : (x))
#define MIN(x,y)             ((x) >  (y)  ? (y)  : (x))
#define ALPHA                0.01 /* SIGNIFICANCE LEVEL */
#define isNegative(x)        ((x) <  0.e0 ?   1 : 0)
#define isGreaterThanOne(x)  ((x) >  1.e0 ?   1 : 0)
#define isZero(x)            ((x) == 0.e0 ?   1 : 0)


/* Logarithm of gamma function */
double cephes_lgam(double x)
{
    double p, q, u, w, z;
    int i;

    sgngam = 1;

    if (x < -34.0)
    {
        q = -x;
        w = cephes_lgam(q); /* note this modifies sgngam! */
        p = floor(q);
        if (p == q)
        {
        lgsing:
            goto loverf;
        }
        i = (int)p;
        if ((i & 1) == 0)
            sgngam = -1;
        else
            sgngam = 1;
        z = q - p;
        if (z > 0.5)
        {
            p += 1.0;
            z = p - q;
        }
        z = q * sin(PI * z);
        if (z == 0.0)
            goto lgsing;
        /*      z = log(PI) - log( z ) - w;*/
        z = log(PI) - log(z) - w;
        return z;
    }

    if (x < 13.0)
    {
        z = 1.0;
        p = 0.0;
        u = x;
        while (u >= 3.0)
        {
            p -= 1.0;
            u = x + p;
            z *= u;
        }
        while (u < 2.0)
        {
            if (u == 0.0)
                goto lgsing;
            z /= u;
            p += 1.0;
            u = x + p;
        }
        if (z < 0.0)
        {
            sgngam = -1;
            z = -z;
        }
        else
            sgngam = 1;
        if (u == 2.0)
            return (log(z));
        p -= 2.0;
        x = x + p;
        p = x * cephes_polevl(x, (double *)B, 5) / cephes_p1evl(x, (double *)C, 6);

        return log(z) + p;
    }

    if (x > MAXLGM)
    {
    loverf:
        printf("lgam: OVERFLOW\n");

        return sgngam * MAXNUM;
    }

    q = (x - 0.5) * log(x) - x + log(sqrt(2 * PI));
    if (x > 1.0e8)
        return q;

    p = 1.0 / (x * x);
    if (x >= 1000.0)
        q += ((7.9365079365079365079365e-4 * p - 2.7777777777777777777778e-3) * p + 0.0833333333333333333333) / x;
    else
        q += cephes_polevl(p, (double *)A, 4) / x;

    return q;
}

double cephes_igam(double a, double x)
{
    double ans, ax, c, r;

    if ((x <= 0) || (a <= 0))
        return 0.0;

    if ((x > 1.0) && (x > a))
        return 1.e0 - cephes_igamc(a, x);

    /* Compute  x**a * exp(-x) / gamma(a)  */
    ax = a * log(x) - x - cephes_lgam(a);
    if (ax < -MAXLOG)
    {
        printf("igam: UNDERFLOW\n");
        return 0.0;
    }
    ax = exp(ax);

    /* power series */
    r = a;
    c = 1.0;
    ans = 1.0;

    do
    {
        r += 1.0;
        c *= x / r;
        ans += c;
    } while (c / ans > MACHEP);

    return ans * ax / a;
}

double cephes_igamc(double a, double x)
{
    double ans, ax, c, yc, r, t, y, z;
    double pk, pkm1, pkm2, qk, qkm1, qkm2;

    if ((x <= 0) || (a <= 0))
        return (1.0);

    if ((x < 1.0) || (x < a))
        return (1.e0 - cephes_igam(a, x));

    ax = a * log(x) - x - cephes_lgam(a);

    if (ax < -MAXLOG)
    {
        printf("igamc: UNDERFLOW\n");
        return 0.0;
    }
    ax = exp(ax);

    /* continued fraction */
    y = 1.0 - a;
    z = x + y + 1.0;
    c = 0.0;
    pkm2 = 1.0;
    qkm2 = x;
    pkm1 = x + 1.0;
    qkm1 = z * x;
    ans = pkm1 / qkm1;

    do
    {
        c += 1.0;
        y += 1.0;
        z += 2.0;
        yc = y * c;
        pk = pkm1 * z - pkm2 * yc;
        qk = qkm1 * z - qkm2 * yc;
        if (qk != 0)
        {
            r = pk / qk;
            t = fabs((ans - r) / r);
            ans = r;
        }
        else
            t = 1.0;
        pkm2 = pkm1;
        pkm1 = pk;
        qkm2 = qkm1;
        qkm1 = qk;
        if (fabs(pk) > big)
        {
            pkm2 *= biginv;
            pkm1 *= biginv;
            qkm2 *= biginv;
            qkm1 *= biginv;
        }
    } while (t > MACHEP);

    return ans * ax;
}

//块内最大游程 1
int detec_longestrunone(int n, unsigned char *epsilon, double * qValue, int m)
{
    double pval, chi2, pi[7];
    int run, v_n_obs, N, i, j, K, M, V[7];
    unsigned int nu[7] = {0, 0, 0, 0, 0, 0, 0};

    if (n < 128)
    {
        return 0;
    }
    if (n < 6272)
    {
        K = 3;
        M = 8;
        V[0] = 1;
        V[1] = 2;
        V[2] = 3;
        V[3] = 4;
        pi[0] = 0.2148;
        pi[1] = 0.3672;
        pi[2] = 0.2305;
        pi[3] = 0.1875;
    }
    else if (n < 750000)
    {
        K = 5;
        M = 128;
        V[0] = 4;
        V[1] = 5;
        V[2] = 6;
        V[3] = 7;
        V[4] = 8;
        V[5] = 9;
        pi[0] = 0.1174;
        pi[1] = 0.2430;
        pi[2] = 0.2494;
        pi[3] = 0.1752;
        pi[4] = 0.1027;
        pi[5] = 0.1124;
    }
    else
    {
        K = 6;
        M = 10000;
        V[0] = 10;
        V[1] = 11;
        V[2] = 12;
        V[3] = 13;
        V[4] = 14;
        V[5] = 15;
        V[6] = 16;
        pi[0] = 0.086632;
        pi[1] = 0.208201;
        pi[2] = 0.248419;
        pi[3] = 0.193913;
        pi[4] = 0.121458;
        pi[5] = 0.068011;
        pi[6] = 0.073366;
    }

    N = n / M;
    for (i = 0; i < N; i++)
    {
        v_n_obs = 0;
        run = 0;
        for (j = 0; j < M; j++)
        {
            if (epsilon[i * M + j] == 1)
            {
                run++;
                if (run > v_n_obs)
                    v_n_obs = run;
            }
            else
            {
                run = 0;
            }
        }
        if (v_n_obs < V[0])
            nu[0]++;
        for (j = 0; j <= K; j++)
        {
            if (v_n_obs == V[j])
                nu[j]++;
        }
        if (v_n_obs > V[K])
            nu[K]++;
    }

    chi2 = 0.0;
    for (i = 0; i <= K; i++)
        chi2 += ((nu[i] - N * pi[i]) * (nu[i] - N * pi[i])) / (N * pi[i]);

    pval = cephes_igamc((double)(K / 2.0), chi2 / 2.0);
    *qValue = pval;
    // RAND_DEGUG(pval, *qValue);
    if (isNegative(pval) || isGreaterThanOne(pval))
    {
        return 0;
    }

    if (pval < ALPHA)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

//块内最大游程 0
int detec_longestrunzero(int n, unsigned char *epsilon, double * qValue, int m)
{
    double pval, chi2, pi[7];
    int run, v_n_obs, N, i, j, K, M, V[7];
    unsigned int nu[7] = {0, 0, 0, 0, 0, 0, 0};

    if (n < 128)
    {
        return 0;
    }
    if (n < 6272)
    {
        K = 3;
        M = 8;
        V[0] = 1;
        V[1] = 2;
        V[2] = 3;
        V[3] = 4;
        pi[0] = 0.2148;
        pi[1] = 0.3672;
        pi[2] = 0.2305;
        pi[3] = 0.1875;
    }
    else if (n < 750000)
    {
        K = 5;
        M = 128;
        V[0] = 4;
        V[1] = 5;
        V[2] = 6;
        V[3] = 7;
        V[4] = 8;
        V[5] = 9;
        pi[0] = 0.1174;
        pi[1] = 0.2430;
        pi[2] = 0.2494;
        pi[3] = 0.1752;
        pi[4] = 0.1027;
        pi[5] = 0.1124;
    }
    else
    {
        K = 6;
        M = 10000;
        V[0] = 10;
        V[1] = 11;
        V[2] = 12;
        V[3] = 13;
        V[4] = 14;
        V[5] = 15;
        V[6] = 16;
        pi[0] = 0.086632;
        pi[1] = 0.208201;
        pi[2] = 0.248419;
        pi[3] = 0.193913;
        pi[4] = 0.121458;
        pi[5] = 0.068011;
        pi[6] = 0.073366;
    }

    N = n / M;
    for (i = 0; i < N; i++)
    {
        v_n_obs = 0;
        run = 0;
        for (j = 0; j < M; j++)
        {
            if (epsilon[i * M + j] == 0)
            {
                run++;
                if (run > v_n_obs)
                    v_n_obs = run;
            }
            else
            {
                run = 0;
            }
        }
        if (v_n_obs < V[0])
            nu[0]++;
        for (j = 0; j <= K; j++)
        {
            if (v_n_obs == V[j])
                nu[j]++;
        }
        if (v_n_obs > V[K])
            nu[K]++;
    }

    chi2 = 0.0;
    for (i = 0; i <= K; i++)
        chi2 += ((nu[i] - N * pi[i]) * (nu[i] - N * pi[i])) / (N * pi[i]);

    pval = cephes_igamc((double)(K / 2.0), chi2 / 2.0);
    *qValue = pval;
    // RAND_DEGUG(pval, *qValue);
    if (isNegative(pval) || isGreaterThanOne(pval))
    {
        return 0;
    }

    if (pval < ALPHA)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int detec_longestrun(int n, unsigned char *epsilon, double * qValue1, double *qValue2, int m)
{
    if (detec_longestrunone(n, epsilon, qValue1, m) &&
        detec_longestrunzero(n, epsilon, qValue2, m))
    {
        return 1;//成功
    }
    else
    {
        return 0;
    }
}

double psi2(int m, int n, BitSequence *epsilon)
{
    int i, j, k, powLen;
    double sum, numOfBlocks;
    unsigned int *P;

    if ((m == 0) || (m == -1))
        return 0.0;
    numOfBlocks = n;
    powLen = (int)pow(2, m + 1) - 1;
    if ((P = (unsigned int *)calloc(powLen, sizeof(unsigned int))) == NULL)
    {
        return 0.0;
    }
    for (i = 1; i < powLen - 1; i++)
        P[i] = 0; /* INITIALIZE NODES */
    for (i = 0; i < numOfBlocks; i++)
    { /* COMPUTE FREQUENCY */
        k = 1;
        for (j = 0; j < m; j++)
        {
            if (epsilon[(i + j) % n] == 0)
                k *= 2;
            else if (epsilon[(i + j) % n] == 1)
                k = 2 * k + 1;
        }
        P[k - 1]++;
    }
    sum = 0.0;
    for (i = (int)pow(2, m) - 1; i < (int)pow(2, m + 1) - 1; i++)
        sum += pow(P[i], 2);
    sum = (sum * pow(2, m) / (double)n) - (double)n;
    free(P);

    return sum;
}

int detec_serial(int n, unsigned char *epsilon, double * qValue1, double * qValue2, int m)
{
    double p_value1, p_value2, psim0, psim1, psim2, del1, del2;

    psim0 = psi2(m, n, epsilon);
    psim1 = psi2(m - 1, n, epsilon);
    psim2 = psi2(m - 2, n, epsilon);
    del1 = psim0 - psim1;
    del2 = psim0 - 2.0 * psim1 + psim2;
    p_value1 = cephes_igamc(pow(2, m - 1) / 2, del1 / 2.0);
    p_value2 = cephes_igamc(pow(2, m - 2) / 2, del2 / 2.0);
    *qValue1 = p_value1;
    *qValue2 = p_value2;

    if (p_value1 < ALPHA || p_value2 < ALPHA)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

double cephes_polevl(double x, double *coef, int N)
{
    double ans;
    int i;
    double *p;

    p = coef;
    ans = *p++;
    i = N;

    do
        ans = ans * x + *p++;
    while (--i);

    return ans;
}

double cephes_p1evl(double x, double *coef, int N)
{
    double ans;
    double *p;
    int i;

    p = coef;
    ans = x + *p++;
    i = N - 1;

    do
        ans = ans * x + *p++;
    while (--i);

    return ans;
}

static unsigned char _compute(unsigned char b, unsigned char factor)
{
    if ((factor & b) == factor) {
        return 0x01;
    } else {
        return 0x00;
    }
}

int BytesToBitSequence(unsigned char *in, int inl, BitSequence *outbuf, int bufsize)
{
    int j = 0, i = 0;
    if (bufsize < inl * 8) {
        return 0;
    }

    for (i = 0; i < inl; ++i) {
        j = i * 8;
        outbuf[j] = (BitSequence) (_compute(in[i], 0x80));
        outbuf[j + 1] = (BitSequence) (_compute(in[i], 0x40));
        outbuf[j + 2] = (BitSequence) (_compute(in[i], 0x20));
        outbuf[j + 3] = (BitSequence) (_compute(in[i], 0x10));
        outbuf[j + 4] = (BitSequence) (_compute(in[i], 0x08));
        outbuf[j + 5] = (BitSequence) (_compute(in[i], 0x04));
        outbuf[j + 6] = (BitSequence) (_compute(in[i], 0x02));
        outbuf[j + 7] = (BitSequence) (_compute(in[i], 0x01));
    }

    return 1;
}