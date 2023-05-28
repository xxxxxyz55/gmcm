#include "algApi.h"
#include "gtest.h"

void perf_random();
void gen_128m();

int main(int argc, char const *argv[])
{
    /* code */
    Gtest test;
    test.pushTest(perf_random, "perf random");
    test.pushTest(gen_128m, "gen 128m random");
    return 0;
}

class RandomLoop: public GtestLoop
{
private:
    int run(size_t id)
    {
        rand_bytes_with_detec(buf, len);
        return 0;
    }

public:
    uint8_t buf[8192];
    uint32_t len = 8192;
};

void perf_random()
{
    RandomLoop loop;
    loop.setThreadNum(8);
    loop.setDataLength(loop.len);
    loop.loopFor();
}

#include <stdio.h>
void gen_128m()
{
    FILE *fp = fopen("./random.bin", "w");
    uint32_t randLen = 128*1024*1024;
    uint32_t pad = 8192;
    uint8_t buf[8192];

    for (size_t i = 0; i < randLen / pad; i++)
    {
        rand_bytes_with_detec(buf, pad);
        if (fwrite(buf, 1, pad, fp) != pad)
        {
            printf("fwrite fail\n");
            break;
        }
    }
    fclose(fp);
}
