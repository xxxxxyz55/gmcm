#include "pjst.h"
using namespace pjst;

PJST_FIELD_BEGIN(pkg, "pkg")
PJST_FIELD_ADD(name, PJST_STRING, 1, NULL)
PJST_FIELD_ADD(len, PJST_NUM, 1, NULL)
PJST_FIELD_END(pkg)

int main(int argc, char const *argv[])
{
    char *jreq = (char *)"{"
                         "\"name\": \"test111\", "
                         "\"len\": 123"
                         "}";
    pkg reqPtr;
    int ret = reqPtr.pointToPuffer(jreq);
    if (ret)
    {
        printf("ret = [%d] [%s]\n", ret, reqPtr.errField);
    }
    reqPtr.print();
    return 0;
}
