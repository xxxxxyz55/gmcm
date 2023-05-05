#include "pjst.h"
#include <vector>
using namespace pjst;

PJST_FIELD_BEGIN(pkg, "pkg")
PJST_FIELD_ADD_REQ(name, PJST_STRING, 1, NULL)
PJST_FIELD_ADD_REQ(len, PJST_NUM, 1, NULL)
PJST_FIELD_END(pkg)

PJST_FIELD_BEGIN(respPkg, "respPkg")
PJST_FIELD_ADD_RESP(name, 32, PJST_STRING)
PJST_FIELD_ADD_RESP(len, sizeof(double), PJST_NUM)
PJST_FIELD_END(respPkg)

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

    respPkg resp;
    resp.len.setNUM(123);
    resp.name.setStr("islam");
    resp.print();
    cout << resp.toJsonStr() << endl;
    vector<string> *p = new vector<string>({"test", "123"});
    return 0;
}

