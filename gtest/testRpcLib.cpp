#include "util/tc_json.h"
#include "util/tc_uuid_generator.h"
#include <iostream>

using namespace tars;

void testJson()
{
    // {
    //     "id":1,
    //     "name":"test"
    // }
    JsonValueObjPtr pObj = new JsonValueObj();
    pObj->value["id"] = new JsonValueNum((int64_t)1);
    pObj->value["name"] = new JsonValueString("test");
    string jsonStr = TC_Json::writeValue(pObj);
    cout << "json : " << jsonStr << endl;

    JsonValueObjPtr pJson = JsonValueObjPtr::dynamicCast(TC_Json::getValue(jsonStr));
    try
    {
        cout << JsonValueNumPtr::dynamicCast(pJson->get("id"))->value << endl;
        cout << JsonValueStringPtr::dynamicCast(pJson->get("name"))->value << endl;
        cout << JsonValueStringPtr::dynamicCast(pJson->get("err"))->value << endl;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    JsonValueObjPtr p;
    printf("%ld\n", sizeof(JsonValueObjPtr));
    p = JsonValueObjPtr::dynamicCast(TC_Json::getValue(jsonStr));
    try
    {
        JsonValuePtr ptr = p->get("id");
        cout << JsonValueNumPtr::dynamicCast(ptr)->value << endl;
        cout << JsonValueNumPtr::dynamicCast(p->get("id"))->value << endl;
        cout << JsonValueStringPtr::dynamicCast(p->get("name"))->value << endl;
        cout << JsonValueStringPtr::dynamicCast(p->get("err"))->value << endl;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

void testUUid()
{
    int count = 10;
    while (count --)
    {
        cout << TC_UUIDGenerator::getInstance()->genID() << endl;
    }

    time_t tm = TNOW;
    while (tm == TNOW);
    while (tm + 1 == TNOW)
    {
        TC_UUIDGenerator::getInstance()->genID();
        count++;
    }
    cout << "uuid generate " << count << " tps" << endl;
}

int main(int argc, char const *argv[])
{
    testJson();
    // testUUid();
    return 0;
}
