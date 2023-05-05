#include "orm.h"
using namespace std;

ORM_TABLE_BEGIN_WITH_KEY(person, "test", "id")
ORM_TABLE_FIELD_ADD(id, ORM_NUM, 4, NULL)
ORM_TABLE_FIELD_ADD(path, ORM_STRING, 256, NULL)
ORM_TABLE_END(person, id)

int main(int argc, char const *argv[])
{
    person obj;
    obj.creatTb();

    obj.select((obj.id = 1) + "and" + (obj.path = "test"), {&obj.path, &obj.id});
    obj.select((obj.id = 1) + "and" + (obj.path = "test"), {});

    obj.id.setVal(3);
    obj.path.setVal("test/path");
    obj.insert();

    obj.update(obj.where(obj.id = 2));
    obj.update((obj.id = 3) + "and" + (obj.path = "test update"));
    obj.clear();

    return 0;
}
