#include <iostream>

using namespace std;

class base
{
private:
    int val = 0;

public:
    base(/* args */)
    {
        printf("create base\n");
    }

    base &operator=(base str)
    {
        printf("base =\n");
        this->val = str.val;
        return *this;
    }

    ~base()
    {
        printf("destory base\n");
    }
};

class object
{
private:
    base val;

public:
    object(/* args */)
    {
        printf("obj create\n");
    }

    object(base str):val(str)
    {
        printf("obj create from str\n");
    }

    object& operator=(object obj)
    {
        printf("copy init obj\n");
        this->val = obj.val;
        return *this;
    }

    ~object()
    {
        printf("obj destroy\n");
    }
};

string return_str(const char *str)
{
    string var = str;
    return var;
}

int main(int argc, char const *argv[])
{
    printf("obj 1 >>>\n");
    base val;
    object obj1(val);
    printf("obj 2 >>>\n");
    object obj2;
    obj2 = val;
    printf("obj 3 >>>\n");
    object obj3 = val;
    printf("\n=======\n");
    return 0;
}
