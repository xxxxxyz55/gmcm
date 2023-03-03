#include <iostream>
#include "utilFunc.h"
#include "globalClass.h"
#include <string.h>
#include <vector>
#include <functional>

void test_vector_string();
void test_string_copy();
void test_string();
void test_static();
void test_constructor();
void test_bind();

int main(int argc, char const *argv[])
{
    int choose;
    while ((choose = utilTool::stdGetInt("\n0 exit\n"
                                         "1 vector str test\n"
                                         "2 str copy test\n"
                                         "3 str test\n"
                                         "4 static\n"
                                         "5 constructor\n"
                                         "6 bind\n")))
    {
        switch (choose)
        {
        case 1:
            test_vector_string();
            break;
        case 2:
            test_string_copy();
            break;
        case 3:
            test_string();
            break;
        case 4:
            test_static();
            break;
        case 5:
            test_constructor();
            break;
        case 6:
            test_bind();
            break;

        default:
            exit(1);
            break;
        }
    }
}

void copySting(vector<string>* vec)
{
    unsigned char ustr[64];
    unsigned int ustrLen = 32;
    memset(ustr, 0x01, ustrLen);
    vec->push_back(string((char *)ustr, ustrLen));
    memset(ustr, 0x02, ustrLen);
}

void printVecString(vector<string> vec)
{
    cout << "vector size " << vec.size() << endl;
    for (size_t i = 0; i < vec.size(); i++)
    {
        // cout << "vec " << i << " len " << vec[i].length() << " val " << vec[i].c_str() << endl;
        utilTool::printHex((unsigned char *)vec[i].c_str(), vec[i].length(), "vec");
    }
    
}

void test_vector_string()
{
    vector<string> vec;

    unsigned char ustr[64];
    unsigned int ustrLen = 32;
    memset(ustr, 0x01, ustrLen);
    vec.push_back(string((char *)ustr, ustrLen));
    printVecString(vec);
    copySting(&vec);
    printVecString(vec);
}

void test_string_copy()
{
    unsigned char data[32];
    memset(data, 0x01, 32);

    string strData((char *)data, 32);
    utilTool::printHex((unsigned char *)strData.c_str(), strData.length(), "str");
    strData[1] = 0x02;
    utilTool::printHex((unsigned char *)strData.c_str(), strData.length(), "str");
    strData += string({0x03, 0x04});
    utilTool::printHex((unsigned char *)strData.c_str(), strData.length(), "str");
}

class tString:public string
{
private:
    /* data */
public:
    // using string::string;
    tString(const char *str) : string(str)
    {
        cout << "sting" << endl;
    }
};

void test_tstring(tString str)
{
    str += "1";
    cout << str << endl;
}

void test_pstring(tString *str)
{
    *str += "1";
    cout << *str << endl;
}

void test_string()
{
    tString str = "test";
    cout << str << endl;
    test_tstring(str);
    cout << str << endl;
    test_pstring(&str);
    cout << str << endl;
}

class testStr1
{
private:
    /* data */
public:
    string str1 = "123";
};

class testStr2
{
private:
    /* data */
public:
    string str2 = "456";
};

class testStr3 : public testStr1, public testStr2
{
public:
};

class testGlobal
{
private:
    string str = "1111";
    testGlobal()
    {
        cout << "constructor testGlobal " << endl;
    }
    ~testGlobal()
    {
        cout << "destructor testGlobal " << endl;
    }
    friend class globalClass<testGlobal>;

public:
    static void init()
    {
        globalClass<testGlobal>::getGlobalClass();
    }

    static void print()
    {
        cout << globalClass<testGlobal>::getGlobalClass()->str << endl;
    }

    static void free()
    {
        globalClass<testGlobal>::getGlobalClass(false);
    }
};

void test_static()
{
    printf("addr %p\n", globalClass<testStr1>::getGlobalClass());
    printf("str %s\n", globalClass<testStr1>::getGlobalClass()->str1.c_str());

    printf("addr %p\n", globalClass<testStr2>::getGlobalClass());
    printf("str %s\n", globalClass<testStr2>::getGlobalClass()->str2.c_str());

    printf("addr %p\n", globalClass<testStr3>::getGlobalClass());
    printf("str %s\n", globalClass<testStr3>::getGlobalClass()->str1.c_str());
    printf("str %s\n", globalClass<testStr3>::getGlobalClass()->str2.c_str());

    globalClass<testStr1>::getGlobalClass(false);
    globalClass<testStr2>::getGlobalClass(false);
    globalClass<testStr3>::getGlobalClass(false);

    testGlobal::print();
    globalClass<testGlobal>::getGlobalClass(false);
}

class base
{
private:
    int val;

public:
    base(int num)
    {
        val = num;
        cout << "num = " << num << endl;
        cout << "val = " << val << endl;
        printf("val addr %p\n", &val);
    }
    int getVal()
    {
        cout << "val = " << val << endl;
        printf("val addr %p\n", &val);
        return val;
    }
    base(){};
    ~base(){};
};

class derived:public base
{
private:
    /* data */
public:

    derived();
    ~derived(){};
};

derived::derived():base(3)
{
}

void test_constructor()
{
    derived obj;
    cout << "val : " << obj.getVal() << endl;
}

class father
{
private:
    string str = "111";
public:
    void print()
    {
        cout << str << endl;
    }
};

class father2
{
private:
    string str2 = "222";

public:
};

class son : public father2, public father
{
private:
    int num;
    void test(){};
    /* data */
public:
};



void test_bind()
{
    son obj;
    std::function<void()> func = std::bind(&father::print, obj);
    func();
}