#include <iostream>
#include "utilFunc.h"
#include "globalClass.h"
#include <string.h>
#include <map>
#include <vector>
#include <functional>
#include <stdlib.h>

using namespace std;

void test_vector_string();
void test_string_copy();
void test_string();
void test_static();
void test_constructor();
void test_bind();
void test_scope();
void test_vector();
void test_file();
void test_snprintf();
void test_return_str();
void test_strpp();
void test_globalClass();
void test_base64();
void test_to_string();
void test_str_append();

int main(int argc, char const *argv[])
{
    int choose;
loop:
    choose = utilTool::stdGetInt("\n0 exit\n"
                                 "1 vector str test\n"
                                 "2 str copy test\n"
                                 "3 str test\n"
                                 "4 static\n"
                                 "5 constructor\n"
                                 "6 bind\n"
                                 "7 scope\n"
                                 "8 vector\n"
                                 "9 file\n"
                                 "10 snprintf\n"
                                 "11 test return str\n"
                                 "12 test str ++\n"
                                 "13 test global class\n"
                                 "14 test base64\n"
                                 "15 test to string\n"
                                 "16 test str append\n");
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
    case 7:
        test_scope();
        break;
    case 8:
        test_vector();
        break;
    case 9:
        test_file();
        break;
    case 10:
        test_snprintf();
        break;
    case 11:
        test_return_str();
        break;
    case 12:
        test_strpp();
        break;
    case 13:
        test_globalClass();
        break;
    case 14:
        test_base64();
        break;
    case 15:
        test_to_string();
        break;
    case 16:
        test_str_append();
        break;

    default:
        exit(1);
        break;
    }
    goto loop;
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

    char *pStr = (char *)calloc(1, 8);
    string str(pStr, 8);

    printf("c   str [%p]\n", pStr);
    printf("cpp str [%p]\n", str.c_str());

}

class tString:public string
{
private:
    /* data */
public:
    // using string::string;
    tString(const char *str) : string(str)
    {
        cout << "constructor string " << str << endl;
    }
    ~tString()
    {
        cout << "destructor string " << this->c_str() << endl;
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
public:
    int32_t step;
    /* data */
    testStr1()
    {
        printf("constructor str1\n");
    }
    ~testStr1()
    {
        printf("destructor str1\n");
    }
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


    testGlobal::print();
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

class lockTest
{
private:
    /* data */
    int i;
public:
    lockTest(/* args */);
    ~lockTest();
};

lockTest::lockTest(/* args */)
{
    cout << "constructor !" << endl;
}

lockTest::~lockTest()
{
    cout << "destructor !" << endl;
}

void test_scope()
{
    cout << "scope in !" << endl;
    {
        lockTest obj;
    }
    cout << "scope exit !" << endl;
}

void test_vector()
{
    vector<lockTest> vt;
    printf("start\n");
    {
        lockTest lt;
        vt.push_back(lt);
    }
    printf("exit\n");
}

#include <sys/dir.h>
#include <sys/stat.h>
#include <error.h>
#include <stdlib.h>

void test_file()
{
    if (mkdir("test/test/", 777) < 0)
    {
        cout << "mkdir fail " << endl;
    }
    else
    {
        cout << "mkdir success." << endl;
    }
}

void test_snprintf()
{
    char buf[32];
    memset(buf, '1', sizeof(buf));
    printf("[%s]\n", buf);
    snprintf(buf, sizeof(buf), "test");
    printf("[%s]\n", buf);
}

#include <memory>

shared_ptr<tString> return_str()
{
    tString str("str1,");
    str += "str2,";
    return make_shared<tString>(str);
}

void test_return_str()
{
    // tString str = return_str();
    // printf("%s\n", str.c_str());

    printf("%s\n", return_str()->c_str());
    printf("\n\n");

    shared_ptr<tString> pStr = return_str();
    printf("%s\n", pStr->c_str());
}


void test_strpp()
{
    // tString str = "123";
    // {
    //     str = "456";
    // }
}

template <typename T>
class sigleton
{
private:

    static void atExit()
    {
        delete getInstance();
    }

public:
    static T *getInstance()
    {
        static T *_obj = NULL;
        if (!_obj)
        {
            _obj = new T;
            atexit(atExit);
        }
        return _obj;
    }
};

class testSingleton 
{
private:
    /* data */
public:
    testSingleton(/* args */)
    {
        cout << "constructor sigleton" << endl;
    }
    ~testSingleton()
    {
        cout << "destructor sigleton" << endl;
    }

    void print()
    {
        cout << "test sigleton" << endl;
    }
};

class testSingleton1
{
private:
    /* data */
public:
    testSingleton1(/* args */)
    {
        cout << "constructor sigleton 1" << endl;
    }
    ~testSingleton1()
    {
        cout << "destructor sigleton 1" << endl;
    }

    void print()
    {
        cout << "test sigleton 1" << endl;
    }
};

class testSingleton2 : public sigleton<testSingleton2>
{
private:
    /* data */
public:
    testSingleton2(/* args */)
    {
        cout << "constructor sigleton 2" << endl;
    }
    ~testSingleton2()
    {
        cout << "destructor sigleton 2" << endl;
    }

    void print()
    {
        cout << "test sigleton 2" << endl;
    }
};




void test_globalClass()
{
    sigleton<testSingleton>::getInstance()->print();
    sigleton<testSingleton1>::getInstance()->print();
    testSingleton2::getInstance()->print();
}

void test_base64()
{
    const char *b64str = "MIHGAgEBBIHArXa25AGbJQZUQdisEvLI833spQbImE/xA+Gj6jCBQ2XrDwJxxpjId6qotq0wwLzcCx5n7WL0e1SQeNz8Bh5E7qKIOxiWHBfcwf2azIr82tdci7Bl/Y5BOFdEMpxFu4257U1ZpLTFdOr5mM5Hu4fRWJOWnsAldHLDNXyb4DeSiIYL1bIAD+nxdlRN0iytaoMv6XZfJuZj7B0sJ9EBSsi7fYDP7Zv0HrmEySllnDakW91M5osp1btIENWawPPNjyOZ";
    unsigned char buf[1024] = {0};
    int len =  base64::base64Decode(b64str, strlen(b64str), buf);
    utilTool::printHex(buf, len, "base64");
}

tString return_string()
{
    return tString("123");
}

void test_to_string()
{
    printf("%s\n", return_string().c_str());
}

tString append_str_1()
{
    char str[32];
    snprintf(str, sizeof(str), "%s%s%s", "123", "456", "789");
    printf("str %p\n", str);
    return str;
}

tString append_str_2()
{
    tString str = "123";
    printf("str %p\n", str.c_str());
    str += "456";
    printf("str %p\n", str.c_str());
    str += "789";
    printf("str %p\n", str.c_str());
    return str;
}

void test_str_append()
{
    printf("str1 %p\n", append_str_1().c_str());
    printf("str2 %p\n", append_str_2().c_str());
}