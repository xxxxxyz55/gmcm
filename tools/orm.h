#ifndef _TOOL_ORM_H_
#define _TOOL_ORM_H_

#include <string>
#include <sstream>
#include <vector>
#include <iostream>

using namespace std;

enum orm_field_type
{
    ORM_UNDEF = 0,
    ORM_NUM,
    ORM_SERIAL,
    ORM_STRING,
    ORM_TEXT,
};

class ORMfield
{
public:
    int64_t num;
    string str;
    string name;
    uint32_t size;
    uint8_t type;
    const char *def;
    uint8_t cond;

    ORMfield(const char *field, uint8_t uType, uint32_t uSize, const char *defVal)
    {
        name = field;
        type = uType;
        if (type == ORM_STRING || type == ORM_TEXT)
        {
        }
        size = uSize;
        def = defVal;
    }
    ORMfield(){};
    ~ORMfield(){};

    string operator=(const char *sVal)
    {
        return " " + name + " = '" + sVal + "' ";
    }

    string operator=(int32_t iVal)
    {
        return " " + name + " = " + to_string(iVal) + " ";
    }

    void setVal(int32_t iVal)
    {
        if (type == ORM_NUM || type == ORM_SERIAL)
        {
            cond = 3;
            num = iVal;
        }
    }

    void setVal(string sVal)
    {
        if (type == ORM_STRING)
        {
            cond = 3;
            str = sVal;
        }
    }

    void clear()
    {
        cond = 0;
    }
};

class ORMtablePtr
{
private:
    const char *tbName;
    const char *tbKey;
    uint32_t fieldNum = 0;
    ORMfield field[128];
    friend class ORMtablePtrFunc;
};

class ORMtablePtrFunc
{
public:
    ORMfield *getField(uint32_t index)
    {
        return &((ORMtablePtr *)this)->field[index];
    }

    ORMtablePtr *getThis()
    {
        return (ORMtablePtr *)this;
    }

    void creatTb()
    {
        ostringstream sSql;
        sSql << "create table " << getThis()->tbName << "(";
        for (size_t i = 0; i < getThis()->fieldNum; i++)
        {
            sSql << getField(i)->name << " ";
            if(getField(i)->type == ORM_NUM)
            {
                sSql << "integer ";
            }
            else if(getField(i)->type == ORM_SERIAL)
            {
                sSql << "serial ";
            }
            else if(getField(i)->type == ORM_STRING)
            {
                sSql << "varchar( " << to_string(getField(i)->size) << ") ";
            }
            else if (getField(i)->type == ORM_TEXT)
            {
                sSql << "text ";
            }

            if(getField(i)->def)
            {
                sSql << "default " << getField(i)->def;
            }

            if (i != getThis()->fieldNum - 1)
            {
                sSql << ", ";
            }
        }
        
        if(getThis()->tbKey)
        {
            sSql  << "," << "primary key(" << getThis()->tbKey << ")";
        }

        sSql << ");";

        cout << "create sql [" << sSql.str() << "]" << endl;
    }

    void insert()
    {
        ostringstream sSql;
        bool startChar = false;
        sSql << "insert into " << getThis()->tbName << " (";

        for (size_t i = 0; i < getThis()->fieldNum; i++)
        {
            if(getField(i)->cond == 3)
            {
                if(startChar == true)
                {
                    sSql << ", ";
                }
                else
                {
                    startChar = true;
                }
                sSql << getField(i)->name;
            }
        }

        sSql << ") values (";
        startChar = false;
        for (size_t i = 0; i < getThis()->fieldNum; i++)
        {
            if(getField(i)->cond == 3)
            {
                if(startChar == false)
                {
                    startChar = true;
                }
                else
                {
                    sSql << ", ";
                }

                if (getField(i)->type == ORM_NUM || getField(i)->type == ORM_SERIAL)
                {
                    sSql << "'" << getField(i)->num << "'";
                }
                else
                {
                    sSql << "'" << getField(i)->str << "'";
                }
            }
        }
        cout << "insert sql [" << sSql.str() << "]." << endl;
    }


protected:
    void update_sql(string sub)
    {
        ostringstream sSql;
        bool startChar = false;
        sSql << "update " << getThis()->tbName << " set ";
        for (size_t i = 0; i < getThis()->fieldNum; i++)
        {
            if (getField(i)->cond == 3)
            {
                if (startChar == true)
                {
                    sSql << ",";
                }
                else
                {
                    startChar = true;
                }

                if(getField(i)->type == ORM_NUM || getField(i)->type == ORM_SERIAL)
                {
                    sSql << getField(i)->name << " = '" << getField(i)->num << "'";
                }
                else
                {
                    sSql << getField(i)->name << " = '" << getField(i)->str << "'";
                }
            }
        }
        sSql << " where " << sub;
        cout << "update sql [" << sSql.str() << "]." << endl;
    }

    void select_sql(string sub, vector<ORMfield *> fields)
    {
        ostringstream sSql;
        if (fields.size())
        {
            sSql << "select  " << fields[0]->name;
            for (size_t i = 1; i < fields.size(); i++)
            {
                sSql << " ," << fields[i]->name;
            }
            sSql << " from " << getThis()->tbName;
        }
        else
        {
            sSql << "select * from " << getThis()->tbName;
        }

        sSql << " where " << sub;

        cout << "select sql [" << sSql.str() << "]." << endl;
    }

    void clear_func()
    {
        for (size_t i = 0; i < getThis()->fieldNum; i++)
        {
            getField(i)->clear();
        }
    }
};

#define ORM_TABLE_BEGIN_WITH_KEY(name, desc, key) \
    class name : public ORMtablePtrFunc           \
    {                                             \
    public:                                       \
        const char *tbName = #name;               \
        const char *tbKey = key;                  \
        uint32_t fieldNum = (sizeof(name) - 24) / sizeof(ORMfield);

#define ORM_TABLE_BEGIN(name, desc)     \
    class name : public ORMtablePtrFunc \
    {                                   \
    public:                             \
        const char *tbName = #name;     \
        const char *key = NULL;         \
        uint32_t fieldNum = (sizeof(name) - 24) / sizeof(ORMfield);

#define ORM_TABLE_FIELD_ADD(field, type, size, defVal) \
    ORMfield field{#field, type, size, defVal};

#define ORM_TABLE_END(name, key)                               \
public:                                                        \
    vector<name> select(string sub, vector<ORMfield *> fields) \
    {                                                          \
        select_sql(sub, fields);                               \
        vector<name> vt;                                       \
        return vt;                                             \
    }                                                          \
    string where(string sSub)                                  \
    {                                                          \
        return sSub;                                           \
    }                                                          \
                                                               \
    void update(string sub)                                    \
    {                                                          \
        update_sql(sub);                                       \
    }                                                          \
                                                               \
    name *clear()                                              \
    {                                                          \
        clear_func();                                          \
        return this;                                           \
    }                                                          \
    }                                                          \
    ;

#endif