#ifndef _GMCM_USER_H_
#define _GMCM_USER_H_

/*  hash
    admins      sys_user
                app_user  appName<==>userName
*/

enum user_type
{
    SYS_USER = 1,
    APP_USER = 2,
};

typedef struct userInfo_st
{
    char name[32];
    char pwd[32];
    char type;
    char appName[128];
} userInfo;

class user
{
public:
    userInfo info;
};
