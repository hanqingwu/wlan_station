/*************************************************************************
	> File Name: main.c
	> Author: 
	> Mail: 
	> Created Time: 2019年05月02日 星期四 21时39分55秒
 ************************************************************************/

#include<stdio.h>
#include "wpamanager.h"

int main(int argc , char **argv)
{
    WPAManager  manager;

    printf("\nstart open ...\n");

//    manager.openCtrlConnection(NULL);

    printf("start get ....\n");

    list<netWorkItem>  networklist = manager.get_avail_wireless_network();


    while(1);


    return 0;

}
