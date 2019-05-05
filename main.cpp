/*************************************************************************
	> File Name: main.c
	> Author: 
	> Mail: 
	> Created Time: 2019年05月02日 星期四 21时39分55秒
 ************************************************************************/

#include <stdio.h>
#include "wpamanager.h"

#include <unistd.h>
#include <iostream>
#include <vector>

using std::vector;
using namespace std;


int main(int argc , char **argv)
{
    do
    {
        WPAManager  manager;

        cout << "start open " << endl;

        do 
        {
            cout <<"=========================="<<endl;

            list<netWorkItem>  networklist = manager.get_avail_wireless_network();

            for (list<netWorkItem>::iterator it = networklist.begin(); it != networklist.end(); it++)
            {

                cout <<"ssid "<<(*it).ssid << endl;
 /*               cout << "bssid "<< (*it).bssid << endl;
                cout << "freq "<<(*it).frequence << endl;
                cout << "signal "<< (*it).signal << endl;
                cout << "flags "<< (*it).flags << endl;
 */           }

            sleep(3);

        }
        while(0);

        cout << "start connect \n"<< endl;

        manager.connectNetwork(string("OpenWrt"), string("18181818"));

        sleep(10);
        manager.getConfiguredNetWork();

        cout << "start disconnect \n"<< endl;

        manager.disconnectNetwork();

        cout << "slee 10 second "<< endl;

        manager.getConfiguredNetWork();

        sleep(10);


    }while(1);


    return 0;

}
