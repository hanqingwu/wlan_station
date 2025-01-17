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

int status_notify(int status)
{
    cout << "!!!!!! status _notify " << status << " !!!!!!!!" <<endl;

    return 0;
}

int main(int argc , char **argv)
{

    int count = 0;

    do
    {
        WPAManager  manager;

        cout << "*********************start open count  "<<count++ <<"***********************"<< endl;

        manager.wifi_poweron(1);

        sleep(3);


        string mac;


//        cout << endl <<  "local mac info "<< mac << endl;

        manager.scan();

        sleep(5);

#if 0        
        do 
        {
//            cout <<"=========================="<<endl;

            list<netWorkItem>  networklist = manager.get_avail_wireless_network();

            for (list<netWorkItem>::iterator it = networklist.begin(); it != networklist.end(); it++)
            {

                cout <<"ssid "<<(*it).ssid << endl;
 /*               cout << "bssid "<< (*it).bssid << endl;
                cout << "freq "<<(*it).frequence << endl;
                cout << "signal "<< (*it).signal << endl;
                cout << "flags "<< (*it).flags << endl;
 */           }

         //   sleep(3);

        }
        while(0);
#endif

        cout << "start connect \n"<< endl;

        manager.set_status_callback(status_notify);

        manager.connectNetwork(string("HiWiFi_ZEASN"), string("zeasn87654321"));

        cout << "slee 15 second "<< endl;
        string strMac, strMacsk ,strGateway, strDns, strBakDns;

        manager.getMacInfo(strMac);
        cout << "get Mac "<< strMac << endl;

        manager.getMaskInfo(strMacsk);
        cout << "get mack " << strMacsk << endl;

        manager.getGateway(strGateway);
        cout << "get Gateway " << strGateway << endl;

        manager.getDns(strDns, strBakDns);
        cout << "get Dns "<< strDns << "Bak Dns "<< strBakDns << endl;
        

        sleep(15);

    netWorkItem connectedItem;
    bool isConnected = manager.getConnectedItem(&connectedItem);

        cout << "status  "<< isConnected << " ssid  "<< connectedItem.ssid <<endl;

        cout << "start disconnect "<< endl;

        manager.disconnectNetwork();

        cout << "slee 5 second "<< endl;

        manager.wifi_poweron(0);

        sleep(5);


    }while(1);


    return 0;

}
