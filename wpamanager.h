#ifndef WPAMANAGER_H
#define WPAMANAGER_H


#include <string>
#include <list>

#include <pthread.h>

using  std::string;
using  std::list;

#define CTRL_EVENT_CONNECTING "Trying to associate with"

enum WifiState {
    WIFI_STATE_NULL = 0,
    WIFI_STATE_SAVED,
    WIFI_STATE_AUTH_FAILED,
    WIFI_STATE_CONNECTING,
    WIFI_STATE_CONNECTED,
};

struct netWorkItem
{
    string ssid;
    string bssid;
    string frequence;
    string signal;
    string flags;
    int networkId = -1;
    WifiState state = WIFI_STATE_NULL;
};

class WPAManager 
{
public:
    WPAManager();
    static WPAManager* getInstance(void);
    ~WPAManager();

    //获取当前可用wifi AP
    list<netWorkItem> get_avail_wireless_network();

    //连接WIFI或断开
    void connectNetwork(const string &ssid, const string &password);
    void disconnectNetwork();
    
    int openCtrlConnection(const char *ifname);

    //获取配置的网络
    list<netWorkItem> getConfiguredNetWork();

    //获取网络是否已连接
    bool getConnectedItem(netWorkItem *connectedItem);

    //删除已配置网络
    void removeNetwork(int networkId);

    struct wpa_ctrl *get_monitor_conn();


    void receiveMsgs();

private:
    static WPAManager *_instance;

    int ctrlRequest(const char *cmd, char *buf, size_t *buflen);

    //控制socket
    struct wpa_ctrl *ctrl_conn;

    //监听回调 socket
    struct wpa_ctrl *monitor_conn;

    char *ctrl_iface;

    //wpa_supplicant 路径
    char *ctrl_iface_dir;

    list<netWorkItem> updateScanResult();

    pthread_t monitor_thread_id;

    void processMsg(char *msg);
    
    void scan();
    void selectNetwork(const string &sel);
    int setNetworkParam(int id, const char *field, const char *value, bool quote);
    void closeWPAConnection();

};

#endif // WPAMANAGER_H
