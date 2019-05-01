#ifndef WPAMANAGER_H
#define WPAMANAGER_H


#include <string>

#include <pthread.h>


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
    String frequence;
    String signal;
    String flags;
    int networkId = -1;
    WifiState state = WIFI_STATE_NULL;
};

class WPAManager 
{
public:
    static WPAManager* getInstance(void);
    ~WPAManager();

    int ctrlRequest(const char *cmd, char *buf, size_t *buflen);

    List<netWorkItem> get_avail_wireless_network();

    void connectNetwork(const String &ssid, const String &password);
    void disconnectNetwork();
    
    int openCtrlConnection(const char *ifname);

    List<netWorkItem> getConfiguredNetWork();
    bool getConnectedItem(netWorkItem *connectedItem);


private:
    static WPAManager *_instance;
    WPAManager();

    //控制socket
    struct wpa_ctrl *ctrl_conn;

    //监听回调 socket
    struct wpa_ctrl *monitor_conn;

    char *ctrl_iface;

    //wpa_supplicant 路径
    char *ctrl_iface_dir;

    void updateScanResult();

    pthread_t monitor_thread_id;


    static void *monitor_process(void *arg);
    static void WPAManager::receiveMsgs();


    phread_mutex_t  thread_exit_mutex;
};

#endif // WPAMANAGER_H
