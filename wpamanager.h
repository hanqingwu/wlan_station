#ifndef WPAMANAGER_H
#define WPAMANAGER_H


#include <string>
#include <list>

#include <pthread.h>

using  std::string;
using  std::list;

#define CTRL_EVENT_CONNECTING "Trying to associate with"
enum Wifi_Security
{   
    WIFI_SECURITY_UNKNOWN = -1,
    WIFI_SECURITY_NONE = 0,
    WIFI_SECURITY_PSK,
    WIFI_SECURITY_WEP,
    WIFI_SECURITY_802DOT1X_EAP

};

enum WifiState {
    WIFI_STATE_NULL = 0,
    WIFI_STATE_SAVED,
    WIFI_STATE_AUTH_FAILED,
    WIFI_STATE_CONNECTING,
    WIFI_STATE_CONNECTED,
};


enum NetworkStatus
{
	WIFI_STATUS_DISABLED,
	WIFI_STATUS_ENABLED,
	WIFI_STATUS_CURRENT,
	WIFI_STATUS_CONNECTING,
	WIFI_STATUS_GETTING_IP,
	WIFI_STATUS_CONNECTED,
	WIFI_STATUS_DISCONNECTED,
	WIFI_STATUS_NOT_IN_RANGE,
	WIFI_STATUS_SAVED
};
struct netWorkItem
{
    string ssid;
    string bssid;
    string frequence;
    string signal;
    string flags;

    int status;
    int security;
    int level;
    int mode;
    int maxSpeed;

    int networkId = -1;
    WifiState state = WIFI_STATE_NULL;
};

class WPAManager 
{
public:
    WPAManager();
    static WPAManager* getInstance(void);
    ~WPAManager();

    //wifi模块上下电
    int wifi_poweron(int on);

    //获取当前可用wifi AP
    list<netWorkItem> get_avail_wireless_network();

    //直接返回scan_result
    list<netWorkItem> getWifiListInfo();

    //连接WIFI或断开
    int connectNetwork(const string ssid, const string password, int security = -1);
    int connectNetwork(int networkId);
    void disconnectNetwork();

    //获取网络是否已连接及连接信息
    bool getConnectedItem(netWorkItem *connectedItem);

    //获取wlan mac info
    //int getLocalWifiMacInfo(string &mac);

    //删除已配置网络
    int addNetwork(const string ssid, const string password, int security = -1);
    void removeNetwork(int networkId);
    int  removeNetwork(const string &ssid);

    //监听线程使用
    struct wpa_ctrl *get_monitor_conn();
    void receiveMsgs();

    int ping();
    int set_status_callback(int (*status_change)(int status));

    pthread_mutex_t  monitor_thread_exit_mutex;
    pthread_mutex_t  control_thread_exit_mutex;

    //扫描启动
    void scan();

    int getLocalIpInfo(std::string &strOut);
    int getMacInfo(std::string &strOut);
    int getMaskInfo(std::string &strOut);
    int getMaxSpeed();
    int getGateway(std::string &strOut);
    int getDns(std::string &strOut, std::string & strBakDns);

    int setLocalIp(std::string strIn);
    int setLocalMask(std::string strIn);
    int setLocalGateway(std::string strIn);
    int setLocalDns(std::string strIn, std::string strIn2);

    //提供给soc的回调
    int (*scanCallBack)(); 
    int (*connectCallBack)(int status);

    int setDhcpEnable(int set);
    int getDhcpEnable();

private:
    static WPAManager *_instance;

    int power_state;

    int dhcp_enable;

    //扫描结果
    list<netWorkItem> apListResult;

    pthread_mutex_t  apListResult_mutex;

    int (*status_change)(int status);

    int ctrlRequest(const char *cmd, char *buf, size_t *buflen);

    //控制socket
    struct wpa_ctrl *ctrl_conn;

    //监听回调 socket
    struct wpa_ctrl *monitor_conn;

    char *ctrl_iface;

    //wpa_supplicant 路径
    char *ctrl_iface_dir;

    //处理扫描结果
    list<netWorkItem> updateScanResult();

    //监听线程ID
    pthread_t monitor_thread_id;

    //控制接口重连线程
    pthread_t control_thread_id;

    //处理监听返回结果
    void processMsg(char *msg);
    
    
    //获取已配置的网络
    list<netWorkItem> getConfiguredNetWork();

    //选择配置网络
    void selectNetwork(const string &sel);
    
    //配置指定ID网络
    int setNetworkParam(int id, const char *field, const char *value, bool quote);

    //退出控制
    void closeWPAConnection();

    //启动控制
    int openCtrlConnection(const char *ifname);

    //
    void save_config();

};

#endif // WPAMANAGER_H
