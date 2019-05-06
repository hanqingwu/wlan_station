#include "wpamanager.h"
#include "wpa_ctrl.h"

#include "wpaserviceutil.h"

#include <dirent.h>


#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <string.h>

#include <errno.h>
#include <vector>


#define Debug(format, ...) do{      \
        printf(format, ##__VA_ARGS__);    \
                                        \
} while(0)

using std::vector;

WPAManager *WPAManager::_instance = NULL;

WPAManager* WPAManager::getInstance(void)
{
    if (!_instance)
        _instance = new WPAManager();

    return _instance;
}

WPAManager::WPAManager()
{
    ctrl_conn = NULL;
    ctrl_iface = NULL;
    monitor_conn = NULL;
    power_state = 1;

    monitor_thread_id = 0;
    control_thread_id = 0;

    ctrl_iface_dir = strdup("/var/run/wpa_supplicant");

    /*
    if (openCtrlConnection(ctrl_iface) < 0) {
        Debug("Failed to open control connection to "
               "wpa_supplicant.");
    }
    */
}


struct wpa_ctrl *WPAManager::get_monitor_conn()
{
    return monitor_conn;
}

int WPAManager::ping()
{
    char buf[10];
    size_t len;

    if (ctrl_conn != NULL) {
        return 0 ;
    }

    len = sizeof(buf) - 1;
    if (ctrlRequest("PING", buf, &len) < 0) {
        if (openCtrlConnection(ctrl_iface) >= 0) {
            return 0;
        }
    }

    return -1;
}

void *control_ping_process(void *arg)
{
    struct timeval  tv;
    class WPAManager *manger = (class WPAManager * )arg;
    
    while(1)
    {
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        select(0, NULL,NULL,NULL,&tv);
        manger->ping();
    }

   
    Debug("%s exit ...\n", __FUNCTION__);

    pthread_exit(NULL);

    return NULL;
}

int WPAManager::wifi_poweron(int on)
{
    if (on)
    {
        wifi_start_supplicant();

        if (openCtrlConnection("wlan0") < 0) {
            Debug("Failed to open control connection to "
                   "wpa_supplicant.");
            
            if (control_thread_id)
            {
                pthread_join(control_thread_id, NULL);
                control_thread_id = 0;
            }

             //创建monitor线程
            pthread_create(&control_thread_id, NULL, 
                              control_ping_process, (void*)this);

        }

    }
    else
    {
        if (control_thread_id)
        {
            pthread_join(control_thread_id, NULL);
            control_thread_id = 0;
        }

        wifi_stop_supplicant();

        closeWPAConnection();

    }

     power_state = on;

    return 0;
}

void *monitor_process(void *arg)
{
    fd_set rd;
    struct timeval  tv;
    int err;
    class WPAManager *manger = (class WPAManager * )arg;
    
    struct wpa_ctrl *monitor_conn = manger->get_monitor_conn();
    int fd = wpa_ctrl_get_fd(monitor_conn);

    //select 
    FD_ZERO(&rd);

    while(1)
    {
        FD_SET(fd,&rd);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        err = select(fd + 1,&rd,NULL,NULL,&tv);
        if(err == 0) //超时
        {
           // printf("select time out!\n");
            continue;
        }
        else if(err == -1)  //失败
        {
            Debug("fail to select %s!\n", strerror(errno));
            break;
        }
        else  //成功
        {
            if (FD_ISSET(fd, &rd))
            {
                manger->receiveMsgs();
            }
        }

    }

   
    Debug("%s exit ...\n", __FUNCTION__);

    pthread_exit(NULL);

}

//打开与wpa的连接
int WPAManager::openCtrlConnection(const char *ifname)
{
    char *cfile;
    int flen;

    if (ifname) {
        if (ifname != ctrl_iface) {
            free(ctrl_iface);
            ctrl_iface = strdup(ifname);
        }
    } else {
        struct dirent *dent;
        DIR *dir = opendir(ctrl_iface_dir);
        if (ctrl_iface)
            free(ctrl_iface);
        ctrl_iface = NULL;
        if (dir) {
            while ((dent = readdir(dir))) {
#ifdef _DIRENT_HAVE_D_TYPE
                /* Skip the file if it is not a socket.
                 * Also accept DT_UNKNOWN (0) in case
                 * the C library or underlying file
                 * system does not support d_type. */
                if (dent->d_type != DT_SOCK &&
                        dent->d_type != DT_UNKNOWN)
                    continue;
#endif /* _DIRENT_HAVE_D_TYPE */

                if (strcmp(dent->d_name, ".") == 0 ||
                        strcmp(dent->d_name, "..") == 0)
                    continue;
                if (strncmp(dent->d_name, "p2p",3 ) == 0)
                    continue;

                Debug("Selected interface '%s'",
                       dent->d_name);
                ctrl_iface = strdup(dent->d_name);
                break;
            }
            closedir(dir);
        }
    }

    if (ctrl_iface == NULL) {
        goto _exit_failed;
    }

    flen = strlen(ctrl_iface_dir) + strlen(ctrl_iface) + 2;
    cfile = (char *) malloc(flen);
    if (cfile == NULL) {
        goto _exit_failed;
    }
    snprintf(cfile, flen, "%s/%s", ctrl_iface_dir, ctrl_iface);

    if (ctrl_conn) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }

    if (monitor_conn) {
        wpa_ctrl_detach(monitor_conn);
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;

    }


    if (monitor_thread_id)
    {
        pthread_join(monitor_thread_id, NULL);
        monitor_thread_id = 0;
    }

    ctrl_conn = wpa_ctrl_open(cfile);
    if (ctrl_conn == NULL) {
        free(cfile);
        goto _exit_failed;
    }

    monitor_conn = wpa_ctrl_open(cfile);
    free(cfile);
    if (monitor_conn == NULL) {
        wpa_ctrl_close(ctrl_conn);
        goto _exit_failed;
    }
    if (wpa_ctrl_attach(monitor_conn)) {
        Debug("Failed to attach to wpa_supplicant");
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        goto _exit_failed;
    }


    //创建monitor线程
    pthread_create(&monitor_thread_id, NULL, 
                          monitor_process, (void*)this);
    
    return 0;

_exit_failed:
    return -1;
}

static int str_match(const char *a, const char *b)
{
    return strncmp(a, b, strlen(b)) == 0;
}

void WPAManager::processMsg(char *msg)
{
    char *pos = msg, *pos2;
    int priority = 2;

    if (*pos == '<') {
        /* skip priority */
        pos++;
        priority = atoi(pos);
        pos = strchr(pos, '>');
        if (pos)
            pos++;
        else
            pos = msg;
    }

    
    /* Update last message with truncated version of the event */
    if (strncmp(pos, "CTRL-", 5) == 0) {
        pos2 = strchr(pos, str_match(pos, WPA_CTRL_REQ) ? ':' : ' ');
        if (pos2)
            pos2++;
        else
            pos2 = pos;
    } else
        pos2 = pos;

    string lastmsg = pos2;
//    lastmsg.truncate(40);

    if (str_match(pos, WPA_EVENT_SCAN_RESULTS)) {
        updateScanResult();
    } else if (str_match(pos, CTRL_EVENT_CONNECTING)) {
 //       emit sig_eventConnecting(getConnectingSSIDFromMsg(pos));
    } else if (str_match(pos, WPA_EVENT_TEMP_DISABLED)) {
//        emit sig_eventConnectFail(getFailedSSIDFromMsg(pos));
        scan();
    } else if (str_match(pos, WPA_EVENT_CONNECTED)) {
//        emit sig_eventConnectComplete(getConnectedBSSIDFromMsg(pos));
        Debug("%s receiveMsgs CONNECTED \n", __FUNCTION__);
        get_IP_address();
        scan();
    } else if (str_match(pos, WPA_EVENT_DISCONNECTED)) {
//        emit sig_eventDisconnected(getDisconnetedBSSIDFromMsg(pos));
        scan();
    }
}

void WPAManager::receiveMsgs()
{
    char buf[256];
    size_t len;

    while (monitor_conn && wpa_ctrl_pending(monitor_conn) > 0) {
        len = sizeof(buf) - 1;
        if (wpa_ctrl_recv(monitor_conn, buf, &len) == 0) {
            buf[len] = '\0';

            Debug("%s recv %s\n", __FUNCTION__, buf);
            
            processMsg(buf);
        }
    }
}

void SplitString(const std::string& s, std::vector<std::string>& v, const char *split)
{
    std::string::size_type pos1, pos2;
    string c(split);
    pos2 = s.find(c);
    pos1 = 0;

    while(std::string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2-pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
   
    if(pos1 != s.length())
        v.push_back(s.substr(pos1));
}


list<netWorkItem>WPAManager::updateScanResult()
{
    char reply[2048];
    size_t reply_len;
    int index;
    char cmd[20];

    list<netWorkItem> netWorksList;

    index = 0;
    while (true) {
        snprintf(cmd, sizeof(cmd), "BSS %d", index++);
        if (index > 1000)
            break;

        reply_len = sizeof(reply) - 1;
        if (ctrlRequest(cmd, reply, &reply_len) < 0)
            break;

        reply[reply_len] = '\0';

        string bss(reply);
        if (bss.empty() || strncmp(bss.c_str(), "FAIL",4) == 0)
            break;

        string ssid, bssid, freq, signal, flags;
        vector<string> lines;

        SplitString(bss, lines, "\n");

        for (vector<string>::iterator it = lines.begin();it != lines.end(); it++) {
            size_t pos;

            if ((pos = (*it).find("bssid=")) != std::string::npos)
                bssid = (*it).substr(pos + strlen("bssid="));
            else if ((pos = (*it).find("freq=")) != std::string::npos)
                freq = (*it).substr(pos + strlen("freq="));
            else if ((pos = (*it).find("level=")) != std::string::npos)
                signal = (*it).substr(pos + strlen("level="));
            else if ((pos = (*it).find("flags=")) != std::string::npos)
                flags = (*it).substr(pos + strlen("flags="));
            else if ((pos = (*it).find("ssid=")) != std::string::npos)
                ssid = (*it).substr(pos +strlen("ssid="));

        }
        
        if (!ssid.empty())
        {
            netWorkItem item;
            item.ssid = ssid;
            item.bssid = bssid;
            item.frequence = freq;
            item.signal = signal;
            item.flags = flags;

//            Debug("push back ssid = %s \n", item.ssid.c_str());
            netWorksList.push_back(item);
        }

        if (bssid.empty())
            break;
    }

    //发送消息?
    //
    return netWorksList;
}

list<netWorkItem> WPAManager::get_avail_wireless_network()
{
    scan();

    return updateScanResult();
}

void WPAManager::scan()
{
    char reply[10];
    size_t reply_len = sizeof(reply);
    ctrlRequest("SCAN", reply, &reply_len);
}

int WPAManager::getLocalWifiMacInfo(string &mac)
{
    FILE *fp;
    char  lineStr[512];

    fp = popen("cat /sys/class/net/wlan0/address","r");
    if(fp != NULL)
    {
        if (fgets(lineStr,sizeof(lineStr),fp) != NULL)        
        {
            int len = strlen(lineStr);

            if (len > 0 && lineStr[len -1] == '\n')
            {
                lineStr[len-1] = '\0';
            }

//            Debug("%s get mac [%s]\n", __FUNCTION__, lineStr);
            mac = lineStr; 
        }
        pclose(fp);
        return 0;
    }

    return -1;
}

int WPAManager::setNetworkParam(int id, const char *field,
                                const char *value, bool quote)
{
    char reply[10], cmd[256];
    size_t reply_len;
    snprintf(cmd, sizeof(cmd), "SET_NETWORK %d %s %s%s%s",
             id, field, quote ? "\"" : "", value, quote ? "\"" : "");
    reply_len = sizeof(reply);
    ctrlRequest(cmd, reply, &reply_len);

    Debug("%s cmd %s, reply %s\n", __FUNCTION__, cmd, reply);

    return strncmp(reply, "OK", 2) == 0 ? 0 : -1;
}

void WPAManager::selectNetwork(const string &sel)
{
    string cmd = string("SELECT_NETWORK ") + sel;
    char reply[10];
    size_t reply_len = sizeof(reply);

    ctrlRequest(cmd.c_str(), reply, &reply_len);
    scan();
}



int WPAManager::connectNetwork(int networkId)
{
    char reply[256], cmd[256];
    size_t reply_len;
    int id = networkId;

    memset(reply, 0, sizeof(reply));
    reply_len = sizeof(reply) - 1;

    snprintf(cmd, sizeof(cmd), "ENABLE_NETWORK %d", id);
    ctrlRequest(cmd, reply, &reply_len);
    Debug("ENABLE_NETWORK %d ret %s\n", id, reply);

    return 0;
}

int WPAManager::connectNetwork(const string ssid, const string password)
{
    char reply[256], cmd[256];
    size_t reply_len;
    int id;

    memset(reply, 0, sizeof(reply));
    reply_len = sizeof(reply) - 1;

    //如果已配置，则删除
    list<netWorkItem> networklist = getConfiguredNetWork();
    for (list<netWorkItem>::iterator it = networklist.begin(); it != networklist.end(); it++)
    {
        if ( ssid.compare((*it).ssid) == 0 )
        {
            Debug("%s get same configed netowrk ssid %s\n", __FUNCTION__,ssid);
            removeNetwork((*it).networkId);
            break;
        }
    }
    

    ctrlRequest("ADD_NETWORK", reply, &reply_len);
    if (reply[0] == 'F') {
        Debug("error: failed to add network");
        return -1;
    }

    id = atoi(reply);
    Debug("ADD_NETWORK get %d\n", id);

    setNetworkParam(id, "ssid", ssid.c_str(), true);
    setNetworkParam(id, "psk", password.c_str(), true);

    selectNetwork(std::to_string(id));

    snprintf(cmd, sizeof(cmd), "ENABLE_NETWORK %d", id);
    ctrlRequest(cmd, reply, &reply_len);
    Debug("ENABLE_NETWORK %d ret %s\n", id, reply);

    memset(reply, 0, sizeof(reply));
    ctrlRequest("SAVE_CONFIG", reply, &reply_len);
    Debug("SAVE_CONFIG  ret %s\n", reply);
    return id;
}


void WPAManager::disconnectNetwork()
{
    char reply[256], cmd[256];
    size_t reply_len;
    int id;

    memset(reply, 0, sizeof(reply));
    reply_len = sizeof(reply) - 1;

    ctrlRequest("DISCONNECT", reply, &reply_len);
    Debug("%s ret %s\n", __FUNCTION__, reply);
    if (reply[0] == 'F') {
        Debug("error: failed to add network");
        return;
    }

    return;
}

int  WPAManager::removeNetwork(const string &ssid)
{
    int iRet = -1;

    list<netWorkItem> networklist = getConfiguredNetWork();
    for (list<netWorkItem>::iterator it = networklist.begin(); it != networklist.end(); it++)
    {
        if ( ssid.compare((*it).ssid) == 0 )
        {
            Debug("%s get same configed netowrk ssid %s\n", __FUNCTION__,ssid);
            removeNetwork((*it).networkId);
            iRet = 0;
            break;
        }
    }

    return iRet;
}

void WPAManager::removeNetwork(int networkId)
{
    char reply[10];
    size_t reply_len = sizeof(reply);

    string cmd = string("REMOVE_NETWORK ") + string(std::to_string(networkId));
    ctrlRequest(cmd.c_str(), reply, &reply_len);

    memset(reply, 0, sizeof(reply));
    ctrlRequest("SAVE_CONFIG", reply, &reply_len);
    scan();
}

bool WPAManager::getConnectedItem(netWorkItem *connectedItem)
{
    char buf[2048], *start, *end, *pos;
    size_t len;

    len = sizeof(buf) - 1;
    if (ctrl_conn == NULL || ctrlRequest("STATUS", buf, &len) < 0) {
        Debug("Could not get status from wpa_supplicant.");
        return false;
    }

    Debug("%s get status %s\n", __FUNCTION__, buf);

    buf[len] = '\0';
    start = buf;

    while (*start) {
        bool last = false;
        end = strchr(start, '\n');
        if (end == NULL) {
            last = true;
            end = start;
            while (end[0] && end[1])
                end++;
        }
        *end = '\0';

        pos = strchr(start, '=');
        if (pos) {
            *pos++ = '\0';
            if (strcmp(start, "bssid") == 0) {
                connectedItem->bssid = pos;
            } else if (strcmp(start, "ssid") == 0) {
                connectedItem->ssid = pos;
            } else if (strcmp(start, "wpa_state") == 0) {
                if (strcmp(pos, "COMPLETED") == 0)
                    connectedItem->state = WIFI_STATE_CONNECTED;
            }
        }

        if (last)
            break;
        start = end + 1;
    }

    if (connectedItem->state == WIFI_STATE_CONNECTED && connectedItem->ssid != "")
        return true;
    else
        return false;
}

list<netWorkItem> WPAManager::getConfiguredNetWork()
{
    char buf[4096], *start, *end, *id, *ssid, *bssid, *flags;
    size_t len;
    list<netWorkItem> list_item;
    netWorkItem connectedItem;
    bool isConnected = getConnectedItem(&connectedItem);

    if (ctrl_conn == NULL)
        return list_item;

    len = sizeof(buf) - 1;
    if (ctrlRequest("LIST_NETWORKS", buf, &len) < 0)
        return list_item;

    buf[len] = '\0';
    start = strchr(buf, '\n');
    if (start == NULL)
        return list_item;
    start++;

    while (*start) {
        bool last = false;
        end = strchr(start, '\n');
        if (end == NULL) {
            last = true;
            end = start;
            while (end[0] && end[1])
                end++;
        }
        *end = '\0';

        id = start;
        ssid = strchr(id, '\t');
        if (ssid == NULL)
            break;
        
        *ssid++ = '\0';
        bssid = strchr(ssid, '\t');
        if (bssid == NULL)
            break;

        *bssid++ = '\0';
        flags = strchr(bssid, '\t');
        if (flags == NULL)
            break;
        *flags++ = '\0';

        if (strstr(flags, "[DISABLED][P2P-PERSISTENT]")) {
            if (last)
                break;
            start = end + 1;
            continue;
        }

        netWorkItem item;
        item.ssid = ssid;
        item.bssid = bssid;
        item.networkId = atoi(id);

        if (isConnected && item.ssid == connectedItem.ssid)
            item.state = WIFI_STATE_CONNECTED;
        else if (!isConnected && strstr(flags, "[CURRENT]"))
            item.state = WIFI_STATE_CONNECTING;
        else
            item.state = WIFI_STATE_SAVED;

        list_item.push_back(item);

        if (last)
            break;

        start = end + 1;
    }

    return list_item;
}

void WPAManager::closeWPAConnection()
{
    if (monitor_conn) {
        wpa_ctrl_detach(monitor_conn);
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
    }

    if (monitor_thread_id)
    {
        pthread_join(monitor_thread_id, NULL);
        monitor_thread_id = 0;
    }
   
    if (ctrl_conn) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }

}


int WPAManager::ctrlRequest(const char *cmd, char *buf, size_t *buflen)
{
    int ret;

    if (ctrl_conn == NULL)
        return -3;
    ret = wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, buflen, NULL);
    if (ret == -2)
        Debug("'%s' command timed out.", cmd);
    else if (ret < 0)
        Debug("'%s' command failed.", cmd);

    return ret;
}

WPAManager::~WPAManager()
{
    Debug("destory WPAManager\n");

    closeWPAConnection();

    if (ctrl_iface)
        free(ctrl_iface);
    ctrl_iface = NULL;

    if (ctrl_iface_dir)
        free(ctrl_iface_dir);
    ctrl_iface_dir = NULL;
}


