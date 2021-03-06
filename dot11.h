#include <stdint.h>
#include <string>
#include <cstring>

#define BEACON_TYPE 0X80
#define DATA_TYPE 0X08
#define QOS_DATA_TYPE 0X88

struct RadiotapHdr{ // 4 bytes
    uint8_t revision;
    uint8_t pad;
    uint16_t len;   // radiotap total size
    // uint32_t present;
    // 다른 데이터 존재

    uint8_t getPresentSize(){
        uint8_t count = 0;
        uint32_t present;
        while (true) {
            memcpy(&present, (char*)this+sizeof(RadiotapHdr)+(count*sizeof(present)), sizeof(present));
            count++;
            if((present >> 31) == 0)    //31bit 1이면 32bit present 더 존재 -> 31bit 0일때까지 present 존재
                break;
        }
        return count*sizeof(present);
    }
};

struct RadiotapFixedData{
    uint8_t flag;
    uint8_t dataRate;
    uint16_t chFreq;
    uint16_t chFlag;
    int8_t signal;
    uint16_t signalQ;
    // 다른 데이터 존재
};

struct Mac{
    uint8_t mac[6];

    bool operator < (const Mac& r) const { return memcmp(mac, r.mac, 6) < 0; }

    std::string getMAC(){
        char buf[20]; // enough size
        sprintf(buf, "%02x:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    };
};

struct BeaconHdr{   // 24 bytes
    uint8_t type;   // beacon(0x80), data(0x08), QoS data(0x88)
    uint8_t flag;
    uint16_t duration;
    Mac dmac;  // 6 bytes   // data : dmac | QoS : bssid(reciever)
    Mac smac;               // data : bssid(trasnmitter) | QoS : smac(trasnmitter)
    Mac bssid;              // data : smac | QoS : dmac
    uint16_t seqControl;
};

struct BeaconFixedData{  // 12 bytes + 4 bytes
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capacity;
    uint32_t reserved;
};

struct TagParm{
    uint8_t tag;    // ssid == 0x00
    uint8_t len;

    void* value(){
        return (char*)this+sizeof(TagParm);
    }

    TagParm* next(){
        char* res = (char*)this;
        res += sizeof(TagParm)+this->len;
        return (TagParm*) res;
    }
};
