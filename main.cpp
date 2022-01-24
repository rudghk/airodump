#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include "dot11.h"
#include <map>
#include <iostream>

void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

struct BSSIDInfo{
    Mac bssid;
    int8_t pwr;   // 범위 : 0 ~ -128
    uint16_t beacons;
    uint16_t data;  // (QoS) data frame 개수
    uint16_t ch;
//    uint8_t enc;
    char essid[50];

    void set(Mac bid, int8_t power, uint16_t nBeacons, uint16_t nData, uint16_t channel){
        this->bssid = bid;
        this->pwr = power;
        this->beacons = nBeacons;
        this->data = nData;
        this->ch = channel;
    }

    void print(){
        std::cout << bssid.getMAC() +"\t";
        printf("%d\t", pwr);
        printf("%u\t", beacons);
        printf("%u\t", data);
        printf("%u\t", convertCh());
//        printf("%u\t", enc);
        printf("%s\n", essid);
    }

    uint8_t convertCh(){
        uint8_t channel = (uint8_t)((ch - 2400) / 5) - 1;
        if(channel > 14)
            channel = 14;
        return channel;
    }
};

// 화면 갱신
void render(std::map<Mac, BSSIDInfo> infoMap){
    system("clear");
    printf("BSSID\t\t\tPWR\tBeacons\t#Data\tCH\tESSID\n");
    for (std::map<Mac, BSSIDInfo>::iterator itr = infoMap.begin(); itr != infoMap.end(); ++itr) {
            itr->second.print();
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    std::map<Mac, BSSIDInfo> infoMap;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        bool changed = false;       // Render flag

        // Get radiotap len
        struct RadiotapHdr* radiotapHdr = (struct RadiotapHdr*)packet;
        // Get channel and power
        uint8_t presentSize = radiotapHdr->getPresentSize();
        struct RadiotapFixedData* radiotapData = (struct RadiotapFixedData*)&packet[sizeof(RadiotapHdr)+presentSize];
        // Get frame type and BSSID
        struct BeaconHdr* beaconHdr = (struct BeaconHdr*)&packet[radiotapHdr->len];
        // beacon frame인 경우
        if(beaconHdr->type == BEACON_TYPE){
            auto info = infoMap.find(beaconHdr->bssid);
            if(info != infoMap.end()){  // 이미 알고 있는 bssid인 경우
                info->second.set(beaconHdr->bssid, radiotapData->signal, info->second.beacons+1, info->second.data, radiotapData->chFreq);
            }
            else{
                BSSIDInfo bssidInfo;
                bssidInfo.set(beaconHdr->bssid, radiotapData->signal, 1, 0, radiotapData->chFreq);
                // Get ESSID
                struct TagParm* tagParm = (struct TagParm*)&packet[(radiotapHdr->len)+sizeof(BeaconHdr)+12]; // beacon fixed parm 12 bytes
                while(tagParm->tag != 0x0){    // SSID(0x0)
                    tagParm = tagParm->next();
                }
                memset(bssidInfo.essid, 0, sizeof(bssidInfo.essid));
                memcpy(&bssidInfo.essid, tagParm->value(), tagParm->len);
                bssidInfo.essid[tagParm->len+1] = '\0';
                infoMap.insert({bssidInfo.bssid, bssidInfo});
            }
            changed = true;
        }
        else if(beaconHdr->type == DATA_TYPE || beaconHdr->type == QOS_DATA_TYPE){  // Get #Data
            Mac targetBSSID;
            if(beaconHdr->type == DATA_TYPE)
                targetBSSID = beaconHdr->smac;  // data frame인 경우 smac 위치가 bssid
            else
                targetBSSID = beaconHdr->dmac;  // QoS data frame인 경우 dmac 위치가 bssid
            auto info = infoMap.find(targetBSSID);
            if(info != infoMap.end()){  // 이미 알고 있는 bssid인 경우
                info->second.set(beaconHdr->bssid, radiotapData->signal, info->second.beacons, info->second.data+1, radiotapData->chFreq);
            }
            changed = true;
        }

        if(changed)
            render(infoMap);
    }
    pcap_close(pcap);
}
