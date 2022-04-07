#include <stdio.h>
#include <stdint-gcc.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>
#include "checksum.h"
uint16_t readEthernetHeader(uint8_t *data){
    printf("\n\tEthernet Header\n\t\tDest MAC: ");
    printf("%x",data[0]);
    for(int i =1; i<6;i++){
        printf(":%x",data[i]);
    }
    printf("\n\t\tSource MAC: ");
    printf("%x",data[6]);
    for(int i =7; i<12;i++){
        printf(":%x",data[i]);
    }
    printf("\n\t\t");

    if((data[12] == 0x08) & (data[13] == 0x00)) {
        printf("Type: IP\n");
        return (uint16_t) 0x0800;
    }

    if((data[12] == 0x08) & (data[13] == 0x06)) {
        printf("Type: ARP\n");
        return (uint16_t) 0x0806;
    }


    printf("Type: Unknown\n");
    return (uint16_t) 0;


}

void readArpHeader(uint8_t *data){
    printf("\n\tARP header\n\t\tOpcode: ");
    printf("%s\n", (data[21] == 0x01) ? "Request":"Reply");

    printf("\t\tSender MAC: ");
    printf("%x",data[22]);
    for(int i =23; i<28;i++){
        printf(":%x",data[i]);
    }

    printf("\n\t\tSender IP: ");
    printf("%d",data[28]);
    for(int i =29; i<32;i++){
        printf(".%d",data[i]);
    }

    printf("\n\t\tTarget MAC: ");
    printf("%x",data[32]);
    for(int i =33; i<38;i++){
        printf(":%x",data[i]);
    }

    printf("\n\t\tTarget IP: ");
    printf("%d",data[38]);
    for(int i =39; i<42;i++){
        printf(".%d",data[i]);
    }

    printf("\n");


}

void readIPHeader(uint8_t *data){
    uint16_t PDUlength;
    memcpy(&PDUlength, &data[16], 2);
    PDUlength = ntohs(PDUlength);
    printf("\n\tIP Header\n\t\tHeader Len: %d (bytes)", 4*(data[14]%16));


    printf("\n\t\tTOS: 0x%x", data[15]);
    printf("\n\t\tTTL: %d", data[22]);
    printf("\n\t\tIP PDU Len: %d (bytes)", PDUlength);
    printf("\n\t\tProtocol: ");
    uint8_t protocol = data[23];
    if(protocol == 1){
        printf("ICMP");
    } else
    if(protocol == 6){
        printf("TCP");
    } else
    if(protocol == 16){
        printf("UDP");
    }else
        printf("Unknown");

    uint16_t chkSm;
    memcpy(&chkSm, &data[24], 2);
    //chkSm = ntohs(chkSm);

    printf("\n\t\tChecksum: %s (0x%x)", (in_cksum((unsigned short *) (data + 14), 4*(data[14]%16)) == 0) ? "Correct":"Incorrect", chkSm);

    printf("\n\t\tSender IP: ");
    printf("%d",data[26]);
    for(int i =27; i<30;i++){
        printf(".%d",data[i]);
    }
    printf("\n\t\tDest IP: ");
    printf("%d",data[30]);
    for(int i =31; i<34;i++){
        printf(".%d",data[i]);
    }
    printf("\n");
}


int main(){



//    char pcapError[PCAP_ERRBUF_SIZE];
//    pcap_t *capture = pcap_open_offline("PingTest.pcap", pcapError);
//    pcap_loop(capture, 0, )





FILE* ptr;
char ch;

    ptr = fopen("PingTest.pcap", "rb");

    if(NULL == ptr){
        printf("File Does Not Exist. Exiting..\n");
        return 0;
    }

    fseek(ptr, 0, SEEK_END); // seek to end of file
    int size = ftell(ptr) - 24; // get current file pointer
    fseek(ptr, 0, SEEK_SET); // seek back to beginning of file

    printf("\n");

    int packetIndex = 1;
    uint8_t FileHeader[24];
    fread(FileHeader, 24, 1, ptr);

    while(size > 16){
        uint8_t PacketRecord[16];
        fread(PacketRecord, 16, 1, ptr);
        uint8_t dataLen = PacketRecord[8];
        uint8_t *data = malloc(dataLen);
        printf("Packet number: %d  Frame Len: %d\n", packetIndex, dataLen);
        fread(data, dataLen, 1, ptr);
        uint16_t type= readEthernetHeader(data);
        if(type == 0x0806)
            readArpHeader(data);
        if(type == 0x0800)
            readIPHeader(data);
        printf("\n");
        size -= (16+dataLen);
        packetIndex++;
        free(data);
    }


}