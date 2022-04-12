#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>
#include "checksum.h"
#include <arpa/inet.h>

uint16_t readEthernetHeader(uint8_t *data){
    printf("\n\tEthernet Header\n\t\tDest MAC: ");
    printf("%x",data[0]);
    int i = 0;
    for( i=1; i<6;i++){
        printf(":%x",data[i]);
    }
    printf("\n\t\tSource MAC: ");
    printf("%x",data[6]);
    for(i =7; i<12;i++){
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
    int i =0;
    for(i =23; i<28;i++){
        printf(":%x",data[i]);
    }

    printf("\n\t\tSender IP: ");
    printf("%d",data[28]);
    for(i =29; i<32;i++){
        printf(".%d",data[i]);
    }

    printf("\n\t\tTarget MAC: ");
    printf("%x",data[32]);
    for(i =33; i<38;i++){
        printf(":%x",data[i]);
    }

    printf("\n\t\tTarget IP: ");
    printf("%d",data[38]);
    for(i =39; i<42;i++){
        printf(".%d",data[i]);
    }

    printf("\n\n");


}

void readUDPHeader(uint8_t *data) {
    uint8_t IPHL = 4*(data[14]%16);

    printf("\n\tUDP Header\n\t\tSource Port: : ");

    uint16_t srcPort;
    memcpy(&srcPort, &data[IPHL + 14], 2);
    srcPort = ntohs(srcPort);
    printf("%u\n", srcPort);

    uint16_t dstPort;
    memcpy(&dstPort, &data[IPHL + 16], 2);
    dstPort = ntohs(dstPort);
    printf("\t\tDest Port: : %u\n", dstPort);

}

void readTCPHeader(uint8_t *data){

    uint8_t IPHL = 4*(data[14]%16);

    printf("\n\tTCP Header\n");


    uint16_t srcPort;
    memcpy(&srcPort, &data[IPHL + 14], 2);
    srcPort = ntohs(srcPort);

    if(srcPort == 80){
        printf("\t\tSource Port:  HTTP\n");
    } else {
        printf("\t\tSource Port: : %u\n", srcPort);
    }

    uint16_t dstPort;
    memcpy(&dstPort, &data[IPHL + 16], 2);
    dstPort = ntohs(dstPort);
    if(dstPort == 80){
        printf("\t\tDest Port:  HTTP\n");
    } else {
        printf("\t\tDest Port: : %u\n", dstPort);
    }

    uint32_t sqNum;
    memcpy(&sqNum, &data[IPHL + 18], 4);
    sqNum = ntohl(sqNum);
    printf("\t\tSequence Number: %u\n", sqNum);

    uint32_t ackNum;
    memcpy(&ackNum, &data[IPHL + 22], 4);
    ackNum = ntohl(ackNum);

    uint16_t flag;
    memcpy(&flag, &data[IPHL + 26], 2);
    flag = ntohs(flag);

    if(flag & 0x0010){
        printf("\t\tACK Number: %u\n", ackNum);
    } else {
        printf("\t\tACK Number: <not valid>\n");
    }

    printf("\t\tACK Flag: %s\n", (flag & 0x0010) ? "Yes":"No");
    printf("\t\tSYN Flag: %s\n", (flag & 0x0002) ? "Yes":"No");
    printf("\t\tRST Flag: %s\n", (flag & 0x0004) ? "Yes":"No");
    printf("\t\tFIN Flag: %s\n", (flag & 0x0001) ? "Yes":"No");

    uint16_t winSize;
    memcpy(&winSize, &data[IPHL + 28], 2);
    winSize = ntohs(winSize);
    printf("\t\tWindow Size: %u\n", winSize);

    uint16_t chkSm;
    memcpy(&chkSm, &data[IPHL + 30], 2);
    uint16_t PDUlength;
    memcpy(&PDUlength, &data[16], 2);
    PDUlength = ntohs(PDUlength);

    uint16_t TCPLength = PDUlength-IPHL;
    uint8_t *TCP = malloc((12+TCPLength));
    memcpy(TCP, &data[26], 8);
    TCP[8] = 0;
    TCP[9] = 6;
    uint16_t TCPLengthNetWork = htons(TCPLength);
    memcpy(&TCP[10], &TCPLengthNetWork, 2);

    memcpy(&TCP[12], &data[IPHL + 14], TCPLength);
    printf("\t\tChecksum: %s (0x%x)",
           (in_cksum((unsigned short *) (TCP), 12+TCPLength) == 0) ? "Correct":"Incorrect", ntohs(chkSm));
    free(TCP);


    printf("\n");


}

void readICMPHeader(uint8_t *data) {
    uint8_t IPHL = 4*(data[14]%16);
    if(data[IPHL+14]==0){
        printf("\n\tICMP Header\n\t\tType: Reply\n");
    } else
    if(data[IPHL+14]==8){
        printf("\n\tICMP Header\n\t\tType: Request\n");
    }  else
        printf("\n\tICMP Header\n\t\tType: %u\n", data[IPHL+14]);

}

void readIPHeader(uint8_t *data){
    uint16_t PDUlength;
    uint16_t chkSm;
    memcpy(&PDUlength, &data[16], 2);
    PDUlength = ntohs(PDUlength);
    printf("\n\tIP Header\n\t\tHeader Len: %d (bytes)", 4*(data[14]%16));


    printf("\n\t\tTOS: 0x%x", data[15]);
    printf("\n\t\tTTL: %d", data[22]);
    printf("\n\t\tIP PDU Len: %d (bytes)", PDUlength);
    printf("\n\t\tProtocol: ");
    uint8_t protocol = data[23];
    if(protocol == 1)
        printf("ICMP");
    else if(protocol == 6)
        printf("TCP");
    else if(protocol == 17)
        printf("UDP");
    else
        printf("Unknown");

    memcpy(&chkSm, &data[24], 2);

    printf("\n\t\tChecksum: %s (0x%x)",
           (in_cksum((unsigned short *) (data + 14), 4*(data[14]%16)) == 0) ? "Correct":"Incorrect", chkSm);

    printf("\n\t\tSender IP: ");
    printf("%d",data[26]);
    int i =0;
    for(i =27; i<30;i++){
        printf(".%d",data[i]);
    }
    printf("\n\t\tDest IP: ");
    printf("%d",data[30]);
    for(i =31; i<34;i++){
        printf(".%d",data[i]);
    }
    printf("\n");

    if(protocol == 6){
        readTCPHeader(data);
    }
    if(protocol == 17){
        readUDPHeader(data);
    }
    if(protocol == 1){
        readICMPHeader(data);
    }
}




int main(int argc, char *argv[]){

    FILE* ptr;

    if(argc != 2){
        printf("Invalid Arguments\n");
    }

    ptr = fopen(argv[1], "rb");

    if(NULL == ptr){
        printf("File Does Not Exist. Exiting..\n");
        return 0;
    }

    fseek(ptr, 0, SEEK_END);
    long size = ftell(ptr) - 24;
    fseek(ptr, 0, SEEK_SET);

    int packetIndex = 1;
    uint8_t FileHeader[24];
    fread(FileHeader, 24, 1, ptr);

    while(size > 16){
        printf("\n");
        uint8_t PacketRecord[16];
        fread(PacketRecord, 16, 1, ptr);
        uint32_t dataLen;
        memcpy(&dataLen, &PacketRecord[8], 4);
        uint8_t *data = malloc(dataLen);
        printf("Packet number: %d  Frame Len: %d\n", packetIndex, dataLen);
        fread(data, dataLen, 1, ptr);
        uint16_t type= readEthernetHeader(data);
        if(type == 0x0806)
            readArpHeader(data);
        if(type == 0x0800)
            readIPHeader(data);
        size -= (long)(16+dataLen);
        packetIndex++;
        free(data);
    }
return 0;

}