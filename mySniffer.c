#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<netinet/ip_icmp.h>
#include<netinet/igmp.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/if_ether.h>
#include<net/if.h>
#include<netinet/dhcp.h>
#include<net/ethernet.h>
#include<sys/ioctl.h>
#include<time.h>
#include<sys/types.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<pcap.h>
#include<signal.h>




void PrintData(unsigned char* data, int size){
    int i,j;
    for(i = 0; i < size; i++){
        if(i != 0 && i%16 == 0){
            printf("      ");
            for(j = i -16; j<i ;j++){
                if(data[j] >= 32 && data[j] <= 128){
                    printf("%c",(unsigned char)data[j]);
                }
                else{
                    printf(".");
                }
                
            }
            printf("\n");
        }
        if(i%16 == 0){
            printf(" %02x",(unsigned int)data[j]);
        }
        if(i == size -1){
            for(j = 0; j<15-i%16 ;j++)
               printf("    ");
            for(j = i%16; j <=i;j++){
                if(data[j] >= 32 && data[j] <= 128){
                    printf("%c",(unsigned char)data[j]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}

void print_info_arp_address_mac(char* label,unsigned char* address){
    printf("%s: ",label);
    for(int i = 0; i < 5; i++){
        printf("%02x",address[i]);
        if(i < 4 ){
            printf("-");
        }

    }
    printf("\n");
}
void print_info_arp_address_ip(char* label,unsigned char* address){
    printf("%s: ",label);
    for(int i = 0; i < 4; i++){
        printf("%d",address[i]);
        if(i < 3 ){
            printf(".");
        }

    }
    printf("\n");
}

void print_info_ethernet_header(unsigned char *buff, int size){
    struct ethhdr *eth = (struct ethhdr*)buff;

    printf("\n");
    printf("Ethernet Header:\n");
    printf("    -Destination address: %02x-%02x-%02x-%02x-%02x-%02x \n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    printf("    -Source address: %02x-%02x-%02x-%02x-%02x-%02x \n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]); 
    printf("    -Protocol: %u \n",(unsigned short)eth->h_proto);
}

void print_info_ip_header(unsigned char *buff, int size){
    print_info_ethernet_header(buff,size);

    struct sockaddr_in source, dest;
    struct iphdr *iph = (struct iphdr*)(buff + sizeof(struct ethhdr));

    memset(&source,0,sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest,0,sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    printf("\n");
    printf("IP Header:\n");
    printf("     -Version: %d \n", (unsigned int)iph->version);
    printf("     -IHL: %d DWORDS or %d Bytes \n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl)*4));
    printf("     -Type of Service (ToS): %d \n",(unsigned int )iph->tos);
    printf("     -Total Length: %d \n",(unsigned int )iph->tot_len);
    printf("     -Identification (ID): %d \n",ntohs(iph->id));
    printf("     -Fragment Offset: %d \n",ntohs(iph->frag_off));
    printf("     -Time To Live (TTL): %d \n",(unsigned int )iph->ttl);
    printf("     -Protocol: %d \n",(unsigned int )iph->protocol);
    printf("     -Header checksum: %d \n",(unsigned int )iph->check);
    printf("     -Source IP: %s \n",inet_ntoa(source.sin_addr));
    printf("     -Destination IP: %s \n",inet_ntoa(dest.sin_addr));

}

void print_info_icmp_packet(unsigned char *buff, int size){
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)(buff + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct icmphdr *icmph = (struct icmphdr*)(buff + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(icmph);
    struct sockaddr_in gateway;
    gateway.sin_addr.s_addr = icmph->un.gateway;

    printf("************* ICMP PACKET *************\n");

    print_info_ip_header(buff,size);

    printf("\n");
    printf("ICMP Header:\n");
    printf("     -Type: %d ",(unsigned int)(icmph->type));
    if((unsigned int)(icmph->type) == 11){
        printf(" (TTL Expired)\n");
    }
    else if ((unsigned int)(icmph->type) == 0){
        printf(" (Echo Reply)\n");
    }
    else if ((unsigned int)(icmph->type) == 8){
        printf(" (Echo Request)\n");
    }
    printf("     -Code: %d \n",(unsigned int)(icmph->code));
    printf("     -Checksum: %d \n",htons(icmph->checksum));
    printf("         |ID: %d \n",htons(icmph->un.echo.id));
    printf("         |Sequence: %d \n",htons(icmph->un.echo.sequence));
    printf("         |Gateway Adress: %s \n",inet_ntoa(gateway.sin_addr));
    printf("\n");

    printf("               Data Dump           \n");
    printf("\n");
    printf("IP Header:\n");
    PrintData(buff,iphdrlen);
    printf("\n");
    printf("ICMP Header:\n");
    PrintData(buff + iphdrlen, sizeof(icmph));
    printf("\n");
    printf("Data Payload:\n");
    PrintData(buff + header_size, size - header_size);
    printf("\n");
    printf("***************************************\n");
}

void print_info_igmp_packet(unsigned char *buff,int size){
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)(buff + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct igmp *igmph = (struct igmp*)(buff + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(igmph);

    printf("************* IGMP PACKET *************\n");

    print_info_ip_header(buff,size);

    printf("\n");
    printf("IGMP Header:\n");
    printf("   -Type: %d \n",(unsigned int)(igmph->igmp_type));
    printf("   -Max Resp Code: %d \n",(unsigned int)(igmph->igmp_code));
    printf("   -Checsum: %d \n",htons(igmph->igmp_cksum));
    printf("   -Group Adresses: %s \n",inet_ntoa(igmph->igmp_group));

    printf("               Data Dump           \n");
    printf("\n");
    printf("IP Header:\n");
    PrintData(buff,iphdrlen);
    printf("\n");
    printf("IGMP Header:\n");
    PrintData(buff + iphdrlen, sizeof(igmph));
    printf("\n");
    printf("Data Payload:\n");
    PrintData(buff + header_size, size -header_size);
    printf("\n");

    printf("***************************************\n");
}

void print_info_tcp_packet(unsigned char* buffer, int size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)buffer;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
			
	printf("************* TCP PACKET *************\n");
		
	print_info_ip_header(buffer,size);
		
	printf("\n");
	printf("TCP Header:\n");
	printf("   -Source Port      : %u\n",ntohs(tcph->source));
	printf("   -Destination Port : %u\n",ntohs(tcph->dest));
	printf("   -Sequence Number    : %u\n",ntohl(tcph->seq));
	printf("   -Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	printf("   -Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	printf("   -Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	printf("   -Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	printf("   -Push Flag            : %d\n",(unsigned int)tcph->psh);
	printf("   -Reset Flag           : %d\n",(unsigned int)tcph->rst);
	printf("   -Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	printf("   -Finish Flag          : %d\n",(unsigned int)tcph->fin);
	printf("   -Window         : %d\n",ntohs(tcph->window));
	printf("   -Checksum       : %d\n",ntohs(tcph->check));
	printf("   -Urgent Pointer : %d\n",tcph->urg_ptr);
	printf("\n");
	printf("               Data Dump           \n");
	printf("\n");
		
	printf("IP Header\n");
	PrintData(buffer,iphdrlen);
		
	printf("TCP Header\n");
	PrintData(buffer+iphdrlen,tcph->doff*4);
	
	printf("Data Payload\n");	
	PrintData(buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4) );

						
	printf("***************************************\n");
}

void print_info_dhcp_packet(unsigned char* buff,int size){
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)(buff + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct dhcp_header *dhcph = (struct dhcp_header*)(buff + sizeof(struct udphdr) + iphdrlen + sizeof(struct ethhdr));
    struct sockaddr_in gateway,assigned,server,client;
    gateway.sin_addr.s_addr = dhcph->giaddr;
    assigned.sin_addr.s_addr = dhcph->yiaddr;
    client.sin_addr.s_addr = dhcph->ciaddr;
    server.sin_addr.s_addr = dhcph->siaddr;



    printf("DHCP Header:\n");
    printf("     -Operation: %s \n",(dhcph->op == BOOTREQUEST) ? "Request" : "Reply");
    printf("     -Hardware Address Type: %d \n",ntohs(dhcph->htype));
    printf("     -Hardware Type Length: %d \n",ntohs(dhcph->hlen));
    printf("     -Number of hops: %d \n",ntohs(dhcph->hops));
    printf("     -Transaction ID: %d \n",ntohs(dhcph->xid));
    printf("     -Seconds: %d \n",ntohs(dhcph->secs));
    printf("     -Flags: %d \n",ntohs(dhcph->flags));
    printf("     -Client IP: %s \n",inet_ntoa(client.sin_addr));
    printf("     -Assigned Client IP: %s \n",inet_ntoa(assigned.sin_addr));
    printf("     -Server IP: %s \n",inet_ntoa(server.sin_addr));
    printf("     -Gateway DHCP: %s \n",inet_ntoa(gateway.sin_addr));
    printf("     -Client Hardware Address: ");
    for (int i = 0; i < dhcph->hlen; ++i) {
        printf("%02X:", dhcph->chaddr[i]);
    }
    printf("\n");
    printf("     -Server Name: %s \n",dhcph->sname);
    printf("     -Boot filename: %s \n",dhcph->file);
    //printf("     -Options: %d \n",ntohs(udph->len));
}


void print_info_udp_packet(unsigned char *buff,int size){
    
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)(buff + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(buff + iphdrlen + sizeof(struct ethhdr));
    unsigned short src_port = ntohs(udph->source);
    unsigned short dest_port = ntohs(udph->dest);
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);
    if((src_port == 67 && dest_port == 68) || (src_port == 68 && dest_port == 67)){
        printf("************* DHCP PACKET *************\n");
        print_info_ip_header(buff,size);
        printf("UDP Header:\n");
        printf("     -Source port: %d \n",src_port);
        printf("     -Destination port: %d \n",dest_port);
        printf("     -UDP Length: %d \n",ntohs(udph->len));
        printf("     -UDP Chechsum: %d \n",ntohs(udph->check));
        printf("\n");
        print_info_dhcp_packet(buff,size);
        printf("              DATA Dump               \n");
        printf("\n");

        printf("IP Header:\n");
        PrintData(buff,iphdrlen);
        printf("UDP Header:\n");
        PrintData(buff+ iphdrlen,sizeof(udph));
        printf("DHCP Header:\n");
        PrintData(buff + iphdrlen + sizeof(udph),sizeof(struct dhcp_header));
        printf("Data Payload:\n");
        PrintData(buff + header_size,size-header_size);
        printf("**************************************\n");
    }
    else{
        printf("************* UDP PACKET *************\n");
        print_info_ip_header(buff,size);
        printf("UDP Header:\n");
        printf("     -Source port: %d \n",src_port);
        printf("     -Destination port: %d \n",dest_port);
        printf("     -UDP Length: %d \n",ntohs(udph->len));
        printf("     -UDP Chechsum: %d \n",ntohs(udph->check));
        printf("\n");
        printf("              DATA Dump               \n");
        printf("\n");

        printf("IP Header:\n");
        PrintData(buff,iphdrlen);
        printf("UDP Header:\n");
        PrintData(buff+ iphdrlen,sizeof(udph));
        printf("Data Payload:\n");
        PrintData(buff + header_size,size-header_size);
        printf("**************************************\n");
    }

}

void printf_info_arp_header(unsigned char*buff, int size){

    unsigned char* arp_ptr = buff + sizeof(struct ethhdr);
    struct arphdr* arp = (struct arphdr*)arp_ptr;
      
    unsigned short arpop = ntohs(arp->ar_op);

    printf("Hardware Type (HTYPE): %04x\n", ntohs(arp->ar_hrd));
    printf("ProtocolType (PTYPE): %04x\n", ntohs(arp->ar_pro));
    printf("Hardware Adress Length (HLEN): %02x\n", ntohs(arp->ar_hln));
    printf("Protocol Adress Length (PLEN): %02x\n", ntohs(arp->ar_pln));
    printf("Operation  (OPER): %s\n", (arpop == ARPOP_REQUEST) ? "Request" : "Reply");
    
    unsigned char* sender_mac = arp_ptr + sizeof(struct arphdr);
    unsigned char* sender_ip = sender_mac + arp->ar_hln;
    unsigned char* target_mac = sender_ip + arp->ar_pln;
    unsigned char* target_ip = target_mac + arp->ar_hln;

    print_info_arp_address_mac("Sender MAC", sender_mac);
    print_info_arp_address_ip("Sender IP", sender_ip);
    print_info_arp_address_mac("Target MAC", target_mac);
    print_info_arp_address_ip("Target IP", target_ip);

}

void print_info_arp_packet(unsigned char *buff, int size){
    printf("************* ARP *************\n");
    printf_info_arp_header(buff,size);
    printf("*******************************\n");
}
void Packets(unsigned char* buff,int size){

    struct ethhdr *eth = (struct ethhdr*)buff;
    unsigned short eth_type = ntohs(eth->h_proto);

    if(eth_type == ETH_P_ARP){       
        print_info_arp_packet(buff,size);
    }
    else if( eth_type == ETH_P_IP){
        struct iphdr *iph = (struct iphdr*)(buff + sizeof(struct ethhdr));
        switch(iph->protocol){
            case 1:
                print_info_icmp_packet(buff,size);
            case 2:
                print_info_igmp_packet(buff,size);
            case 6:
                print_info_tcp_packet(buff,size);
            case 17:
                print_info_udp_packet(buff,size);
        }
    }
    
}

void fun_error(char *msg){
    perror(msg);
    exit(0);
}


int socket_fd;

void handler(int signal){
    if(signal == SIGINT){
        close(socket_fd);
        printf("\nFinished.\n");
        exit(0);
    }
}

int main(int argc,char *argv[]){

    signal(SIGINT,handler);
    if(argc != 2){
        printf("Uzycie programu: program <interfejs>\n");
        exit(0);
    }
    int saddr_size, data_size;
    struct sockaddr saddr;

    unsigned char *buff = (unsigned char *)malloc(65536);
    socket_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(socket_fd < 0){
        fun_error("Socket Error");
    }
    if(setsockopt(socket_fd,SOL_SOCKET,SO_BINDTODEVICE,argv[1],strlen(argv[1]) + 1) == -1){
        fun_error("Nieznany interfejs sieciowy");
    }
    printf("Starting...\n");
    while(1){
        saddr_size = sizeof(saddr);
        data_size = recvfrom(socket_fd,buff,65536,0,&saddr,(socklen_t *)&saddr_size);
        if(data_size < 0){
            fun_error("Recvfrom Error");
        }
        
        Packets(buff,data_size);

    }
    printf("Finished.\n");

    close(socket_fd);
    return 0;
}
