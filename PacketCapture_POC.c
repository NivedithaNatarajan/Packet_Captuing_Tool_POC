#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include<errno.h>
#include<netdb.h>
#include<stdlib.h>
#include<string.h>
#include<net/ethernet.h> 
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>  
#include<netinet/tcp.h>  
#include<netinet/ip.h>   
#include<unistd.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<stdbool.h>
#include<regex.h>
#include<ctype.h>


void print_iph(unsigned char* , int);
void print_tcp(unsigned char * , int );
void print_udp(unsigned char * , int );
void print_icmp(unsigned char* , int );
void PrintData (unsigned char* , int);
char* domain_start (unsigned char[] , int);
char* domain_end (unsigned char[] , int);

struct sockaddr_in src,dest;
int tcp=0,udp=0,icmp=0,tot=0,other=0,i,j,tcp_size,udp_size;
char spu,dpu,spt,dpt;
int choice;



void alert (unsigned char str[], int Size)
{

    char *pos1, *pos2;

    str[Size]='\0';
    unsigned char *script_start = "%3Cscript%3E";
    unsigned char *script_end = "%3C/script%3E";
    int len;
    char *d_start, *d_end;

    size_t i;

    if((pos1 = strstr(str, script_start)) != NULL)
    {
      if((pos2 = strstr(str, script_end)) != NULL)
      {
         len = pos2 - pos1;   
      }
    }
    if(len>0 && pos1 != NULL && pos2 != NULL)
    {
      printf("\n\nALERT!!       Attack detected!\n");
      printf("Description : XSS attack");
      printf("\nAttacker IP : %s",inet_ntoa(src.sin_addr));
      printf("\nVictim IP   : %s   (Domain)",inet_ntoa(dest.sin_addr));

      d_start = domain_start(str, Size);
      if(d_start==NULL)
      {
    //printf("\nNo URL found\n");
    return;
      }

      d_end = domain_end(str, Size);

      if(d_end==NULL)
      {
    //printf("\nNo distinct URL found\n");
    return;
      }
       
      if(d_start!=NULL && d_end!=NULL)
      {
    int len = d_end + 11 - d_start;
    PrintURL(d_start,len);
    printf("Payload     : ");
    PrintURL(pos1,len + 14);
      }
    
     return;
      }
      else
    printf("\nClear.\n");
}


char* domain_start (unsigned char str[], int Size)
{

  char *pos;
  unsigned char *MUST_CONTAIN[] =
  {
    "Host:",
    "http://",
    "www.",
    "in.",
    "en"
   };
  str[Size]='\0';

  size_t i;
  for(i=0; i<sizeof(MUST_CONTAIN)/sizeof(*MUST_CONTAIN); i++)
  {
    if((pos=strstr(str, MUST_CONTAIN[i])) != NULL)
    {
      return pos;
    }
  }
  return NULL;
}



char* domain_end (unsigned char str[], int Size)
{
  char *pos;

  unsigned char* MUST_END[]=
  {
    ".net",
    ".org",
    ".in",
    ".com",
    ".it",
    ".int",
    ".gov",
    ".edu",
    ".mil"

  };
  str[Size]='\0';

  size_t i;
  for(i=0; i<sizeof(MUST_END)/sizeof(*MUST_END); i++)
  {
    if((pos=strstr(str, MUST_END[i])) != NULL)
    {
      return pos+4;
    }
  }

  return NULL;
}



char* url_start(unsigned char str[], int Size)
{
  char *pos;
 
  unsigned char* MUST_START[]=
  {
    "http://www.",
    "Referer:"
   
  };
  str[Size]='\0';

  size_t i;
  for(i=0; i<sizeof(MUST_START)/sizeof(*MUST_START); i++)
  {
    if((pos = strstr(str,MUST_START[i]))!=NULL)
    {
    return pos;
    }
  }
 
  return NULL;
}



char* url_end(unsigned char str[], int Size)
{
  char *pos;
 
  unsigned char *MUST_END[]=
  {
    ".dtd",
    ".aspx",
    ".html:",
    ".php",
    "Cookie:"
  };
  str[Size]='\0';
 
  size_t i;
  for(i=0; i<sizeof(MUST_END)/sizeof(*MUST_END); i++)
  {
    if((pos = strstr(str,MUST_END[i]))!=NULL)
    {
    return pos + 4;
    }
  }

  return  NULL;
}  



void func(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int size = header->len;
 
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    ++tot;
    switch (iph->protocol)
    {
        case 1: 
            ++icmp;
            print_icmp( packet , size);
            break;
        
        case 6: 
            ++tcp;
            print_tcp(packet , size);
            break;
        
        case 17:
            ++udp;
            print_udp(packet , size);
            break;
        
        default:
            ++other;
            break;
    }


}


void print_eheader(unsigned char *Buffer, int size)
{
    struct ethhdr *e = (struct ethhdr *)Buffer;
        
    printf("\n");
    printf("Ethernet Header\n");
    printf("|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", e->h_dest[0] , e->h_dest[1] , e->h_dest[2] , e->h_dest[3] , e->h_dest[4] , e->h_dest[5] );
    printf("|-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", e->h_source[0] , e->h_source[1] , e->h_source[2] , e->h_source[3] , e->h_source[4] , e->h_source[5] );
    printf("|-Protocol  : %u \n",(unsigned short)e->h_proto);

}



void print_iph(unsigned char* Buffer,int Size)
{
    print_eheader(Buffer , Size);
      
    unsigned short iphdrlen;
           
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
        
    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->saddr;
        
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
        
    printf("\n");
        printf("IP Header\n");
    printf("|IP Version : %d|\t",(unsigned int)iph->version);
    printf("|IP Header Length  : %d DWORDS or %d Bytes|\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("|Type Of Service: %d|\t",(unsigned int)iph->tos);
    printf("|IP Total Length: %d  Bytes(Size of Packet)|\t",ntohs(iph->tot_len));
    printf("|Identification : %d|\n",ntohs(iph->id));
    printf("|TTL : %d|\t",(unsigned int)iph->ttl);
    printf("|Protocol : %d|\t",(unsigned int)iph->protocol);
    printf("|Checksum : %d|\n",ntohs(iph->check));
    //spt = inet_ntoa(src.sin_addr);
    //dpt = inet_ntoa(dest.sin_addr);
    printf("|Source IP        : %s|\t",inet_ntoa(src.sin_addr));
    printf("|Destination IP   : %s|\n",inet_ntoa(dest.sin_addr));
}



void print_tcp(unsigned char *Buffer,int Size)
{
    unsigned short iphdrlen;
        
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
        
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
                
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
        
    printf("\n\n***********************TCP Packet*************************\n"); 
            
    print_iph(Buffer,Size);
   
    printf("\n");
    printf("TCP Header\n");
    printf("|Source Port: %u|\t",tcph->source);
    printf("|Destination Port: %u|\n",tcph->dest);
    printf("|Sequence Number: %u|\t",ntohl(tcph->seq));
    printf("|Acknowledge Number : %u|\t",ntohl(tcph->ack_seq));
    printf("|Header Length: %d DWORDS or %d BYTES|\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    if((unsigned int)tcph->urg==1)
    printf("|Urgent Flag = %d|\t",(unsigned int)tcph->urg);
    if((unsigned int)tcph->ack==1)
    printf("|Acknowledgement Flag = %d|\t",(unsigned int)tcph->ack);
    if((unsigned int)tcph->psh==1)
    printf("|Push Flag = %d|\n",(unsigned int)tcph->psh);
    if((unsigned int)tcph->rst==1)
    printf("|Reset Flag= %d|\t",(unsigned int)tcph->rst);
    if((unsigned int)tcph->syn==1)
    printf("|Synchronise Flag= %d|\t",(unsigned int)tcph->syn);
    if((unsigned int)tcph->fin==1)
    printf("|Finish Flag= %d|\n",(unsigned int)tcph->fin);
    printf("|Window: %d|\t",ntohs(tcph->window));
    printf("|Checksum: %d|\t",ntohs(tcph->check));
    printf("|Urgent Pointer : %d|\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
            
    printf("IP Header\n");
    PrintData(Buffer,iphdrlen);
          
    printf("TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    if(choice==1)
    {     
        printf("Data Payload\n");   
        PrintData(Buffer + header_size , Size - header_size );
    }
   
    printf("\nPayload size : %d",Size - header_size);
   
    if((Size - header_size)>0)
    {
        unsigned char *p = Buffer + header_size;
        unsigned char buffer_string[Size - header_size];
        int j;
           
        strcpy(buffer_string,p);
           
/*        printf("\n\nContents of buffer_string :\n");
        unsigned char *temp=buffer_string;
        int bytes=0;   
   
        while(bytes<= (Size - header_size))
        {
            if(isprint(*temp))
                printf("%c",*temp);
            else
                printf(".");
            bytes++;
            temp++;
        }
*/
        printf("\n");
        buffer_string[(Size - header_size) + 1]='\0';
       
        char *u_start = url_start(buffer_string, Size - header_size);
        char *u_end = url_end(buffer_string, Size - header_size);

        char *d_start, *d_end;
        if(u_start==NULL || u_end==NULL)
        {
            d_start = domain_start(buffer_string, Size - header_size);
            if(d_start==NULL)
            {
                //printf("\nNo URL found\n");
                return;
            }
           
            d_end = domain_end(buffer_string, Size - header_size);
            if(d_end==NULL)
            {
                //printf("\nNo distinct URL found\n");
                return;
            }
           
            int len = d_end - d_start;
           
            printf("\nDomain : ");
            PrintURL(d_start,len);
            printf("Looking for attacks..");
            alert(buffer_string, Size - header_size);
            return;
        }
       
        else
        {

        int len=u_end - u_start;            
        printf("URL : ");
        PrintURL(u_start,len);
        printf("Looking for attacks..");
        alert(buffer_string, Size - header_size);
        }

    }
   
    printf("\n###########################################################\n");
   
}


void print_udp(unsigned char *Buffer,int Size){

    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
  
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    
    printf("\n\n***********************UDP Packet*************************\n");
    
    print_iph(Buffer,Size);              
    printf("\nUDP Header\n");
    printf("|-Source Port: %d|\t" , udph->source);
    printf("|-Destination Port : %d|\n" , udph->dest);
    printf("|-UDP Length : %d|\t" , ntohs(udph->len));
    printf("|-UDP Checksum : %d|\n" , ntohs(udph->check));
        
    printf("\n");
    printf("IP Header\n");
    PrintData(Buffer , iphdrlen);
            
    printf("UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
   
    if(choice==1)
    {                
        printf("Data Payload\n");        
        PrintData(Buffer + header_size , Size - header_size);
    }

    if((Size - header_size)>0)
    {
        unsigned char *p = Buffer + header_size;
        unsigned char buffer_string[Size - header_size];
        int j;
           
        strcpy(buffer_string,p);
           
/*        printf("\n\nContents of buffer_string :\n");
        unsigned char *temp=buffer_string;
        int bytes=0;   
   
        while(bytes<= (Size - header_size))
        {
            if(isprint(*temp))
                printf("%c",*temp);
            else
                printf(".");
            bytes++;
            temp++;
        }
*/
        printf("\n");
        buffer_string[(Size - header_size) + 1]='\0';
       
        char *u_start = url_start(buffer_string, Size - header_size);
        char *u_end = url_end(buffer_string, Size - header_size);

        char *d_start, *d_end;
        if(u_start==NULL || u_end==NULL)
        {
            d_start = domain_start(buffer_string, Size - header_size);
            if(d_start==NULL)
            {
                //printf("\nNo URL found\n");
                return;
            }
           
            d_end = domain_end(buffer_string, Size - header_size);
            if(d_end==NULL)
            {
                //printf("\nNo distinct URL found\n");
                return;
            }
           
            if(d_start!=NULL && d_end!=NULL)
            {
            int len = d_end - d_start;
            printf("\nDomain : ");
            PrintURL(d_start,len);
            printf("Looking for attacks..");
            alert(buffer_string, Size - header_size);
            }
            return;
           
        }
       
        else
        {

        int len=u_end - u_start;            
        printf("URL : ");
        PrintURL(u_start,len);
        printf("Looking for attacks..");
        alert(buffer_string, Size - header_size);
        }
                  
    }
        
    printf("\n###########################################################\n");
}   
   


void print_icmp(unsigned char *Buffer,int Size){
    unsigned short iphdrlen;
            
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
            
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
      
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
        
    printf("\n\n***********************ICMP Packet*************************\n");
        
    print_iph(Buffer , Size);
                
    printf("\n");
            
    printf("ICMP Header\n");
    printf("\n|-Type : %d|\t",(unsigned int)(icmph->type));
                
    if((unsigned int)(icmph->type) == 11)
    {
    printf("  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
    printf("  (ICMP Echo Reply)\n");
    }
        
        printf("|-Code : %d|\t",(unsigned int)(icmph->code));
    printf("|-Checksum : %d|\n",ntohs(icmph->checksum));
    printf("\n");
     
    printf("IP Header\n");
    PrintData(Buffer,iphdrlen);
            
    printf("UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
   
    if(choice==1)
    {      
    printf("Data Payload\n");   
        PrintData(Buffer + header_size , (Size - header_size) );
    }  
   
    printf("\n###########################################################\n");
    }
       
   
void print_upayload(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    const u_char *ip_header;
    const u_char *udp_header;
    const u_char *upayload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int udp_header_length;
    int payload_length;
   
    const u_char *url, *end_url, *final_url;
    int url_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);
   
    udp_header = packet + ethernet_header_length + ip_header_length;
   
    udp_header_length = ((*(udp_header + 12)) & 0xF0) >> 4;

    udp_header_length = udp_header_length * 4;

    printf("UDP header length in bytes: %d\n", udp_header_length);

    int total_headers_size = ethernet_header_length + ip_header_length + udp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
  
    payload_length = header->caplen - (ethernet_header_length + ip_header_length + udp_header_length); 
    printf("Payload size: %d bytes\n", payload_length);
    upayload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", upayload);  
   
    printf("\n");
    return;
}




void print_payload(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    const u_char *ip_header;
    const u_char *tcp_header;
    u_char *payload;
 

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;

    int payload_length;

    int url_length;
    char *url, *end_url;
    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);

    tcp_header = packet + ethernet_header_length + ip_header_length;
   
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
       
    tcp_header_length = tcp_header_length * 4;


    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
  
    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
 
  
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    return;
}


 

void PrintData(unsigned char *data, int Size)
{

    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)  
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]);
                   
                else
                    printf(".");
            }
        printf("\n");
        }
        
        if(i%16==0)
             printf("   ");
        printf(" %02X",(unsigned int)data[i]);
                
        if( i==Size-1)
        {
            for(j=0;j<15-i%16;j++)
            {
                printf("   ");
            }
            
            printf("         ");
           
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    printf("%c",(unsigned char)data[j]);
                }
                else
                {
                    printf(".");
                }    
            }         
        printf("\n" );
        }   
    }
}


void PrintURL(unsigned char *data, int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)  
        {
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]);
                       
                else
                    printf(".");
            }
        }
                                         
        if( i==Size-1)
        {           
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    printf("%c",(unsigned char)data[j]);
                }
                else
                {
                    printf(".");
                }    
            }         
            printf("\n" );
        }
    }
}
   
   
   
int main(int argc, char **argv) {   
    if(argc<3)
    {
    printf("\nIncorrect usage!\nCorrect usage : './a.out <number of packets to be sniffed> <(1) Display data dump. (0) Eliminate data dump.>'\n");
    exit (0);
    }

    choice = atoi(argv[2]);

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;
    //char filter_exp[] = "dst port 80 or dst port 443";

 
    char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
    printf("Lookupdev failed. No device found. Error description : %s\n", errbuf);
    return(2);
    }
    printf("\nStarting..");

    pcap_t *handle = pcap_open_live(device, BUFSIZ, 0, 10000, errbuf);
    if(handle==NULL){
    printf("\nError in finding a device");
    exit(1);
    }
    printf("\nSniffing packets..\n");
  
   // if(pcap_compile(handle, &fp, filter_exp, 0, net)==-1){
   // printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
   // return(2);
   // }

  //if (pcap_setfilter(handle, &fp) == -1) {
  //  printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //return(2);
   // }

    pcap_loop(handle, atoi(argv[1]) , func, NULL);
    printf("\nFinished.\nSummary:");
    printf("\nTCP : %d   UDP : %d  ICMP : %d  Others : %d  Total : %d \n",tcp,udp,icmp,other,tot);

    return 0;
}