/******************************************************************************
*
*  @file    iudp.c
*
*  @brief   UDP Network Analyzer 
*
******************************************************************************/


/* ---- Include Files ------------------------------------------------------ */
#include <stdio.h>
#include <stdlib.h>    
#include <string.h>
#include <math.h>
#include <time.h>

#include <errno.h>   
#include <unistd.h>     
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <sys/signal.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* ---- Public Constants and Types ---------------------------------------- */
#define MSG_LEN 2400

#define MIN_MSG_LEN 1200
#define MAX_MSG_LEN 3600

#define ICMP_LEN 192
#define PACKETS 250
#define PORT 10000
#define SECONDS 5
#define OCTETS 4

#define IP_DELIM "."


typedef struct sockaddr_in sockaddr_in_t;
typedef struct timeval timeval_t;

typedef struct  
{
//   unsigned char msg[MSG_LEN];
   unsigned char rmsg[MSG_LEN];
   unsigned char* msg;
   unsigned int len;
   unsigned int seq;
} udp_load_t;

typedef struct
{
   int sockfd;
   sockaddr_in_t svr_addr,cln_addr;
   udp_load_t load;
} udp_t;

typedef struct 
{
   udp_t udp;
   unsigned char* ip;
   unsigned int pkts;
   float rate;   
   unsigned int port;   
   unsigned int sz;   
} udp_data_t;


typedef struct
{
   unsigned int pkts;
   unsigned int rcv_pkts;
   unsigned int lost_pkts;

   float time;   /* in seconds */
   float mb;

   float avg_throughput;  
   float min_throughput;
   float max_throughput;

   float avg_sz;
   float min_sz;
   float max_sz;
   
   float avg_rcv_rate;
   float min_rcv_rate;

   float avg_lost_rate;
   float max_lost_rate;

} stat_t;

/* ---- Public Variables --------------------------------------------------- */
const char ALPHA_NUMERIC[62] =  {'0','1','2','3','4','5','6','7','8','9','a',
'b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t',
'u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
'O','P','Q','R','S','T','U','V','W','X','Y','Z'};
stat_t stat;

/* ---- Public Function Prototypes ----------------------------------------- */
void usage();
void server_usage();
void client_usage();
void default_settings();
unsigned int gen_num (unsigned int min, unsigned int max);
void set_msg (unsigned char* msg, unsigned int len);
int alloc_strlen(unsigned char* str);
int ping(unsigned char *host);

void client_thread (void* ptr);
void server_thread (void* ptr);
void time_thread (void* ptr);
/* ---- Private Constants and Types ---------------------------------------- */
/* ---- Private Variables -------------------------------------------------- */
/* ---- Private Function Prototypes ---------------------------------------- */
/* ---- Functions ---------------------------------------------------------- */

void usage () 
{
   fprintf(stderr, "\nUsage: iudp [-s|-c host -ip server_ip] [options]\n");
   fprintf(stderr, "iudp [-h|--help]\n\n");
//   fprintf(stderr, "Client/Server:\n");
//   fprintf(stderr, "-o, --output    <filename> output the report or error message to this specified file\n\n");
   server_usage();
   client_usage();
   fprintf(stderr, "Miscellaneous:\n");
   fprintf(stderr, "-h, --help                 print this message and quit\n");
   fprintf(stderr, "-df, --default             print all default settings\n");
   fprintf(stderr, "\n\n");
   fprintf(stderr, "[KM] Indicates options that support a K or M suffix for kilo- or mega-\n");
}

void server_usage()
{
   fprintf(stderr, "Server:\n");
   fprintf(stderr, "-s, --server               run in server mode\n");
   fprintf(stderr, "-p, --port      #          listen on port number (min. 1024)\n");
   fprintf(stderr, "-d, --daemon               run the server as a daemon\n\n");
}

void client_usage() 
{
   fprintf(stderr, "Client:\n");
   fprintf(stderr, "-c, --client    <host>     run in client mode, connecting to <host>\n");
   fprintf(stderr, "-p, --port      #          sent to server port number (min. 1024)\n");
   fprintf(stderr, "-ip,                       server host ip\n");
   fprintf(stderr, "-n,             #[KM]      number of bytes to transmit (min. 2400KB)\n");
//   fprintf(stderr, "-F, --fileinput <name>     input the data to be transmitted from a file\n");
   fprintf(stderr, "-p, --parallel  #          number of parallel client threads to run\n\n");
}

void default_settings() 
{
   fprintf(stderr, "\nServer Settings:\n");
   fprintf(stderr, "Listening Port: %i\n", PORT);
   fprintf(stderr, "\nClient Settings:\n");
   fprintf(stderr, "Connect Port: %i\n", PORT);
   fprintf(stderr, "Message Length: %i\n", MSG_LEN);
   fprintf(stderr, "Number of Packets: %i\n\n", PACKETS);
}

unsigned int gen_num (unsigned int min, unsigned int max)
{
   unsigned int num = rand() % max + min;
   while (num > max || num < min) 
   {
      num = rand() % max + min;
   }

   return num;
}

void set_msg (unsigned char* msg, unsigned int len) 
{
   int i,num;
  
   strcpy(msg, "");

   printf("strlen(%i)\n", strlen(msg));
   for(i = 0; i < len ; i++) 
   {
      num = gen_num(0, 61);
      msg[i] = ALPHA_NUMERIC[num];
   }
   printf("strlen(%i)\n", strlen(msg));
}

int alloc_strlen(unsigned char* str)
{
   int len=0;
   while(str[len])
   {
      len++;
   }

   return len;
}

static int icmp_chksum(unsigned short *buf, int sz)
{
   int nleft = sz;
   int sum = 0;
   unsigned short *w = buf;
   unsigned short ans = 0;
  
   while (nleft > 1) 
   {
      sum += *w++;
      nleft -= 2;
   }
  
   if (nleft == 1) 
   {
      *(unsigned char *) (&ans) = *(unsigned char *) w;
      sum += ans;
   }
  
   sum = (sum >> 16) + (sum & 0xFFFF);
   sum += (sum >> 16);
   ans = ~sum;
   return (ans);
}


static void no_icmp_response(int ign)
{
   fprintf(stderr, "\nError: Unable to connect to host\n");
   fprintf(stderr, "Please check ./iudp -c '-ip <host>'\n\n");
   fprintf(stderr, "For more help, please type ./iudp -h\n\n");
   exit(0);
}

int ping(unsigned char *host)
{
   struct hostent *h;
   sockaddr_in_t pingaddr;
   struct icmp *pkt;
   int sockfd, ret;
   char packet[ICMP_LEN];
 
   if((sockfd = socket(AF_INET, SOCK_RAW, 1)) < 0) 
   {       
      fprintf(stderr, "Warning: Unable to create ICMP socket fd, server host may be unreachable!\n");
      return 0;
   }
  
   memset(&pingaddr, 0, sizeof(sockaddr_in_t));
  
   pingaddr.sin_family = AF_INET;
   if (!(h = gethostbyname(host))) 
   {
      fprintf(stderr, "Error: Unknown server host %s\n", host);
      return -1;
   }
  
   memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr));
  
   pkt = (struct icmp *) packet;
   memset(pkt, 0, sizeof(packet));
   pkt->icmp_type = ICMP_ECHO;
   pkt->icmp_cksum = icmp_chksum((unsigned short *) pkt, sizeof(packet));
  
   ret = sendto(sockfd, packet, sizeof(packet), 0,
   (struct sockaddr *) &pingaddr, sizeof(sockaddr_in_t));
  
   if (ret < 0 || ret != sizeof(packet)) 
   {
      if (ret < 0)
      fprintf(stderr, "Warning: ICMP return message was corrupted, server host may be unreachable!\n");
      return 0;
   }
  
   signal(SIGALRM, no_icmp_response);
   alarm(2);  
   sockaddr_in_t from;
   size_t fromlen = sizeof(from);
   ret = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *) &from, &fromlen); 

   if (ret >= 76) 
   {                   /* ip + icmp */
      struct iphdr *iphdr = (struct iphdr *) packet;
      pkt = (struct icmp *) (packet + (iphdr->ihl << 2));      /* skip ip hdr */
      if (pkt->icmp_type == ICMP_ECHOREPLY)
      {
         return 0;
      }
      else 
      {
         fprintf(stderr, "Warning: Non-ICMP return message received, server host may be unreachable!\n");
         return 0;
      } 
   } 
   else 
   {
      return -1;
   }
}


void report(int s){
   printf("\n------------------------------------------------------------\n");
   printf("Server Report\n");
   printf("------------------------------------------------------------\n");
   printf("Time:\t\t\t%.2f s\n\n", stat.time);

   printf("Packets:\t\t%i\n", stat.pkts);
   printf("Packets Rate:\t\t%.2f pkt/s\n", (stat.time == 0 ? 0:(float)stat.pkts/(float)stat.time));
   printf("Packets Received:\t%i\n", stat.rcv_pkts);
   printf("Packets Lost:\t\t%i\n\n", stat.lost_pkts);

   printf("Total Size:\t\t%.2f MB\n", stat.mb);
   printf("Average Packet Size:\t%.2f KB\n", stat.avg_sz);
   printf("Min Packet Size:\t%.2f KB\n", stat.min_sz);
   printf("Max Packet Size:\t%.2f KB\n\n", stat.max_sz);
   
   printf("Average Received %%:\t%.2f %%\n", stat.avg_rcv_rate);
   printf("Min Received %%:\t\t%.2f %%\n\n", stat.min_rcv_rate);

   printf("Average Lost %%:\t\t%.2f %%\n", stat.avg_lost_rate);
   printf("Max Lost %%:\t\t%.2f %%\n\n", stat.max_lost_rate);

   printf("Average Throughput:\t%.2f MB/s\n", stat.avg_throughput);
   printf("Min Throughput:\t\t%.2f MB/s\n", stat.min_throughput);
   printf("Max Throughput:\t\t%.2f MB/s\n\n", stat.max_throughput);
   printf("------------------------------------------------------------\n");

   exit(1); 
}


float get_second () 
{
   char sec [15];
   timeval_t tv;
   time_t curtime;

   gettimeofday(&tv, NULL); 
   curtime=tv.tv_sec;
   strftime(sec,15,"%S.",localtime(&curtime)); 
   sprintf(sec, "%s%ld", sec, tv.tv_usec);

   return atof(sec);
}

/* ---- Threads ---------------------------------------------------------- */
void client_thread (void* ptr)
{
   int ret;
   double ret_d;
   udp_data_t *data=NULL;            
   timeval_t tv;
   time_t curtime;   
   data = (udp_data_t *) ptr;

   // Server host unreachable
   if(ping(data->ip) < 0)
   {
      pthread_exit(0);
   }

   data->udp.sockfd=socket(AF_INET,SOCK_DGRAM,0);
   bzero(&(data->udp.svr_addr),sizeof(data->udp.svr_addr));
   data->udp.svr_addr.sin_family = AF_INET;
   data->udp.svr_addr.sin_addr.s_addr=inet_addr(data->ip);
   data->udp.svr_addr.sin_port=htons(data->port);
   data->udp.load.seq=1;

   data->udp.load.msg = (unsigned char*) malloc (2200 * sizeof(unsigned char));
   data->udp.load.len = 2200;
   set_msg(data->udp.load.msg, 2200); 

  // printf("msg:%s\n", data->udp.load.msg);
   printf("\n------------------------------------------------------------\n");
   printf("Client connecting to %s, UDP port %i\n", data->ip, data->port);
   printf("Sending %d byte datagrams\n", sizeof(data->udp.load));
   printf("------------------------------------------------------------\n");
   printf("Seq\tSent\t\tBandwidth\n");
   while(data->udp.load.seq <= data->pkts)
   {
      ret = sendto(data->udp.sockfd, &(data->udp.load), 2200+sizeof(data->udp.load.seq)+sizeof(data->udp.load.len),
      MSG_DONTWAIT, (struct sockaddr*) &(data->udp.svr_addr), sizeof(data->udp.svr_addr));
      ret_d = (double) ret / 1000;
      printf("%i\t%.1fKB\n", data->udp.load.seq, ret_d);           
      data->udp.load.seq++;
   }
    
   pthread_exit(0);
}

void server_thread (void* ptr)
{
   int len=0,last_seq=0,n,lost=0,rcv=0;
   double rcv_rate=0.0,lost_rate=0.0;
   float sec=0.0,start=0.0, end=0.0;
   udp_data_t *data=NULL;    
        

   int a = 0;
   data = (udp_data_t *) ptr;

   data->udp.sockfd=socket(AF_INET,SOCK_DGRAM,0);
   bzero(&(data->udp.svr_addr),sizeof(data->udp.svr_addr));
   data->udp.svr_addr.sin_family = AF_INET;
   data->udp.svr_addr.sin_addr.s_addr=htonl(INADDR_ANY);
   data->udp.svr_addr.sin_port=htons(data->port);
   bind(data->udp.sockfd,(struct sockaddr *)&(data->udp.svr_addr), 
   sizeof(data->udp.svr_addr));
   printf("\n------------------------------------------------------------\n");
   printf("Server listening on port %i\n", data->port);
   printf("\nNote: 'Received' and 'Lost' columns are cumulative\n");
   printf("------------------------------------------------------------\n");
   printf("Seq\tSize\tReceived(%%)\tLost(%%)\t\tThroughput\n");

   data->udp.load.msg = (unsigned char*) malloc (2400*sizeof(unsigned char));
   while (1)
   {
   //   printf("sz: %i\n", 2200+sizeof(data->udp.load.seq)+sizeof(data->udp.load.len));
      strcpy(data->udp.load.msg, "");  
      len = sizeof(data->udp.cln_addr);
      n = recvfrom(data->udp.sockfd, &(data->udp.load), 2200+sizeof(data->udp.load.seq)+sizeof(data->udp.load.len),
      0, (struct sockaddr*) &(data->udp.cln_addr), &len);

      if(a == 0) {

      printf("msg: %s\n", data->udp.load.msg);
  a=1;
}


      sec = get_second();   
      if(data->udp.load.seq == 1)
      {
         start = sec;
         sec = get_second();
         end = sec;
      }
      else 
      {
         start = end;  
         end = sec;
//         printf("start:%.2f end:%.2f\n", start, end);
      }
      
      if(end > 0.0 && start != end)
      {
         if(end < start) 
            stat.time += start - end;
         else 
            stat.time += end - start;

//         printf("start:%.2f end:%.2f time:%.3f\n", start, end, stat.time);
/*         
         if(elapsed_sec == 0 && last_elapsed == 59) 
            data->elapsed_min++;
         else
            last_elapsed = data->elapsed_sec;

         total_time += data->elapsed_min * 60 + data->elapsed_sec;
*/
      }

      if(data->udp.load.seq == 0)
      {
         last_seq = 0;
         stat.rcv_pkts = 1;
         stat.lost_pkts = 0;
      }
      else
      {
         if(last_seq+1 != data->udp.load.seq)
            stat.lost_pkts += (data->udp.load.seq - last_seq);
         else
            stat.rcv_pkts++;
         last_seq = data->udp.load.seq;   
      }

      stat.mb += (float) n / 1000000;
      // Set Max Throughput
      if(stat.max_throughput == 0)
         stat.max_throughput = stat.mb/stat.time;
      else
         if((stat.mb/stat.time) > stat.max_throughput)
            stat.max_throughput = stat.mb/stat.time;

      // Set Min Throughput
      if(stat.min_throughput == 0)
         stat.min_throughput = stat.mb/stat.time;
      else
         if((stat.mb/stat.time) < stat.min_throughput)
            stat.min_throughput = stat.mb/stat.time;

      stat.pkts = data->udp.load.seq;
      rcv_rate = ((double) stat.rcv_pkts / (stat.rcv_pkts + stat.lost_pkts)) *100;
      lost_rate = ((double) stat.lost_pkts / (stat.rcv_pkts + stat.lost_pkts)) *100;

      // Set Min Packet Size
      if(stat.min_sz == 0) 
      {
         stat.min_sz = n;
         stat.min_sz = stat.min_sz / 1000;
      }
      else 
         if(n < stat.min_sz)
         {
            stat.min_sz = n;
            stat.min_sz = stat.min_sz / 1000;
         }

      // Set Max Packet Size
      if(stat.max_sz == 0)
      {
         stat.max_sz = n;
         stat.max_sz = stat.max_sz / 1000;
      }
      else
         if(n > stat.max_sz) 
         {
            stat.max_sz = n; 
            stat.max_sz = stat.max_sz / 1000;
         }

      // Set Avg Packet Size
      stat.avg_sz = stat.mb * 1000 / stat.rcv_pkts;

      // Set Min Receive %
      if(stat.min_rcv_rate == 0)
         stat.min_rcv_rate = rcv_rate;
      else
         if(rcv_rate < stat.min_rcv_rate)
            stat.min_rcv_rate = rcv_rate;
      stat.avg_rcv_rate = rcv_rate;
  
      // Set Max Lost %
      if(stat.max_lost_rate == 0)
         stat.max_lost_rate = lost_rate;
      else
         if(lost_rate > stat.max_lost_rate)
            stat.max_lost_rate = lost_rate;

      stat.avg_lost_rate = lost_rate;   
      stat.avg_throughput = stat.mb / stat.time;
      printf("%i\t%.1fKB\t%i(%.1f%%)\t%i(%.1f%%)\t\t%.2fMB/s\n", data->udp.load.seq, (double)n/1000, stat.rcv_pkts,rcv_rate,stat.lost_pkts,lost_rate, stat.mb/stat.time);  
   }

   pthread_exit(0);
}

/* ---- Main ---------------------------------------------------------- */
int main(int argc, char* argv [])
{  
   int i,j,ret=0,cnt=0;
   pthread_t cln_thr, svr_thr, cln_t_thr, svr_t_thr; 
   udp_data_t cln_data, svr_data;  

   char* token=NULL;      
   char* tmp=NULL;      
   char* foo = (char*) malloc (10*sizeof(char));
   printf("f:%i\n", sizeof(*foo));

   srand(time(NULL));
   cln_data.pkts = PACKETS;
   cln_data.port = PORT;
   svr_data.port = PORT;

   if(argc <= 1) 
   {
      usage();
   }
   else
   {
      // Generic Arguments
      for(i=0; i<argc; i++)
      {
         if(strcmp(argv[i], "-h")==0 || strcmp(argv[i], "--help")==0)
         {
            usage();
            ret=1;
            break;
         }    

         if(strcmp(argv[i], "-df")==0 || strcmp(argv[i], "--default")==0)
         {
            default_settings();
            ret=1;
            break;
         }    

         if(strcmp(argv[i], "-o")==0 || strcmp(argv[i], "--output")==0)
         {
         }    

         if(strcmp(argv[i], "-f")==0 || strcmp(argv[i], "--format")==0)
         {
         }    
      }

      // Client/Server Arguments
      for(i=0; i<argc; i++)
      {
         if(ret==1)
         {
            break;
         }

         if(strcmp(argv[i], "-s")==0 || strcmp(argv[i], "--server")==0)
         {  
            // Server specific arguments
            for(j=0; j<argc; j++) 
            {
               if(strcmp(argv[j], "-c")==0)
               {
                     fprintf(stderr, "Error: Specify endpoint as either client or server!\n");
                     exit(0);
               }

               if(strcmp(argv[j], "-p")==0 || strcmp(argv[j], "--port")==0)
               {
                  if((j+1) == argc)
                  {
                     fprintf(stderr, "Warning: Missing server port!\n");
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     svr_data.port= PORT;
                     goto port_end;
                  }                   

                  token = strchr(argv[j+1], '-');                
                  if(token)
                  {
                     fprintf(stderr, "Warning: Missing server port!\n");
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     svr_data.port= PORT;
                     goto port_end;
                  }
 
                  if(atoi(argv[j+1])==0 && strcmp(argv[j+1], "0")!=0 || strcmp(argv[j+1], "0")==0)
                  {
                     fprintf(stderr, "Warning: Invalid server port!\n");
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     svr_data.port= PORT;
                     goto port_end;
                  }

                  if(atoi(argv[j+1]) < 1024)
                  {
                     fprintf(stderr, "Warning: Server port %i may be used!\n", atoi(argv[j+1]));
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     svr_data.port= PORT;
                     goto port_end;
                  }

                  svr_data.port = atoi(argv[j+1]);
               } 

               if(strcmp(argv[i], "-D")==0 || strcmp(argv[i], "--daemon")==0)
               {
               } 
            }

            struct sigaction sigIntHandler;
            sigIntHandler.sa_handler = report;
            sigemptyset(&sigIntHandler.sa_mask);
            sigIntHandler.sa_flags = 0;
            sigaction(SIGINT, &sigIntHandler, NULL);

            pthread_create (&svr_thr, NULL, (void *) &server_thread, (void*) &svr_data);
            pthread_join(svr_thr, NULL); 
            break;
         } 

         if(strcmp(argv[i], "-c")==0 || strcmp(argv[i], "--client")==0)
         {
            if((i+1) == argc)
            {
               fprintf(stderr, "Error: Missing server IP address!\n");
               exit(0);
            }

            // Client specific arguments
            for(j=0; j<argc; j++) 
            {


               if(strcmp(argv[j], "-s")==0)
               {
                     fprintf(stderr, "Error: Specify endpoint as either client or server!\n");
                     exit(0);
               }

               if(strcmp(argv[j], "-p")==0 || strcmp(argv[j], "--port")==0)
               {
                  if((j+1) == argc)
                  {
                     fprintf(stderr, "Warning: Missing server port!\n");
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     cln_data.port= PORT;
                     goto port_end;
                  }                   

                  token = strchr(argv[j+1], '-');                
                  if(token)
                  {
                     fprintf(stderr, "Warning: Missing server port!\n");
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     cln_data.port= PORT;
                     goto port_end;
                  }
 
                  if(atoi(argv[j+1])==0 && strcmp(argv[j+1], "0")!=0 || strcmp(argv[j+1], "0")==0)
                  {
                     fprintf(stderr, "Warning: Invalid server port!\n");
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     cln_data.port= PORT;
                     goto port_end;
                  }

                  if(atoi(argv[j+1]) < 1024)
                  {
                     fprintf(stderr, "Warning: Server port %i may be used!\n", atoi(argv[j+1]));
                     fprintf(stderr, "Warning: Setting server port %i\n", PORT);
                     cln_data.port= PORT;
                     goto port_end;
                  }

                  cln_data.port = atoi(argv[j+1]);
               } 
port_end:
               // Set total packets sent
               if(strcmp(argv[j], "-n")==0)
               {            
                  if((j+1) == argc)
                  {
                     fprintf(stderr, "Warning: Missing total sequence number!\n");
                     fprintf(stderr, "Warning: Sending 250 UDP packets\n");
                     cln_data.pkts = PACKETS;
                     goto n_end;
                  }                   

                  token = strchr(argv[j+1], '-');                
                  if(token)
                  {
                     fprintf(stderr, "Warning: Missing total sequence number!\n");
                     fprintf(stderr, "Warning: Sending 250 UDP packets\n");
                     cln_data.pkts = PACKETS;
                     goto n_end;
                  }
 
                  if(atoi(argv[j+1])==0 && strcmp(argv[j+1], "0")!=0 || strcmp(argv[j+1], "0")==0)
                  {
                     fprintf(stderr, "Warning: Invalid total sequence number!\n");
                     fprintf(stderr, "Warning: Sending 250 UDP packets\n");
                     cln_data.pkts = PACKETS;
                     goto n_end;
                  }

                  if(atoi(argv[j+1]) <= PACKETS)
                  {
                     fprintf(stderr, "Warning: Total sequence number is too small!\n");
                     fprintf(stderr, "Warning: Sending 250 UDP packets\n");
                     cln_data.pkts = PACKETS;
                     goto n_end;
                  }

                  cln_data.pkts = atoi(argv[j+1]);
               } 

n_end:

               if(strcmp(argv[j], "-t")==0 || strcmp(argv[j], "--time")==0)
               {
               } 

               if(strcmp(argv[j], "-i")==0 || strcmp(argv[j], "--stdin")==0)
               {
               } 

               // Set Server IP Address
               if(strcmp(argv[j], "-ip")==0)
               {
                  if(j == (argc-1))   
                  {
                     fprintf(stderr, "Error: Missing server IP address!\n");
                     exit(0);
                  }

                  token = strchr(argv[j+1], '-');
                
                  if(token)
                  {
                     fprintf(stderr, "Error: Missing server ip address!\n");
                     exit(0);
                  }
                  
                  tmp = (unsigned char*) malloc (alloc_strlen(argv[j+1])*sizeof(unsigned char));
                  strcpy(tmp, argv[j+1]);
                  token = strchr(tmp, '.');
                  if(!token)
                  {
                     fprintf(stderr, "Error: Invalid IP address format\n");
                     exit(0);
                  }          

                  token = strtok(tmp, IP_DELIM); 
                  while( token != NULL ) 
                  {
                     cnt++;
                     //TODO: Missing check for the case of "10afew.10", result in IP_COUNT error
                     if(atoi(token)==0 && strcmp(token, "0")!=0)
                     {
                        fprintf(stderr, "Error: Non-integer found in IP address in octet %i!\n", (cnt+1));
                        exit(0);
                     }
                     
                      token = strtok(NULL, IP_DELIM);
                  }
 
                  if(cnt != OCTETS)
                  {
                     fprintf(stderr, "Error: Missing %i octet(s) in IP address!\n", (OCTETS-cnt));
                     exit(0);
                  }
 
                  cln_data.ip = (unsigned char*) malloc (alloc_strlen(argv[j+1])*sizeof(unsigned char));
                  strcpy(cln_data.ip, argv[j+1]);          
               } 

               if(strcmp(argv[j], "-sz")==0 || strcmp(argv[j], "--size")==0)
               {
                  if((j+1) == argc)
                  {
                     fprintf(stderr, "Warning: Missing packet size!\n");
                     fprintf(stderr, "Warning: Sending 2400 KB packets\n");
                     cln_data.sz = MSG_LEN;
                     goto sz_end;
                  }                   

                  token = strchr(argv[j+1], '-');                
                  if(token)
                  {
                     fprintf(stderr, "Warning: Missing packet size!\n");
                     fprintf(stderr, "Warning: Sending 2400 KB packets\n");
                     cln_data.sz = MSG_LEN;
                     goto sz_end;
                  }
 
                  if(atoi(argv[j+1])==0 && strcmp(argv[j+1], "0")!=0 || strcmp(argv[j+1], "0")==0)
                  {
                     fprintf(stderr, "Warning: Invalid packet size!\n");
                     fprintf(stderr, "Warning: Sending 2400 KB packets\n");
                     cln_data.sz = MSG_LEN;
                     goto sz_end;
                  }

                  if(atoi(argv[j+1]) <= MIN_MSG_LEN)
                  {
                     fprintf(stderr, "Warning: Packet size is smaller than min (%i KB)!\n", MIN_MSG_LEN);
                     fprintf(stderr, "Warning: Sending 2400 KB packets\n");
                     cln_data.sz = MSG_LEN;
                     goto sz_end;
                  }

                  // Random packet size mode
                  if(atoi(argv[j+1])==0 && strcmp(argv[j+1], "r")==0)
                  {
                     goto sz_end;
                  }

                  cln_data.sz = atoi(argv[j+1]);
               } 
sz_end:
               if(strcmp(argv[j], "-p")==0 || strcmp(argv[j], "--parallel")==0)
               {
               } 
            } 
            
            pthread_create (&cln_thr, NULL, (void *) &client_thread, (void*) &cln_data);
            pthread_join(cln_thr, NULL); 
            break;
         } 
      }
   }


end:

   free(tmp);
   free(token);
   token=NULL;
   tmp=NULL;
   exit(0);
}

