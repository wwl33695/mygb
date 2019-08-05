#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/socket.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <netinet/sctp.h>  
#include <arpa/inet.h>  
// #include "common.h"  
#define MAX_BUFFER 256   
#define MY_PORT_NUM 2222  
#define LOCALTIME_STREAM 256  
#define GMT_STREAM 256  
int main()  
{  
  int connSock, in, i, ret, flags;  
  struct sockaddr_in servaddr;  
  struct sctp_status status;  
  struct sctp_sndrcvinfo sndrcvinfo;  
  struct sctp_event_subscribe events;  
  struct sctp_initmsg initmsg;  
  char buffer[MAX_BUFFER+1];  
        struct sctp_sndrcvinfo sinfo;
    char* msg = "hello world.\n";

	struct sockaddr_in peeraddr;

  /* Create an SCTP TCP-Style Socket */  
  connSock = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP );  
  
  /* Specify that a maximum of 5 streams will be available per socket */  
  memset( &initmsg, 0, sizeof(initmsg) );  
  initmsg.sinit_num_ostreams = 100;  
  initmsg.sinit_max_instreams = 100;  
//  initmsg.sinit_max_attempts = 4;  
  ret = setsockopt( connSock, IPPROTO_SCTP, SCTP_INITMSG,  
                     &initmsg, sizeof(initmsg) );  
  
  /* Specify the peer endpoint to which we'll connect */  
  bzero( (void *)&servaddr, sizeof(servaddr) );  
  servaddr.sin_family = AF_INET;  
  servaddr.sin_port = htons(MY_PORT_NUM);  
  servaddr.sin_addr.s_addr = inet_addr( "127.0.0.1" );  
  
  /* Connect to the server */  
  ret = connect( connSock, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));  
  
  /* Enable receipt of SCTP Snd/Rcv Data via sctp_recvmsg */  
/*
  memset( (void *)&events, 0, sizeof(events) );  
  events.sctp_data_io_event = 1;  
  ret = setsockopt( connSock, IPPROTO_SCTP, SCTP_EVENTS,  
                     (const void *)&events, sizeof(events) );  
*/

  /* Read and emit the status of the Socket (optional step) */  
  in = sizeof(status);  
    status.sstat_assoc_id = 1;
  ret = getsockopt( connSock, IPPROTO_SCTP, SCTP_STATUS,  
                     (void *)&status, (socklen_t *)&in );  
  
  printf("assoc id = %d\n", status.sstat_assoc_id );  
  printf("state = %d\n", status.sstat_state );  
  printf("instrms = %d\n", status.sstat_instrms );  
  printf("outstrms = %d\n", status.sstat_outstrms );  
  
  bzero(&sinfo,sizeof(sinfo));
  sinfo.sinfo_stream = 0;
  sctp_send(connSock, msg, strlen(msg), &sinfo, 0);
  sinfo.sinfo_flags = SCTP_EOF;
  sctp_send(connSock,NULL,0,&sinfo,0);

/*
//	usleep(3000 * 1000); 
  while( 1 ) 
  {  
    	int len = sizeof(peeraddr);
      in = sctp_recvmsg( connSock, (void *)buffer, sizeof(buffer),  
                          (struct sockaddr *)&peeraddr, &len, &sndrcvinfo, &flags );  

      perror("Error: ");
    	printf("sctp_recvmsg %d %d \n", in, connSock);

      if (in > 0) {  
          buffer[in] = 0;  
          printf("%s\n", buffer);  
          printf("%d\n", sndrcvinfo.sinfo_stream);  
          break;
      }  

      usleep(100 * 1000); 
  }  
*/
  /* Close our socket and exit */  
  close(connSock);  
  
	printf("close \n");

  return 0;  
}
