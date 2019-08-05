#include <signal.h>  

#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <time.h>  
#include <sys/socket.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <netinet/sctp.h>  
// #include "common.h"  
#define MAX_BUFFER 256   
#define MY_PORT_NUM 2222  
#define LOCALTIME_STREAM 256  
#define GMT_STREAM 256  

int init_sctp(int fd)
{
    struct sctp_initmsg initmsg;  
    memset( &initmsg, 0, sizeof(initmsg) );  
    initmsg.sinit_num_ostreams = 100;  
    initmsg.sinit_max_instreams = 100;  
    //  initmsg.sinit_max_attempts = 4;  
    int ret = setsockopt( listenSock, IPPROTO_SCTP, SCTP_INITMSG,   
                       &initmsg, sizeof(initmsg) );  
    if( ret <  0 )
    {
        printf("SCTP_INITMSG error \n");
        return -1;
    }

    return 0;
}

int send_sctp(int fd, char *buffer, int buflen, int closesctp = false)
{
    struct sctp_sndrcvinfo sinfo;
    bzero(&sinfo,sizeof(sinfo));
    sinfo.sinfo_stream = 12;
    if( closesctp )
      sinfo.sinfo_flags = SCTP_EOF;      

    sctp_send(fd, buffer, buflen, &sinfo, 0);

    return 0;
}

int send2_sctp(int fd, char *buffer, int buflen, struct sockaddr_in *client_addr)
{
    int len = sizeof(struct sockaddr_in);
    int ret = sctp_sendmsg( fd, buffer, buflen,  
                         (struct sockaddr*)client_addr, len, 0, 0, 12, 0, 0 );
    if( ret < 0 )
    {  
        printf("ret=%d %d \n", ret, fd);
        perror("Error: "); 
        return -1;
    }

    return 0;
}

int recv_sctp(int fd, char* buffer, int buflen, struct sockaddr_in* client_addr, int *len, 
      struct sctp_sndrcvinfo *sndrcvinfo, int *flags)
{
    int ret = sctp_recvmsg(fd, buffer, buflen,  
                  (struct sockaddr *)client_addr, len, sndrcvinfo, flags); 
    if( ret < 0 )
    {  
        printf("ret=%d %d \n", ret, fd);
        perror("Error: "); 
        return -1;
    }

    return 0;
}

int main()  
{  
  int listenSock, connSock, ret, flags;  
  struct sctp_status status;  
  struct sockaddr_in servaddr, client_addr;  
  struct sctp_initmsg initmsg;  
  char buffer[MAX_BUFFER+1];  
  time_t currentTime;  
      struct sctp_sndrcvinfo sinfo;
    char* msg = "hello world.\n";
  struct sctp_sndrcvinfo sndrcvinfo;  
  
  signal(SIGPIPE, SIG_IGN);

  /* Create SCTP TCP-Style Socket */  
  listenSock = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP );  
  
  /* Accept connections from any interface */  
  bzero( (void *)&servaddr, sizeof(servaddr) );  
  servaddr.sin_family = AF_INET;  
  servaddr.sin_addr.s_addr = INADDR_ANY;  
  servaddr.sin_port = htons(MY_PORT_NUM);  
  
//  ret = bind( listenSock, (struct sockaddr *)&servaddr, sizeof(servaddr) );  
  ret = sctp_bindx(listenSock,(struct sockaddr*)&servaddr,
                1,SCTP_BINDX_ADD_ADDR);

  init_sctp(listenSock);
 
  /* Place the server socket into the listening state */  

  listen( listenSock, 5 );  

  while( 1 ) {  
  
    printf("Awaiting a new connection\n");  
    int len = sizeof(client_addr);
    connSock = accept( listenSock, (struct sockaddr *)&client_addr, &len);  

    int in = sizeof(status);  
    status.sstat_assoc_id = 0;
    ret = getsockopt( connSock, IPPROTO_SCTP, SCTP_STATUS,  
                     &status, &in );  

    len = sizeof(client_addr);
    len = sizeof(&sndrcvinfo,sizeof(sndrcvinfo));
    in = sctp_recvmsg( connSock, (void *)buffer, sizeof(buffer),  
                        (struct sockaddr *)&client_addr, &len, &sndrcvinfo, &flags );  
  
    perror("Error: ");
    printf("sctp_recvmsg %d %d \n", in, connSock);

    if (in > 0) {  
      buffer[in] = 0;  
      printf("%s\n", buffer);  
      printf("%d\n", sndrcvinfo.sinfo_stream);  
    }  
  
  }  


  /* Server loop... */  
  while( 1 ) {  
  
    /* Await a new client connection */  
    printf("Awaiting a new connection\n");  
    int len = sizeof(client_addr);
    connSock = accept( listenSock, (struct sockaddr *)&client_addr, &len);  
/*
    bzero(&sinfo,sizeof(sinfo));
    sinfo.sinfo_stream = 12;
    sctp_send(connSock, msg, strlen(msg), &sinfo, 0);
    sinfo.sinfo_flags = SCTP_EOF;
    sctp_send(connSock,NULL,0,&sinfo,0);
*/

/*
    currentTime = time(NULL);  
  
    snprintf( buffer, MAX_BUFFER, "%s\n", ctime(&currentTime) );  
    ret = sctp_sendmsg( connSock, (void *)buffer, (size_t)strlen(buffer),  
                         (struct sockaddr*)&client_addr, len, 0, 0, 0, 0, 0 );  
 	printf("ret=%d %d \n", ret, connSock);
      perror("Error: "); 
*/
/*
    snprintf( buffer, MAX_BUFFER, "%s\n", asctime( gmtime( &currentTime ) ) );  
    ret = sctp_sendmsg( connSock, (void *)buffer, (size_t)strlen(buffer),  
                         (struct sockaddr*)&client_addr, &len, 0, 0, GMT_STREAM, 0, 0 );  
 	printf("ret=%d %d \n", ret, connSock);
        perror("Error: ");
*/
    /* Close the client connection */  
    close( connSock );  
  }  
  
  return 0;  
}
