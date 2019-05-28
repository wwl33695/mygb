
#ifndef WIN32
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <unistd.h>
	#include <fcntl.h>
	#include <errno.h>
#else
	#include <winsock2.h>
#endif // WIN32

#include "mysip.h"

#define PS_BUF_SIZE         (1024*1024*4)

typedef struct RTP_HEADER
{
	uint16_t cc : 4;
	uint16_t extbit : 1;
	uint16_t padbit : 1;
	uint16_t version : 2;
	uint16_t paytype : 7;  //负载类型
	uint16_t markbit : 1;  //1表示前面的包为一个解码单元,0表示当前解码单元未结束
	uint16_t seq_number;  //序号
	uint32_t timestamp; //时间戳
	uint32_t ssrc;  //循环校验码
	//uint32_t csrc[16];
} RTP_header_t;

#define APP_ERR printf

//////////////////////////////////////////////////////////////////////
//初始化udp套接字
int init_udpsocket(int port)
{
	int err = -1;
	int socket_fd;

	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)
	{
		APP_ERR("socket failed, port:%d", port);
		return -1;
	}
	
    /* Set socket option */
    int flag = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int)) < 0) {
        perror("setsockopt()");
        return -1;
    }


    // 设置UDP服务Socket为非阻塞模式
    int sockflag;
    if ((sockflag = fcntl(socket_fd, F_GETFL, 0)) < 0)
    {
        printf("openServer: get socket(%d) flag error=%d(%s)", socket_fd, errno, strerror(errno));
        return -1;
    }
    sockflag = sockflag | O_NONBLOCK;
    if (fcntl(socket_fd, F_SETFL, sockflag) < 0)
    {
        printf("openServer: set socket(%d) flag error=%d(%s)", socket_fd, errno, strerror(errno));
        return -1;
    }


//    vi /etc/sysctl.conf，添加一行
//	net.core.rmem_max = 4194304
//	sysctl -p，使参数生效。再次启动程序，可以看到缓冲也跟着增大了
	
	/*set enable MULTICAST LOOP */
	int loop = 2*1024*1024;
	socklen_t optlen = sizeof(loop);
	err = setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, (const char*)&loop, optlen);
	if (err < 0)
	{
		APP_ERR("setsockopt failed \n");
		return -1;
	}
    int rcvRealSize = -1;
    if (getsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &rcvRealSize, &optlen) < 0)
    {
		APP_ERR("getsockopt failed \n");
        return -1;
    }
	APP_ERR("getsockopt rcvRealSize:%d \n", rcvRealSize);

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	err = bind(socket_fd, (struct sockaddr*)&servaddr, sizeof(struct sockaddr_in));
	if (err < 0)
	{
		APP_ERR("bind failed, port:%d", port);
		return -1;
	}

	return socket_fd;
}

//关闭套接字
void release_udpsocket(int socket_fd)
{
	close(socket_fd);
}

int select_udpsocket(int socket_fd)
{
    static fd_set fds;
    FD_ZERO(&fds);
    FD_SET(socket_fd, &fds);

    static struct timeval tv = {0, 20000};
    int readyNum = select(socket_fd+1, &fds, NULL, NULL, &tv);
    if (readyNum < 0)
    {
        printf("monUdpSock: select error=%d(%s)!!!\n", errno, strerror(errno));
        // 异常处理
        return -1;
    }
    else if (readyNum == 0)
        return -1; // select超时，do nothing

    return 0;
}

int recv_udpsocket(int socket_fd, char* rtpbuf, int buflen)
{
	//接收到的rtp流数据长度
	struct sockaddr_in servaddr;
	socklen_t addr_len = sizeof(struct sockaddr_in);

	return recvfrom(socket_fd, rtpbuf, buflen, 0, (struct sockaddr*)&servaddr, &addr_len);
}

///////////////////////////////////////////////////////////////////////////////////
#include <event.h>
#include <event2/listener.h>

void read_cb(int fd, short event, void *arg) 
{
	CameraParams *p = (CameraParams *)arg;

	RTPData packdata;
	int recvLen = recv_udpsocket(p->sock_fd, packdata.data, sizeof(packdata.data));
//	printf("recvfrom, recvLen=%d event=%d \n",recvLen, event);

	//如果接收到字字段长度还没有rtp数据头长，就直接将数据舍弃
	if (recvLen > 12)
	{
//			ParsePsStream(psBuf, psLen, (char*)rtpbuf+12, recvLen-12, p);
		//写入文件
//			fwrite(packdata.data+12, 1, recvLen-12, p->fpH264);
		packdata.length =  recvLen;
		
		p->queueMutex.lock();
		p->queueData.push(packdata);
		p->queueMutex.unlock();
	}
}

int runeventloop(int port, void *arg) {
    struct event  ev;

    /* Init. event */
    if (event_init() == NULL) {
        printf("event_init() failed\n");
        return -1;
    }

    int sock_fd = init_udpsocket(port);
    if( sock_fd < 0 )
    {
        printf("init_udpsocket failed\n");
        return -1;
    }
	CameraParams *p = (CameraParams *)arg;
	p->sock_fd = sock_fd;
	
	evutil_make_socket_nonblocking(sock_fd);

    /* Init one event and add to active events */
    event_set(&ev, sock_fd, EV_READ | EV_PERSIST, &read_cb, arg);
//    event_set(&ev, sock_fd, EV_READ | EV_PERSIST | EV_ET, &read_cb, arg);
    if (event_add(&ev, NULL) == -1) {
        printf("event_add() failed\n");
    }

    /* Enter event loop */
    event_dispatch();

    return 0;
}
////////////////////////////////////////////////////////////////////////////
int ParsePsStream(char* psBuf, uint32_t &psLen, char* rtpPayload, uint32_t rtpPayloadLength, CameraParams *p)
{
	static uint32_t cnt = 0;
	if (rtpPayloadLength <= 0)
	{
		perror("recvfrom() long");
		return -1;
	}

	char* ptr = psBuf + psLen;			//最新数据的头
	if (psLen + rtpPayloadLength < PS_BUF_SIZE)
	{
		memcpy(ptr, rtpPayload, rtpPayloadLength);
	}
	else
	{
		printf("psBuf memory overflow, %d\n", psLen + rtpPayloadLength);
		psLen = 0;
		return -1;
	}

	//视频流解析
	if (psLen > 0 && 
		ptr[0] == 0x00 && ptr[1] == 0x00 && ptr[2] == 0x01 && ptr[3] == 0xffffffBA)
	{
		if (cnt % 25 == 0)
		{
			p->status = 1;
		}

		p->parser.Parse(psBuf, psLen);
	
		char *packet = NULL;
		uint32_t packetsize = 0;
		if( p->parser.getpacket(&packet, &packetsize) >= 0 )
		{
			if( p->fpH264 )
				fwrite(packet, 1, packetsize, p->fpH264);
//			else
//				p->decoder.SetPacketData((uint8_t*)packet, packetsize);
		}

		memcpy(psBuf, ptr, rtpPayloadLength);
		psLen = 0;
		cnt++;
	}
	psLen += rtpPayloadLength;

	return 0;
}

int getrandomport(uint16_t &port)
{
/*
	jrtplib::RTPRandomURandom _rand;
	if( _rand.Init() < 0 )
		return -1;

	port = _rand.GetRandom16();
	port -= port % 2;
	port %= 50000 ;
	if( port < 10000 )
		port += 10000;
*/
	return 0;
}
/*
int getrtpsession(jrtplib::RTPSession &sess, int &rtpport)
{
	uint16_t portbase;
	int i, num;

	jrtplib::RTPUDPv4TransmissionParams transparams;
	transparams.SetRTPReceiveBuffer(1 * 1024 * 1024);

	jrtplib::RTPSessionParams sessparams;
	sessparams.SetOwnTimestampUnit(1.0 / 90000.0);
	sessparams.SetAcceptOwnPackets(true);
	
	uint16_t localport = 16000;
	if( getrandomport(localport) < 0 )
	{
		printf("getrandomport error \n");
		return -1;
	}

	sess.Destroy();
	for (uint16_t i = localport; i < 65000; i+=2)
	{
		transparams.SetPortbase(i);
		int status = sess.Create(sessparams, &transparams);
		if (status >= 0)
		{
			rtpport = i;
			return 0;
		}
		//printf("getrtpsession error: %d, %s \n", status, jrtplib::RTPGetErrorString(status).c_str() );
		printf("getrtpsession error: %d port=%d \n", status, i);
		sess.Destroy();
	}
	return -1;
}
*/
int checkErrorCount(CameraParams *p, int &error_count)
{
	if( error_count == 7 * 1000 )
	{
		printf("stream connection error: sendPlayBye \n");
		sendPlayBye(p->pliveVideoParams, p);
	}
	else if( error_count >= 10 * 1000 )
	{
		printf("stream connection error: sendInvitePlay \n");
/*
		if( getrtpsession(p->sess, p->recvPort) < 0 )
		{
			printf("[checkErrorCount]  getrtpsession error \n");
			return -1;
		}
*/
		sendInvitePlay(p->pliveVideoParams, p);
		error_count = 0;

		return 0;
	}

	return -1;
}

int parse_thread(void *arg)
{
    pthread_setname_np(pthread_self(), "parse_thread");

	//获取相机参数
	CameraParams *p = (CameraParams *)arg;
	while (p->running)
	{
		RTPData packdata = {0};

		p->queueMutex.lock();
		if( p->queueData.empty() )
		{
			p->queueMutex.unlock();
	
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
			continue;
		}

		packdata = p->queueData.front();
		p->queueData.pop();
		p->queueMutex.unlock();

		fwrite(packdata.data+12, 1, packdata.length-12, p->fpH264);
	}
	
	return 0;
}

//接收相机回传的rtp视频流
int rtp_recv_thread(void *arg)
{
    pthread_setname_np(pthread_self(), "rtp_recv_thread");

	//获取相机参数
	CameraParams *p = (CameraParams *)arg;
	
	//写入视频文件
	//获取当前程序路径
	char filename[MAX_PATH];
	std::string strPath = p->sipId;
	snprintf(filename, MAX_PATH, "%s.264", strPath.c_str());
	if( p->writefile )
		p->fpH264 = fopen(filename, "wb");

	if (p->fpH264 == NULL)
	{
		printf("fopen %s failed \n", filename);
	}

//	runeventloop(p->recvPort, arg);

	int socket_fd = init_udpsocket(p->recvPort);
	if (socket_fd < 0)
	{
		printf("init_udpsocket error: port %d \n", p->recvPort);
		return -1;
	}

	char *psBuf = (char *)malloc(PS_BUF_SIZE);
	if (psBuf == NULL)
	{
		//APP_ERR("malloc failed");
		printf("malloc failed \n");
		return -1;
	}
	memset(psBuf, 0, PS_BUF_SIZE);
	uint32_t psLen = 0;

#ifdef WIN32
	WSADATA dat;
	WSAStartup(MAKEWORD(2, 2), &dat);
#endif // WIN32

	char rtpbuf[1600] = {0};
	while (p->running)
	{	
		if( select_udpsocket(socket_fd) < 0 )
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
			continue;
		}

		while( 1 )
		{		
			RTPData packdata;
			int recvLen = recv_udpsocket(socket_fd, packdata.data, sizeof(packdata.data));
			printf("recvfrom, recvLen=%d \n",recvLen);

			//如果接收到字字段长度还没有rtp数据头长，就直接将数据舍弃
			if (recvLen > 12)
			{
	//			ParsePsStream(psBuf, psLen, (char*)rtpbuf+12, recvLen-12, p);
				//写入文件
	//			fwrite(packdata.data+12, 1, recvLen-12, p->fpH264);
				packdata.length =  recvLen;
				
				p->queueMutex.lock();
				p->queueData.push(packdata);
				p->queueMutex.unlock();
			}
			else
				break;
		}
	}

	release_udpsocket(socket_fd);

#ifdef WIN32
	WSACleanup();
#endif // WIN32

//	p->decoder.Stop();

	if( p->fpH264 )
	{
		fclose(p->fpH264);
		p->fpH264 = NULL;
	}

	if( psBuf )
	{
		free(psBuf);
		psBuf = NULL;
	}

	return 0;
}

//////////////////////////////////////////////////////////////////////////////////

void *gb28181_init(char* localip, int localport, char *localsipid)
{
	struct eXosip_t *sipctx = mysip_init(localport);
	if (!sipctx)
		return NULL;

	liveVideoStreamParams *inst = new liveVideoStreamParams;
	if (!inst)
	{
		mysip_uninit(sipctx);
		return NULL;
	}

	inst->gb28181Param.running = 1;
	inst->gb28181Param.eCtx = sipctx;
	strcpy(inst->gb28181Param.localSipId, localsipid);
	strcpy(inst->gb28181Param.localIpAddr, localip);
	inst->gb28181Param.localSipPort = localport;
	
	inst->gb28181Param.msgthread = std::thread(MsgThreadProc, inst);

	return inst;
}

int gb28181_startstream(void *handle, char* deviceip, int gpu, int record2file)
{
	if (!handle || !deviceip)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;

	CameraParams *param = NULL;
	if (getdeviceinfo(inst, deviceip, &param) < 0)
	{
		printf("getdeviceinfo error \n");
		return -1;
	}
/*
	if( !param->decoder.GetCodec(27, gpu) )
	{
		printf("GetCodec error \n");
		return -1;		
	}

	if (getrtpsession(param->sess, param->recvPort) < 0)
	{
		printf("getrtpsession error \n");
		return -1;
	}
*/
	
	param->recvPort = 16000;

	param->running = 1;
	param->status = 0;
	param->statusErrCnt = 0;
	param->writefile = record2file;//1;

	sendInvitePlay(inst, param);

//	param->rtpthread = std::thread(jrtplib_rtp_recv_thread, (void*)param);
	param->rtpthread = std::thread(rtp_recv_thread, (void*)param);
	param->parsethread = std::thread(parse_thread, (void*)param);

	return 0;
}

int gb28181_stopstream(void *handle, char* deviceip)
{
	if (!handle || !deviceip)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;

	CameraParams *param = NULL;
	if (getdeviceinfo(inst, deviceip, &param) < 0)
	{
		printf("getdeviceinfo error \n");
		return -1;
	}

	param->running = 0;
	param->status = 0;
	param->statusErrCnt = 0;
	param->rtpthread.join();

	sendPlayBye(inst, param);
	return 0;
}

int gb28181_getregisterstatus(void *handle, char* deviceip)
{
	if (!handle || !deviceip)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;
	CameraParams *param = NULL;
	if (getdeviceinfo(inst, deviceip, &param) < 0)
	{
		printf("getdeviceinfo error \n");
		return -1;
	}

	return 0;
}

int gb28181_getinfo(void *handle, char* deviceip, int *width, int *height)
{
	if (!handle || !deviceip)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;
	CameraParams *param = NULL;
	if (getdeviceinfo(inst, deviceip, &param) < 0)
	{
		printf("getdeviceinfo error \n");
		return -1;
	}
/*
	if( !param->decoder.GetInfo(width, height) )
	{
		printf("GetRGBData error \n");
		return -1;		
	}
*/
	return 0;
}

int gb28181_getrgbdata(void *handle, char* deviceip, uint8_t *data, int width, int height)
{
	if (!handle || !deviceip)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;
	CameraParams *param = NULL;
	if (getdeviceinfo(inst, deviceip, &param) < 0)
	{
		printf("getdeviceinfo error \n");
		return -1;
	}
/*
	if( !param->decoder.GetRGBData(data, width, height) )
	{
//		printf("GetRGBData error \n");
		return -1;		
	}
*/
	return 0;
}

int gb28181_uninit(void *handle)
{
	if (!handle)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;
	inst->gb28181Param.running = 0;
	inst->gb28181Param.msgthread.join();

	mysip_uninit(inst->gb28181Param.eCtx);
	delete inst;

	return 0;
}
