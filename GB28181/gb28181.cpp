
/*
GB2818������sipͨѶ��RTP��װ��PS����װ,ʵ������ȻGB28181������3����Ŀ
һ������SIP��GB28181��ֻ�Ǽ����˿�Դ��eXosip2��osip2


������ش���Ƶ
struct RTPHeader
{
uint8_t csrccount:4;
uint8_t extension:1;
uint8_t padding:1;
uint8_t version:2;
uint8_t payloadtype:7;
uint8_t marker:1;
uint16_t sequencenumber;
uint32_t timestamp;
uint32_t ssrc;
};
ϸ���Ƚϸ��ӣ���ʵ����һ��12�ֽڵ�ͷ��������av���ݡ���Ҫע�����¼�����ʶ
Marker:���Ϊ1��������֡�Ѿ�����,Ϊ0��ʾ�����ӵ�����Ƶ����
Sequencenumber:RTP��˳�򣬱���һ֡K֡,200K,˳�������0-199�����һ����MarkerλΪ1��
Ssrc��Ϊ����ʶ��ʵ�ʿ��Զ������һ���˿��Ϸ���ͨ����λ��ʶ��
Payloadlength:Ϊ�ð��ĳ���,�����ǰ��İ�����ֵͨ��Ϊ1024�����һ������Ϊ�ܳ���1024������
Payloadoffset:ͨ��Ϊ12��rtpͷ��Ϣ��
Timestamp:���ֵ����ÿ֡��ʱ���������һ����Ƶ����Ƶ����������ͬ�ġ�

ps��
���ɸ�PS�������һ��AV����Marker��ʶһ֡����������00��00��01�ڸ��ֽڹ̶���ͷ��������Ҫ6���ֽڣ����ݵ�4���ֽ��ж�����Ƶ֡������Ƶ֡
0xBA :I֡(�ؼ�֡)�����滹����8�ֽڵ�ps pack header��Ϣ����ps pack header��Ϣ����Ϊ14�ֽڡ�
0xBB: // ps system header <18�ֽ�>
0xBC:// ps map header <30�ֽ�>
0xC0:// ��Ƶͷ
0xE0: //��Ƶͷ <19�ֽ�>
�����ݸ��ֽڽ���������Ƶ����ʵ�ʳ��ȡ�����һ��I֡Ϊ64400��������64400/1024=63����ȫ�Ǹ�I֡���ݡ���Ƶ֡Ҫ��һЩ��û��ps header��map header.

udp������Ƶ
*/


#include "rtpsession.h"
#include "rtppacket.h"
#include "rtpudpv4transmitter.h"
#include "rtpipv4address.h"
#include "rtpsessionparams.h"
#include "rtperrors.h"
#include "rtpsourcedata.h"

#ifndef WIN32
	#include <netinet/in.h>
	#include <arpa/inet.h>
#else
	#include <winsock2.h>
#endif // WIN32

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <mxml.h>
#include <time.h>
#include <process.h>
#include <eXosip2/eXosip.h>
#include "filenameio.h"

using namespace jrtplib;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mxml1.lib")
#pragma comment(lib, "eXosip.lib")
#pragma comment(lib, "libcares.lib")
#pragma comment(lib, "osip2.lib")

//Dnsapi.lib;Iphlpapi.lib;ws2_32.lib;eXosip.lib;osip2.lib;osipparser2.lib;Qwave.lib;libcares.lib;delayimp.lib;
//���� libcmt.libĬ�Ͽ�
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "osipparser2.lib")
#pragma comment(lib, "Qwave.lib")
#pragma comment(lib, "delayimp.lib")

#ifdef DEBUG
#pragma comment(lib, "jrtplib_d.lib") 
#pragma comment(lib,"jthread_d.lib")
#pragma comment(lib,"WS2_32.lib")
#else
#pragma comment(lib, "jrtplib.lib") 
#pragma comment(lib,"jthread.lib")
#pragma comment(lib,"WS2_32.lib")
#endif

#define CAMERA_SUPPORT_MAX      500
#define RTP_MAXBUF          4096
#define PS_BUF_SIZE         (1024*1024*4)
#define H264_FRAME_SIZE_MAX (1024*1024*2)

typedef struct _gb28181Params{
	char platformSipId[MAX_PATH];
	char platformIpAddr[MAX_PATH];
	int platformSipPort;
	char localSipId[MAX_PATH];
	char localIpAddr[MAX_PATH];
	int localSipPort;
	int SN;
	struct eXosip_t *eCtx;
	int call_id;
	int dialog_id;
	int registerOk;
	int running;
} gb28181Params;

typedef struct {
	char sipId[MAX_PATH];
	char UserName[MAX_PATH];
	char UserPwd[MAX_PATH];
	int recvPort;
	int status;
	int statusErrCnt;
	FILE *fpH264;
	int running;
} CameraParams;

typedef struct _liveVideoStreamParams{
	int cameraNum;
	CameraParams *pCameraParams;
	gb28181Params gb28181Param;
	int stream_input_type;
	int running;
} liveVideoStreamParams;

//�����Ϣ����Ƶ��Ϣ
liveVideoStreamParams g_liveVideoParams;

FILE *g_fp;


static void RegisterSuccess(struct eXosip_t * peCtx, eXosip_event_t *je)
{
	int iReturnCode = 0;
	osip_message_t * pSRegister = NULL;
	iReturnCode = eXosip_message_build_answer(peCtx, je->tid, 200, &pSRegister);
	if (iReturnCode == 0 && pSRegister != NULL)
	{
		eXosip_lock(peCtx);
		eXosip_message_send_answer(peCtx, je->tid, 200, pSRegister);
		eXosip_unlock(peCtx);
		//osip_message_free(pSRegister);
	}
}

void RegisterFailed(struct eXosip_t * peCtx, eXosip_event_t *je)
{
	int iReturnCode = 0;
	osip_message_t * pSRegister = NULL;
	iReturnCode = eXosip_message_build_answer(peCtx, je->tid, 401, &pSRegister);
	if (iReturnCode == 0 && pSRegister != NULL)
	{
		eXosip_lock(peCtx);
		eXosip_message_send_answer(peCtx, je->tid, 401, pSRegister);
		eXosip_unlock(peCtx);
	}
}


//��ini�ļ���ȡ���������Ϣ
static int ParserIniFile()
{
	std::string strIniPath = GetMoudlePath();
	strIniPath += "GB28181.ini";
	::GetPrivateProfileString("GB28181", "platform_id", "���", g_liveVideoParams.gb28181Param.platformSipId, MAX_PATH, strIniPath.c_str());	//��ȡƽ̨ID
	g_liveVideoParams.gb28181Param.platformSipPort = GetPrivateProfileInt("GB28181", "platform_port", 0, strIniPath.c_str());					//��ȡƽ̨�˿�
	::GetPrivateProfileString("GB28181", "platform_ip", "���", g_liveVideoParams.gb28181Param.platformIpAddr, MAX_PATH, strIniPath.c_str());	//��ȡƽ̨IP
	::GetPrivateProfileString("GB28181", "local_id", "���", g_liveVideoParams.gb28181Param.localSipId, MAX_PATH, strIniPath.c_str());		//��ȡ����ID
	g_liveVideoParams.gb28181Param.localSipPort = GetPrivateProfileInt("GB28181", "local_port", 0, strIniPath.c_str());						//��ȡ���ض˿�
	::GetPrivateProfileString("GB28181", "local_ip", "���", g_liveVideoParams.gb28181Param.localIpAddr, MAX_PATH, strIniPath.c_str());		//��ȡƽ̨IP
	g_liveVideoParams.cameraNum = GetPrivateProfileInt("GB28181", "camera_num", 0, strIniPath.c_str());										//�������

	if (g_liveVideoParams.cameraNum > 0 && g_liveVideoParams.cameraNum < CAMERA_SUPPORT_MAX) {
		g_liveVideoParams.pCameraParams = (CameraParams *)malloc(sizeof(CameraParams)*g_liveVideoParams.cameraNum);
		if (g_liveVideoParams.pCameraParams == NULL) {
			fprintf(g_fp, "malloc, failed");
			return -1;
		}
		memset(g_liveVideoParams.pCameraParams, 0, sizeof(CameraParams)*g_liveVideoParams.cameraNum);
		CameraParams *p;

		p = g_liveVideoParams.pCameraParams;

		GetPrivateProfileString("GB28181", "camera1_sip_id", "", p->sipId, MAX_PATH, strIniPath.c_str());
		p->recvPort = GetPrivateProfileInt("GB28181", "camera1_recv_port", 0, strIniPath.c_str());

		//��ȡ�����¼��������
		GetPrivateProfileString("GB28181", "UserPwd", "", p->UserPwd, MAX_PATH, strIniPath.c_str());
		GetPrivateProfileString("GB28181", "UserName", "", p->UserName, MAX_PATH, strIniPath.c_str());
	}

	g_liveVideoParams.gb28181Param.SN = 1;
	g_liveVideoParams.gb28181Param.call_id = -1;
	g_liveVideoParams.gb28181Param.dialog_id = -1;
	g_liveVideoParams.gb28181Param.registerOk = 0;

	fprintf(g_fp, "���������ļ����");

	return 0;
}

//�����������Ϣ���������߳�
static void *MsgProcess(gb28181Params *p28181Params, void * pvSClientGB)
{
	char *p;
	int keepAliveFlag = 0;
	struct eXosip_t * peCtx = (struct eXosip_t *)pvSClientGB;

	//�������ظ��������Ϣ
	while (p28181Params->running)
	{
		eXosip_event_t *je = NULL;
		//�����¼�
		je = eXosip_event_wait(peCtx, 0, 4);
		if (je == NULL)
		{
			osip_usleep(100000);
			continue;
		}

		switch (je->type)
		{
			case EXOSIP_MESSAGE_NEW:				//����Ϣ����
			{
				fprintf(g_fp, "new msg method:%s\n", je->request->sip_method);
				if (MSG_IS_REGISTER(je->request))
				{
					//APP_DEBUG("recv Register");
					fprintf(g_fp, "recv Register");
					g_liveVideoParams.gb28181Param.registerOk = 1;
				}
				else if (MSG_IS_MESSAGE(je->request))
				{
					osip_body_t *body = NULL;
					osip_message_get_body(je->request, 0, &body);
					if (body != NULL)
					{
						p = strstr(body->body, "Keepalive");
						if (p != NULL)
						{
							if (keepAliveFlag == 0)
							{
								fprintf(g_fp, "msg body:%s\n", body->body);
								keepAliveFlag = 1;
								g_liveVideoParams.gb28181Param.registerOk = 1;
							}
						}
						else
						{
							fprintf(g_fp, "msg body:%s\n", body->body);
						}
					}
					else
					{
						// APP_ERR("get body failed");
						fprintf(g_fp, "get body failed");
					}
				}
				else if (strncmp(je->request->sip_method, "BYE", 4) != 0)
				{
					fprintf(g_fp, "unsupport new msg method : %s", je->request->sip_method);
				}
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_MESSAGE_ANSWERED:				//��ѯ
			{
				fprintf(g_fp, "answered method:%s\n", je->request->sip_method);
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_ANSWERED:
			{
				osip_message_t *ack = NULL;
				p28181Params->call_id = je->cid;
				p28181Params->dialog_id = je->did;
				fprintf(g_fp, "call answered method:%s, call_id:%d, dialog_id:%d\n", je->request->sip_method, p28181Params->call_id, p28181Params->dialog_id);
				eXosip_call_build_ack(peCtx, je->did, &ack);
				eXosip_lock(peCtx);
				eXosip_call_send_ack(peCtx, je->did, ack);
				eXosip_unlock(peCtx);
				break;
			}
			case EXOSIP_CALL_PROCEEDING:
			{
				fprintf(g_fp, "recv EXOSIP_CALL_PROCEEDING\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_REQUESTFAILURE:
			{
				printf("recv EXOSIP_CALL_REQUESTFAILURE\n");
				fprintf(g_fp, "recv EXOSIP_CALL_REQUESTFAILURE\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_MESSAGE_ANSWERED:
			{
				printf("recv EXOSIP_CALL_MESSAGE_ANSWERED\n");
				//fprintf(g_fp, "recv EXOSIP_CALL_MESSAGE_ANSWERED\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_RELEASED:         //������Ƶ���ظ��ɹ�
			{
				printf("recv EXOSIP_CALL_RELEASED\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_CLOSED:
				printf("recv EXOSIP_CALL_CLOSED\n");
				RegisterSuccess(peCtx, je);
				break;
			case EXOSIP_CALL_MESSAGE_NEW:
				printf("recv EXOSIP_CALL_MESSAGE_NEW\n");
				RegisterSuccess(peCtx, je);
				break;
			default:
				printf("##test,%s:%d, unsupport type:%d\n", __FILE__, __LINE__, je->type);
				RegisterSuccess(peCtx, je);
				break;
		}
		eXosip_event_free(je);
	}

	return NULL;
}

//��ʼ��udp�׽���
int init_udpsocket(int port, struct sockaddr_in *servaddr)
{
	int err = -1;
	int socket_fd;

	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)
	{
		printf("socket failed, port:%d", port);
		return -1;
	}

	memset(servaddr, 0, sizeof(struct sockaddr_in));
	servaddr->sin_family = AF_INET;
	servaddr->sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr->sin_port = htons(port);

	err = bind(socket_fd, (struct sockaddr*)servaddr, sizeof(struct sockaddr_in));
	if (err < 0)
	{
		printf("bind failed, port:%d", port);
		return -2;
	}

	/*set enable MULTICAST LOOP */
	int loop = 4*1024*1024;
	err = setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, (const char*)&loop, sizeof(loop));
	//err = setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	if (err < 0)
	{
		printf("setsockopt IP_MULTICAST_LOOP failed, port:%d", port);
		return -3;
	}

	return socket_fd;
}

//�ر��׽���
void release_udpsocket(int socket_fd)
{
	closesocket(socket_fd);
}

//���
void checkerror(int rtperr)
{
	if (rtperr < 0)
	{
		std::cout << "ERROR: " << RTPGetErrorString(rtperr) << std::endl;
		return;
		exit(-1);
	}
}

typedef int (*h264framecallback)(char* data, int length, void* usrdata);

class PsPacketParser {
public:
	void Parse(const char* data, size_t size) {
		if (size < 14 || 0xba010000 != *(int32_t*)data) return;
		int extlen = uint8_t(data[13]) & 0x07;
		if (size <= 14 + extlen) return;

		const char * buffer = data + (14 + extlen);
		int length = size - extlen - 14;
		while (length > 0) {
			if (length < 6) break;
			int32_t chunk_flag = *(int32_t*)buffer;
			uint16_t chunk_size = ntohs(*(uint16_t*)(buffer + 4));
			if (chunk_size + 6 > length) break;

			switch (chunk_flag)	{
			case 0xe0010000:
				ParsePes(buffer + 6, chunk_size);
				break;
			}

			buffer += (6 + chunk_size);
			length -= (6 + chunk_size);
		}
	}

	void setcallback(h264framecallback _callback, void* _usrdata){
		callback = _callback;
		usrdata = _usrdata;
	}
private:
	void ParsePes(const char* data, size_t size) {
		if (size > 3){
			int32_t len = uint8_t(data[2]) + 3;
			if (size > len && callback)
				callback((char*)data + len, size - len, usrdata);
		}
	}

private:
	h264framecallback callback;
	void *usrdata;
};
PsPacketParser parser;

int myh264framecallback(char* data, int length, void* usrdata)
{
	CameraParams *p = (CameraParams *)usrdata;

	fwrite(data, 1, length, p->fpH264);

	return 0;
}

int ParsePsStream(char* psBuf, uint32_t &psLen, char* rtpPayload, uint32_t rtpPayloadLength, CameraParams *p)
{
	static uint32_t cnt = 0;
	if (rtpPayloadLength <= 0)
	{
		perror("recvfrom() long");
		return -1;
	}

	char* ptr = psBuf + psLen;			//�������ݵ�ͷ
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

	//��Ƶ������
	if (psLen > 0 && 
		ptr[0] == 0x00 && ptr[1] == 0x00 && ptr[2] == 0x01 && ptr[3] == 0xffffffBA)
	{
		if (cnt % 25 == 0)
		{
			p->status = 1;
		}

		parser.Parse(psBuf, psLen);

		memcpy(psBuf, ptr, rtpPayloadLength);
		psLen = 0;
		cnt++;
	}
	psLen += rtpPayloadLength;

	return 0;
}

static unsigned __stdcall jrtplib_rtp_recv_thread(void* arg)
{
	//��ȡ�������
	CameraParams *p = (CameraParams *)arg;
	parser.setcallback(myh264framecallback, arg);

	char *psBuf = (char *)malloc(PS_BUF_SIZE);
	if (psBuf == NULL)
	{
		//APP_ERR("malloc failed");
		printf("malloc failed");
		return NULL;
	}
	memset(psBuf, '\0', PS_BUF_SIZE);
	uint32_t psLen = 0;

#ifdef WIN32
	WSADATA dat;
	WSAStartup(MAKEWORD(2, 2), &dat);
#endif // WIN32

	RTPSession sess;
	uint16_t portbase;
	std::string ipstr;
	int i, num;

	RTPUDPv4TransmissionParams transparams;
	RTPSessionParams sessparams;

	sessparams.SetOwnTimestampUnit(1.0 / 9000.0);

	portbase = p->recvPort;

	sessparams.SetAcceptOwnPackets(true);
	transparams.SetPortbase(portbase);
	int status = sess.Create(sessparams, &transparams);
	if (status < 0)
	{
		std::cout << "ERROR: " << RTPGetErrorString(status) << std::endl;
		return -1;
	}

	//д����Ƶ�ļ�
	//��ȡ��ǰ����·��
	std::string strPath = GetMoudlePath();
	char filename[MAX_PATH];
	strPath += p->sipId;
	_snprintf(filename, 128, "%s1234.264", strPath.c_str());
	p->fpH264 = fopen(filename, "wb");
	if (p->fpH264 == NULL)
	{
		printf("fopen %s failed", filename);
		return NULL;
	}

	uint32_t last_ts = 0;
	//��ʼ��������
	while (p->running)
	{
		sess.BeginDataAccess();

		// check incoming packets
		if (sess.GotoFirstSourceWithData())
		{
			do
			{
				RTPSourceData *source = sess.GetCurrentSourceInfo();
				RTPIPv4Address *addr = (RTPIPv4Address*)source->GetRTPDataAddress();
				uint32_t ip = htonl(addr->GetIP());
				char ipstr[16] = {0};
				char* ipptr = (char*)&ip;
				sprintf(ipstr, "%u.%u.%u.%u", (uint8_t)ipptr[0], (uint8_t)ipptr[1], (uint8_t)ipptr[2], (uint8_t)ipptr[3]);
				uint16_t rtpport = addr->GetPort();
				printf("ip = %u, ipstr=%s, rtpport = %u \n", ip, ipstr, rtpport);

				RTPPacket *pack;

				while ((pack = sess.GetNextPacket()) != NULL)
				{
					// You can examine the data here
					fprintf(g_fp, "Got packet !\n");
					printf("Got packet! %d \n", pack->GetPayloadLength());

					//std::cout << pack->GetPayloadData() << std::endl;
					uint32_t ts = pack->GetTimestamp();
					if (ts >= last_ts)
					{
						ParsePsStream(psBuf, psLen, (char*)pack->GetPayloadData(), pack->GetPayloadLength(), p);
						last_ts = ts;
					}

					//д���ļ�
//					fwrite(pack->GetPayloadData(), 1, pack->GetPayloadLength(), p->fpH264);
					// we don't longer need the packet, so
					// we'll delete it
					sess.DeletePacket(pack);
				}
			} while (sess.GotoNextSourceWithData());
		}

		sess.EndDataAccess();

#ifndef RTP_SUPPORT_THREAD
		status = sess.Poll();
		checkerror(status);
#endif // RTP_SUPPORT_THREAD

		//RTPTime::Wait(RTPTime(0, 0));
	}

	sess.BYEDestroy(RTPTime(10, 0), 0, 0);

#ifdef WIN32
	WSACleanup();
#endif // WIN32

	fclose(p->fpH264);
	p->fpH264 = NULL;

	return 0;
}

//��ʼ������Ƶ��
static int startStreamRecv(liveVideoStreamParams *pliveVideoParams)
{
	int i;
	HANDLE hHandle;
	HANDLE hHandleAlive;
	//pthread_t pid;
	
	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		CameraParams *p = pliveVideoParams->pCameraParams + i;
		p->statusErrCnt = 0;
		p->running = 1;

		if ((hHandle = (HANDLE)_beginthreadex(NULL, 0, jrtplib_rtp_recv_thread, (void*)p, 0, NULL)) == INVALID_HANDLE_VALUE)
		{
			printf("pthread_create rtp_recv_thread err, %s:%d", p->sipId, p->recvPort);
		}
		else
		{
			CloseHandle(hHandle);
		}
	}

	return 0;
}

static unsigned __stdcall gb28181ServerThread(void *arg)
{
	int iReturnCode = 0;
	struct eXosip_t *eCtx;
	gb28181Params *p28181Params = (gb28181Params *)(arg);

	//��ʼ��������Ϣ
	TRACE_INITIALIZE(6, NULL);

	//��ʼ��eXosip��osipջ
	eCtx = eXosip_malloc();
	iReturnCode = eXosip_init(eCtx);
	if (iReturnCode != OSIP_SUCCESS)
	{
		printf("Can,t initialize, eXosip!");
		return NULL;
	}
	else
	{
		printf("eXosip_init successfully!\n");
	}

	//��һ��UDP socket �����ź�
	iReturnCode = eXosip_listen_addr(eCtx, IPPROTO_UDP, NULL, p28181Params->localSipPort, AF_INET, 0);
	if (iReturnCode != OSIP_SUCCESS)
	{
		printf("eXosip_listen_addr udp error!");
		return NULL;
	}

	p28181Params->eCtx = eCtx;
	MsgProcess(p28181Params, eCtx);

	eXosip_quit(eCtx);
	osip_free(eCtx);
	eCtx = NULL;
	p28181Params->eCtx = NULL;

	fprintf(g_fp, "%s run over", __FUNCTION__);

	return 0;
}

//������Ƶ��Ϣ��SDP��Ϣ
static int sendInvitePlay(char *playSipId, int rtp_recv_port, gb28181Params *p28181Params)
{
	char dest_call[256], source_call[256], subject[128];
	osip_message_t *invite = NULL;
	int ret;
	struct eXosip_t *peCtx = p28181Params->eCtx;

	_snprintf(dest_call, 256, "sip:%s@%s:%d", playSipId, p28181Params->platformIpAddr, p28181Params->platformSipPort);
	_snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
	_snprintf(subject, 128, "%s:0,%s:0", playSipId, p28181Params->localSipId);
	ret = eXosip_call_build_initial_invite(peCtx, &invite, dest_call, source_call, NULL, subject);
	if (ret != 0)
	{
		fprintf(g_fp, "eXosip_call_build_initial_invite failed, %s,%s,%s", dest_call, source_call, subject);
		return -1;
	}

	//sdp
	char body[500];
	int bodyLen = _snprintf(body, 500,
		"v=0\r\n"
		"o=%s 0 0 IN IP4 %s\r\n"
		"s=Play\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=video %d RTP/AVP 96 97 98\r\n"
		"a=rtpmap:96 PS/90000\r\n"
		"a=rtpmap:97 MPEG4/90000\r\n"
		"a=rtpmap:98 H264/90000\r\n"
		"a=recvonly\r\n"
		"y=0100000001\n", playSipId, p28181Params->localIpAddr,
		p28181Params->localIpAddr, rtp_recv_port);
	osip_message_set_body(invite, body, bodyLen);
	osip_message_set_content_type(invite, "APPLICATION/SDP");
	eXosip_lock(peCtx);
	eXosip_call_send_initial_invite(peCtx, invite);
	eXosip_unlock(peCtx);

	return 0;
}

//ֹͣ��Ƶ�ش�
static int sendPlayBye(gb28181Params *p28181Params)
{
	struct eXosip_t *peCtx = p28181Params->eCtx;

	eXosip_lock(peCtx);
	eXosip_call_terminate(peCtx, p28181Params->call_id, p28181Params->dialog_id);
	eXosip_unlock(peCtx);
	return 0;
}

//����������ش���Ƶ
static int startCameraRealStream(liveVideoStreamParams *pliveVideoParams)
{
	int i;

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		CameraParams *p = pliveVideoParams->pCameraParams + i;
		sendInvitePlay(p->sipId, p->recvPort, &(pliveVideoParams->gb28181Param));
	}

	return 0;
}

//ֹͣ�������Ƶ�ش�
static int stopCameraRealStream(liveVideoStreamParams *pliveVideoParams)
{
	int i, tryCnt;
	gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		CameraParams *p = pliveVideoParams->pCameraParams + i;
		p28181Params->call_id = -1;
		sendInvitePlay(p->sipId, p->recvPort, p28181Params);
		tryCnt = 10;
		while (tryCnt-- > 0)
		{
			if (p28181Params->call_id != -1)
			{
				break;
			}
			Sleep(1000);
		}
		if (p28181Params->call_id == -1)
		{
			printf("exception wait call_id:%d, %s", p28181Params->call_id, p->sipId);
		}
		sendPlayBye(p28181Params);

		p->running = 0;
	}

	return 0;
}

//��֤���״̬
static int checkCameraStatus(liveVideoStreamParams *pliveVideoParams)
{
	int i;
	gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		CameraParams *p = pliveVideoParams->pCameraParams + i;
		if (p->status == 0)
		{
			p->statusErrCnt++;
			if (p->statusErrCnt % 10 == 0)
			{
				printf("camera %s is exception, restart it", p->sipId);
				p28181Params->call_id = -1;
				sendInvitePlay(p->sipId, p->recvPort, p28181Params);
				p->statusErrCnt = 0;

			}
		}
		else
		{
			p->statusErrCnt = 0;
			p->status = 0;
		}
	}

	return 0;
}

//ֹͣ����
static int stopStreamRecv(liveVideoStreamParams *pliveVideoParams)
{
	int i;

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		CameraParams *p = pliveVideoParams->pCameraParams + i;
		p->running = 0;
	}

	return 0;
}

const char *whitespace_cb(mxml_node_t *node, int where)
{
	return NULL;
}

//��������catalog��Ϣ
static int sendQueryCatalog(gb28181Params *p28181Params)
{
	char sn[32];
	int ret;
	mxml_node_t *tree, *query, *node;
	struct eXosip_t *peCtx = p28181Params->eCtx;
	char *deviceId = p28181Params->localSipId;

	tree = mxmlNewXML("1.0");
	if (tree != NULL)
	{
		query = mxmlNewElement(tree, "Query");
		if (query != NULL)
		{
			char buf[256] = { 0 };
			char dest_call[256], source_call[256];
			node = mxmlNewElement(query, "CmdType");
			mxmlNewText(node, 0, "Catalog");
			node = mxmlNewElement(query, "SN");
			_snprintf(sn, 32, "%d", p28181Params->SN++);
			mxmlNewText(node, 0, sn);
			node = mxmlNewElement(query, "DeviceID");
			mxmlNewText(node, 0, deviceId);
			mxmlSaveString(tree, buf, 256, whitespace_cb);
			//printf("send query catalog:%s\n", buf);
			osip_message_t *message = NULL;
			_snprintf(dest_call, 256, "sip:%s@%s:%d", p28181Params->platformSipId,
				p28181Params->platformIpAddr, p28181Params->platformSipPort);
			_snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
			ret = eXosip_message_build_request(peCtx, &message, "MESSAGE", dest_call, source_call, NULL);
			if (ret == 0 && message != NULL)
			{
				osip_message_set_body(message, buf, strlen(buf));
				osip_message_set_content_type(message, "Application/MANSCDP+xml");
				eXosip_lock(peCtx);
				eXosip_message_send_request(peCtx, message);
				eXosip_unlock(peCtx);
				printf("xml:%s, dest_call:%s, source_call:%s, ok", buf, dest_call, source_call);
				fprintf(g_fp, "xml:%s, dest_call:%s, source_call:%s, ok", buf, dest_call, source_call);
			}
			else
			{
				printf("eXosip_message_build_request failed");
				fprintf(g_fp, "eXosip_message_build_request failed");
			}
		}
		else
		{
			printf("mxmlNewElement Query failed");
			fprintf(g_fp, "mxmlNewElement Query failed");
		}
		mxmlDelete(tree);
	}
	else
	{
		fprintf(g_fp, "mxmlNewXML failed");
	}

	return 0;
}

//������
int main(int argc, char *argv[])
{

	HANDLE hHandle;

	//��ӡ��־
	std::string strLogPath = GetMoudlePath();
	strLogPath += "log.txt";
	g_fp = fopen(strLogPath.c_str(), "wt");
	if (g_fp == NULL)
		return 0;


	//1.���������ļ���ȡ����������
	ParserIniFile();

	g_liveVideoParams.running = 1;
	g_liveVideoParams.gb28181Param.running = 1;

	//�����������̣߳��������˿ڴ�����̣߳����������������������Ϣ
	if ((hHandle = (HANDLE)_beginthreadex(NULL, 0, gb28181ServerThread, (void*)&(g_liveVideoParams.gb28181Param), 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("error pthread_create gb28181ServerThread err");
		fprintf(g_fp, "error, pthread_create gb28181ServerThread err");
	}
	else
	{
		CloseHandle(hHandle);
	}

	int tmpCnt = 0;
	while ( !g_liveVideoParams.gb28181Param.registerOk )
	{
		Sleep(1000);
	}

//	return 0;

	//��������catalog��Ϣ
//	sendQueryCatalog(&(g_liveVideoParams.gb28181Param));

	//������Ƶ��
	startStreamRecv(&g_liveVideoParams);
	Sleep(1000);

	int i = 0;

	//����������Ƶ��Ϣ
	startCameraRealStream(&g_liveVideoParams);
	while (g_liveVideoParams.running)
	{
		i++;
//		checkCameraStatus(&g_liveVideoParams);
		Sleep(2000);
//		if (i == 20)
//			break;
	}

	g_liveVideoParams.running = 0;
	stopCameraRealStream(&g_liveVideoParams);
	Sleep(300);
	stopStreamRecv(&g_liveVideoParams);
	g_liveVideoParams.gb28181Param.running = 0;
	Sleep(1000);
	printf("LiveVideoStream run over");

	return 0;
}