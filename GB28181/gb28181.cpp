#include "rtpsession.h"
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

	#pragma comment(lib, "ws2_32.lib")
	#pragma comment(lib, "mxml1.lib")
	#pragma comment(lib, "eXosip.lib")
	#pragma comment(lib, "libcares.lib")
	#pragma comment(lib, "osip2.lib")

	//Dnsapi.lib;Iphlpapi.lib;ws2_32.lib;eXosip.lib;osip2.lib;osipparser2.lib;Qwave.lib;libcares.lib;delayimp.lib;
	//忽略 libcmt.lib默认库
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

#endif // WIN32

#include <map>
#include <thread>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <mxml.h>
#include <time.h>
#include <process.h>
#include <eXosip2/eXosip.h>

#define PS_BUF_SIZE         (1024*1024*4)

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

	std::thread msgthread;
} gb28181Params;

typedef struct {
	char sipId[MAX_PATH];
	char deviceip[MAX_PATH];
	int deviceport;
	char UserName[MAX_PATH];
	char UserPwd[MAX_PATH];
	int recvPort;
	int status;
	int statusErrCnt;
	FILE *fpH264;
	int running;

	jrtplib::RTPSession sess;
	std::thread rtpthread;
} CameraParams;

typedef struct _liveVideoStreamParams{
	std::map<std::string, CameraParams> mapCameraParams;
	gb28181Params gb28181Param;
	int stream_input_type;
	int running;
} liveVideoStreamParams;

//相机信息和视频信息
liveVideoStreamParams g_liveVideoParams;

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

//与相机进行消息交换的主线程
int MsgThreadProc(gb28181Params *p28181Params)
{
	char *p;
	int keepAliveFlag = 0;
	struct eXosip_t * peCtx = p28181Params->eCtx;

	//监听并回复摄像机消息
	while (p28181Params->running)
	{
		eXosip_event_t *je = NULL;
		//处理事件
		je = eXosip_event_wait(peCtx, 0, 4);
		if (je == NULL)
		{
			osip_usleep(100 * 1000);
			continue;
		}

		switch (je->type)
		{
			case EXOSIP_MESSAGE_NEW:				//新消息到来
			{
				printf("new msg method:%s\n", je->request->sip_method);
				if (MSG_IS_REGISTER(je->request))
				{
					printf("recv Register \n");
					p28181Params->registerOk = 1;
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
								printf("msg body:%s\n", body->body);
								keepAliveFlag = 1;
								p28181Params->registerOk = 1;
							}
						}
						else
						{
							printf("msg body:%s\n", body->body);
						}
					}
					else
					{
						// APP_ERR("get body failed");
						printf("get body failed \n");
					}
				}
				else if (strncmp(je->request->sip_method, "BYE", 4) != 0)
				{
					printf("unsupport new msg method : %s \n", je->request->sip_method);
				}
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_MESSAGE_ANSWERED:				//查询
			{
				printf("answered method:%s\n", je->request->sip_method);
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_ANSWERED:
			{
				p28181Params->call_id = je->cid;
				p28181Params->dialog_id = je->did;
				printf("call answered method:%s, call_id:%d, dialog_id:%d\n", je->request->sip_method, p28181Params->call_id, p28181Params->dialog_id);
				osip_message_t *ack = NULL;
				eXosip_call_build_ack(peCtx, je->did, &ack);
				eXosip_lock(peCtx);
				eXosip_call_send_ack(peCtx, je->did, ack);
				eXosip_unlock(peCtx);
				break;
			}
			case EXOSIP_CALL_PROCEEDING:
			{
				printf("recv EXOSIP_CALL_PROCEEDING\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_REQUESTFAILURE:
			{
				printf("recv EXOSIP_CALL_REQUESTFAILURE\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_MESSAGE_ANSWERED:
			{
				printf("recv EXOSIP_CALL_MESSAGE_ANSWERED\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_RELEASED:         //请求视频流回复成功
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

	return 0;
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

		parser.Parse(psBuf, psLen);

		memcpy(psBuf, ptr, rtpPayloadLength);
		psLen = 0;
		cnt++;
	}
	psLen += rtpPayloadLength;

	return 0;
}

int getrtpsession(jrtplib::RTPSession &sess, int &rtpport)
{
	uint16_t portbase;
	int i, num;

	jrtplib::RTPUDPv4TransmissionParams transparams;
	jrtplib::RTPSessionParams sessparams;

	sessparams.SetOwnTimestampUnit(1.0 / 9000.0);
	sessparams.SetAcceptOwnPackets(true);

	for (uint16_t i = 6000; i < 60000; i+=2)
	{
		transparams.SetPortbase(i);
		int status = sess.Create(sessparams, &transparams);
		if (status >= 0)
		{
			rtpport = i;
			return 0;
		}
		sess.Destroy();
	}
	return -1;
}

int jrtplib_rtp_recv_thread(void* arg)
{
	//获取相机参数
	CameraParams *p = (CameraParams *)arg;
	parser.setcallback(myh264framecallback, arg);

	char *psBuf = (char *)malloc(PS_BUF_SIZE);
	if (psBuf == NULL)
	{
		//APP_ERR("malloc failed");
		printf("malloc failed");
		return -1;
	}
	memset(psBuf, '\0', PS_BUF_SIZE);
	uint32_t psLen = 0;

#ifdef WIN32
	WSADATA dat;
	WSAStartup(MAKEWORD(2, 2), &dat);
#endif // WIN32

	//写入视频文件
	//获取当前程序路径
	char filename[MAX_PATH];
	std::string strPath = p->sipId;
	_snprintf(filename, 128, "%s1234.264", strPath.c_str());
	p->fpH264 = fopen(filename, "wb");
	if (p->fpH264 == NULL)
	{
		printf("fopen %s failed", filename);
		return NULL;
	}

	uint32_t last_ts = 0;
	//开始接收流包
	while (p->running)
	{
		p->sess.BeginDataAccess();

		// check incoming packets
		if (p->sess.GotoFirstSourceWithData())
		{
			do
			{
				jrtplib::RTPSourceData *source = p->sess.GetCurrentSourceInfo();
				jrtplib::RTPIPv4Address *addr = (jrtplib::RTPIPv4Address*)source->GetRTPDataAddress();
				uint32_t ip = htonl(addr->GetIP());
				char ipstr[16] = {0};
				char* ipptr = (char*)&ip;
				sprintf(ipstr, "%u.%u.%u.%u", (uint8_t)ipptr[0], (uint8_t)ipptr[1], (uint8_t)ipptr[2], (uint8_t)ipptr[3]);
				uint16_t rtpport = addr->GetPort();
				printf("ip = %u, ipstr=%s, rtpport = %u \n", ip, ipstr, rtpport);

				jrtplib::RTPPacket *pack;

				while ((pack = p->sess.GetNextPacket()) != NULL)
				{
					// You can examine the data here
					printf("Got packet! %d \n", pack->GetPayloadLength());

					//std::cout << pack->GetPayloadData() << std::endl;
					uint32_t ts = pack->GetTimestamp();
					if (ts >= last_ts || abs(int(ts - last_ts))/90000 >= 3600 )
					{
						ParsePsStream(psBuf, psLen, (char*)pack->GetPayloadData(), pack->GetPayloadLength(), p);
						last_ts = ts;
					}

					//写入文件
//					fwrite(pack->GetPayloadData(), 1, pack->GetPayloadLength(), p->fpH264);
					// we don't longer need the packet, so
					// we'll delete it
					p->sess.DeletePacket(pack);
				}
			} while (p->sess.GotoNextSourceWithData());
		}

		p->sess.EndDataAccess();

#ifndef RTP_SUPPORT_THREAD
		status = sess.Poll();
		checkerror(status);
#endif // RTP_SUPPORT_THREAD

		jrtplib::RTPTime::Wait(jrtplib::RTPTime(0, 1000));
	}

	p->sess.BYEDestroy(jrtplib::RTPTime(0, 10 * 1000), 0, 0);

#ifdef WIN32
	WSACleanup();
#endif // WIN32

	fclose(p->fpH264);
	p->fpH264 = NULL;

	return 0;
}

struct eXosip_t *mysip_init(int localport)
{
	//初始化跟踪信息
	TRACE_INITIALIZE(6, NULL);

	//初始化eXosip和osip栈
	struct eXosip_t *eCtx = eXosip_malloc();
	if ( !eCtx )
	{
		printf("eXosip_malloc error");
		return NULL;
	}

	int ret = eXosip_init(eCtx);
	if (ret != OSIP_SUCCESS)
	{
		printf("Can,t initialize, eXosip!");
		osip_free(eCtx);
		return NULL;
	}

	//打开一个UDP socket 接收信号
	ret = eXosip_listen_addr(eCtx, IPPROTO_UDP, NULL, localport, AF_INET, 0);
	if (ret != OSIP_SUCCESS)
	{
		printf("eXosip_listen_addr udp error!");
		osip_free(eCtx);
		return NULL;
	}

	return eCtx;
}

int mysip_uninit(struct eXosip_t *eCtx)
{
	if (!eCtx)
		return -1;

	eXosip_quit(eCtx);
	osip_free(eCtx);

	return 0;
}

//请求视频信息，SDP信息
int sendInvitePlay(gb28181Params *p28181Params, CameraParams *p, int rtp_recv_port)
{
	char dest_call[256], source_call[256], subject[128];
	osip_message_t *invite = NULL;
	int ret;
	struct eXosip_t *peCtx = p28181Params->eCtx;

	_snprintf(dest_call, 256, "sip:%s@%s:%d", p->sipId, p->deviceip, p->deviceport);
	_snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
	_snprintf(subject, 128, "%s:0,%s:0", p->sipId, p28181Params->localSipId);
	ret = eXosip_call_build_initial_invite(peCtx, &invite, dest_call, source_call, NULL, subject);
	if (ret != 0)
	{
		printf("eXosip_call_build_initial_invite failed, %s,%s,%s", dest_call, source_call, subject);
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
		"y=0100000001\n", p->sipId, p28181Params->localIpAddr,
		p28181Params->localIpAddr, rtp_recv_port);
	osip_message_set_body(invite, body, bodyLen);
	osip_message_set_content_type(invite, "APPLICATION/SDP");
	eXosip_lock(peCtx);
	eXosip_call_send_initial_invite(peCtx, invite);
	eXosip_unlock(peCtx);

	return 0;
}

//停止视频回传
int sendPlayBye(gb28181Params *p28181Params)
{
	struct eXosip_t *peCtx = p28181Params->eCtx;

	eXosip_lock(peCtx);
	eXosip_call_terminate(peCtx, p28181Params->call_id, p28181Params->dialog_id);
	eXosip_unlock(peCtx);
	return 0;
}

//停止摄像机视频回传
int stopCameraRealStream(liveVideoStreamParams *pliveVideoParams, CameraParams *p)
{
	int i, tryCnt;
	gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

	p28181Params->call_id = -1;
//	sendInvitePlay(p->sipId, p->recvPort, p28181Params);
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

	return 0;
}

//验证相机状态
static int checkCameraStatus(liveVideoStreamParams *pliveVideoParams, CameraParams *p)
{
	int i;
	gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

	if (p->status == 0)
	{
		p->statusErrCnt++;
		if (p->statusErrCnt % 10 == 0)
		{
			printf("camera %s is exception, restart it", p->sipId);
			p28181Params->call_id = -1;
//			sendInvitePlay(p->sipId, p->recvPort, p28181Params);
			p->statusErrCnt = 0;

		}
	}
	else
	{
		p->statusErrCnt = 0;
		p->status = 0;
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
	inst->gb28181Param.registerOk = 0;
	inst->gb28181Param.eCtx = sipctx;
	strcpy(inst->gb28181Param.localSipId, localsipid);
	strcpy(inst->gb28181Param.localIpAddr, localip);
	inst->gb28181Param.localSipPort = localport;
	
	inst->gb28181Param.msgthread = std::thread(MsgThreadProc, &inst->gb28181Param);

	return inst;
}

int gb28181_startstream(void *handle, char* deviceip, int deviceport, char* deviceid)
{
	if (!handle || !deviceip || !deviceid)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;

//	CameraParams param;
	CameraParams &param = inst->mapCameraParams[deviceip];
	if (getrtpsession(param.sess, param.recvPort) < 0)
	{
		printf("getrtpsession error");
		return -1;
	}

	strcpy(param.sipId, deviceid);
	strcpy(param.deviceip, deviceip);
	param.deviceport = deviceport;
	param.running = 1;
	param.status = 0;
	param.statusErrCnt = 0;

	sendInvitePlay(&inst->gb28181Param, &param, param.recvPort);

	param.rtpthread = std::thread(jrtplib_rtp_recv_thread, (void*)&param);

	return 0;
}

int gb28181_stopstream(void *handle, char* deviceid);

int gb28181_getregisterstatus(void *handle)
{
	if (!handle)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;
	return inst->gb28181Param.registerOk;
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
