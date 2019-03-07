
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

#include "mysip.h"

#define PS_BUF_SIZE         (1024*1024*4)

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
			p->decoder.SetPacketData((uint8_t*)packet, packetsize);
			if( p->fpH264 )
				fwrite(packet, 1, packetsize, p->fpH264);
		}

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

	char *psBuf = (char *)malloc(PS_BUF_SIZE);
	if (psBuf == NULL)
	{
		//APP_ERR("malloc failed");
		printf("malloc failed");
		return -1;
	}
	memset(psBuf, 0, PS_BUF_SIZE);
	uint32_t psLen = 0;

#ifdef WIN32
	WSADATA dat;
	WSAStartup(MAKEWORD(2, 2), &dat);
#endif // WIN32

	//写入视频文件
	//获取当前程序路径
	char filename[MAX_PATH];
	std::string strPath = p->sipId;
	snprintf(filename, MAX_PATH, "%s.264", strPath.c_str());
	if( p->writefile )
		p->fpH264 = fopen(filename, "wb");

	if (p->fpH264 == NULL)
	{
		printf("fopen %s failed", filename);
	}

	uint32_t last_ts = 0;
	//开始接收流包
	while (p->running)
	{
		p->sess.WaitForIncomingData(jrtplib::RTPTime(1, 1000));

		p->sess.BeginDataAccess();

		// check incoming packets
		if (p->sess.GotoFirstSourceWithData())
		{
			do{
				jrtplib::RTPPacket *pack;

				if ((pack = p->sess.GetNextPacket()) != NULL)
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
					p->sess.DeletePacket(pack);
				}
			} while (p->sess.GotoNextSourceWithData());
		}

		p->sess.EndDataAccess();

#ifndef RTP_SUPPORT_THREAD
		if( p->sess.Poll() < 0 )
		{
			printf("sess.Poll() error \n");
			break;
		}
#endif // RTP_SUPPORT_THREAD

//		std::this_thread::sleep_for(std::chrono::milliseconds(1));
//		jrtplib::RTPTime::Wait(jrtplib::RTPTime(0, 1));
	}

	p->sess.BYEDestroy(jrtplib::RTPTime(0, 1000), 0, 0);

#ifdef WIN32
	WSACleanup();
#endif // WIN32

	p->decoder.Stop();

	if( p->fpH264 )
	{
		fclose(p->fpH264);
		p->fpH264 = NULL;
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

int gb28181_startstream(void *handle, char* deviceip)
{
	if (!handle || !deviceip)
		return -1;

	liveVideoStreamParams *inst = (liveVideoStreamParams *)handle;

	CameraParams *param = NULL;
	if (getdeviceinfo(inst, deviceip, &param) < 0)
	{
		printf("getdeviceinfo error");
		return -1;
	}

	if( !param->decoder.GetCodec(27, 1) )
	{
		printf("GetCodec error");
		return -1;		
	}

	if (getrtpsession(param->sess, param->recvPort) < 0)
	{
		printf("getrtpsession error");
		return -1;
	}

	param->running = 1;
	param->status = 0;
	param->statusErrCnt = 0;
	param->writefile = 0;//1;

	sendInvitePlay(&inst->gb28181Param, param, param->recvPort);

	param->rtpthread = std::thread(jrtplib_rtp_recv_thread, (void*)param);

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
		printf("getdeviceinfo error");
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
		printf("getdeviceinfo error");
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
		printf("getdeviceinfo error");
		return -1;
	}

	if( !param->decoder.GetInfo(width, height) )
	{
		printf("GetRGBData error");
		return -1;		
	}

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
		printf("getdeviceinfo error");
		return -1;
	}

	if( !param->decoder.GetRGBData(data, width, height) )
	{
		printf("GetRGBData error");
		return -1;		
	}

	if( !param->decoder.GetRGBData(data, width, height) )
	{
		printf("GetRGBData error");
		return -1;		
	}

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
