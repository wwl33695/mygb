
#ifndef WIN32
	#include <netinet/in.h>
	#include <arpa/inet.h>
#else
	#include <winsock2.h>
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
	jrtplib::RTPRandomURandom _rand;
	if( _rand.Init() < 0 )
		return -1;

	port = _rand.GetRandom16();
	port -= port % 2;
	port %= 50000 ;
	if( port < 10000 )
		port += 10000;

	return 0;
}

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

		if( getrtpsession(p->sess, p->recvPort) < 0 )
		{
			printf("[checkErrorCount]  getrtpsession error \n");
			return -1;
		}

		sendInvitePlay(p->pliveVideoParams, p);
		error_count = 0;

		return 0;
	}

	return -1;
}

int jrtplib_rtp_recv_thread(void* arg)
{
    pthread_setname_np(pthread_self(), "recv_thread");

	//获取相机参数
	CameraParams *p = (CameraParams *)arg;

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

	uint32_t last_ts = 0;
	int error_count = 0;
	int ret = -1;
	//开始接收流包
	while (p->running)
	{
#ifndef RTP_SUPPORT_THREAD
		printf("not define RTP_SUPPORT_THREAD \n");
#endif

		int needsleep = 0;
		jrtplib::RTPPacket *pack = NULL;
		p->sess.BeginDataAccess();
		if (p->sess.GotoFirstSourceWithData())
		{
			pack = p->sess.GetNextPacket();
		}
		else
		{
//			printf("no data found \n");
			needsleep = 1;
			error_count++;
		}

		p->sess.EndDataAccess();

		if( pack )
		{
//					printf("Got packet! %d \n", pack->GetPayloadLength());

			if( error_count < 7 * 1000 )
				error_count = 0;
			
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


		if( checkErrorCount(p, error_count) >= 0 )
		{
			last_ts = 0;
		}
	
		if( needsleep )		
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	p->sess.BYEDestroy(jrtplib::RTPTime(0, 1000), 0, 0);

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
*/
	if (getrtpsession(param->sess, param->recvPort) < 0)
	{
		printf("getrtpsession error \n");
		return -1;
	}

	param->running = 1;
	param->status = 0;
	param->statusErrCnt = 0;
	param->writefile = record2file;//1;

	sendInvitePlay(inst, param);

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
