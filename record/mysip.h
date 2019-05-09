#ifndef _MYSIP_H__
#define _MYSIP_H__

#ifndef WIN32
	#include <netinet/in.h>
	#include <arpa/inet.h>
#else
	#include <winsock2.h>
#endif

#include <map>
#include <thread>
#include <mutex>

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <time.h>
#include <eXosip2/eXosip.h>

#include "rtpsession.h"
#include "rtprandomurandom.h"
#include "rtpudpv4transmitter.h"
#include "rtpipv4address.h"
#include "rtpsessionparams.h"
#include "rtperrors.h"
#include "rtpsourcedata.h"

#include "psparser.h"
#include "ffdecoder.h"

#ifndef MAX_PATH
	#define MAX_PATH 128
#endif

struct liveVideoStreamParams;

typedef struct {
	char platformSipId[MAX_PATH];
	char platformIpAddr[MAX_PATH];
	int platformSipPort;
	char localSipId[MAX_PATH];
	char localIpAddr[MAX_PATH];
	int localSipPort;
	int SN;
	struct eXosip_t *eCtx;
	int running;

	std::thread msgthread;
} gb28181Params;

typedef struct {
	char sipId[MAX_PATH];
	char deviceip[MAX_PATH];
	char deviceport[MAX_PATH];
	char UserName[MAX_PATH];
	char UserPwd[MAX_PATH];
	int recvPort;
	int status;
	int statusErrCnt;
	FILE *fpH264;
	int running;

	int call_id;
	int dialog_id;
	int registerOk;
	int writefile;

	jrtplib::RTPSession sess;
	std::thread rtpthread;
	PsPacketParser parser;
	FFDecoder decoder;

	liveVideoStreamParams *pliveVideoParams;
} CameraParams;

struct liveVideoStreamParams {
	std::map<std::string, CameraParams> mapCameraParams;
	std::mutex cameraParamMutex;

	gb28181Params gb28181Param;
	int stream_input_type;
	int running;
};

int getdeviceinfo(liveVideoStreamParams *pliveVideoParams, char* deviceip, CameraParams **param);

//与相机进行消息交换的主线程
int MsgThreadProc(liveVideoStreamParams *p28181Params);

eXosip_t *mysip_init(int localport);

int mysip_uninit(struct eXosip_t *eCtx);

//请求视频信息，SDP信息
int sendInvitePlay(liveVideoStreamParams *pliveVideoParams, CameraParams *p);

//停止视频回传
int sendPlayBye(liveVideoStreamParams *pliveVideoParams, CameraParams *p);

//验证相机状态
int checkCameraStatus(liveVideoStreamParams *pliveVideoParams, CameraParams *p);

#endif