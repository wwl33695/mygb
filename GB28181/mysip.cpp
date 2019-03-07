#include "mysip.h"

void RegisterSuccess(struct eXosip_t * peCtx, eXosip_event_t *je)
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

int getdeviceinfo(liveVideoStreamParams *pliveVideoParams, char* deviceip, CameraParams **param)
{
	pliveVideoParams->cameraParamMutex.lock();

	std::map<std::string, CameraParams>::iterator iter = pliveVideoParams->mapCameraParams.find(deviceip);
	if (iter == pliveVideoParams->mapCameraParams.end())
	{
		printf("can not find camera:%s \n", deviceip);
		pliveVideoParams->cameraParamMutex.unlock();
		return -1;
	}

	*param = &iter->second;
	pliveVideoParams->cameraParamMutex.unlock();

	return 0;
}

int setdeviceinfo(liveVideoStreamParams *pliveVideoParams, char* deviceip, char* deviceport, char* deviceid)
{
	pliveVideoParams->cameraParamMutex.lock();

	if (pliveVideoParams->mapCameraParams.find(deviceip) == pliveVideoParams->mapCameraParams.end())
	{
		printf("setdeviceinfo add camerainfo:%s \n", deviceip);
		CameraParams &param = pliveVideoParams->mapCameraParams[deviceip];
		strcpy(param.sipId, deviceid);
		strcpy(param.deviceip, deviceip);
		strcpy(param.deviceport, deviceport);
		param.registerOk = 1;
		param.fpH264 = NULL;
	}

	pliveVideoParams->cameraParamMutex.unlock();

	return 0;
}

int setdeviceinfo(liveVideoStreamParams *pliveVideoParams, char* deviceip, int cid, int did)
{
	pliveVideoParams->cameraParamMutex.lock();

	if (pliveVideoParams->mapCameraParams.find(deviceip) != pliveVideoParams->mapCameraParams.end())
	{
		CameraParams &param = pliveVideoParams->mapCameraParams[deviceip];
		param.call_id = cid;
		param.dialog_id = did;
	}

	pliveVideoParams->cameraParamMutex.unlock();

	return 0;
}

//与相机进行消息交换的主线程
int MsgThreadProc(liveVideoStreamParams *pliveVideoParams)
{
	_gb28181Params *p28181Params = &pliveVideoParams->gb28181Param;
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
					printf("recv REGISTER \n");
					setdeviceinfo(pliveVideoParams,
						je->request->from->url->host,
						je->request->from->url->port,
						je->request->from->url->username);
				}
				else if (MSG_IS_MESSAGE(je->request))
				{
					printf("recv MESSAGE \n");
					osip_body_t *body = NULL;
					osip_message_get_body(je->request, 0, &body);
					if (body != NULL)
					{
						char* p = strstr(body->body, "Keepalive");
						if (p != NULL)
						{
							setdeviceinfo(pliveVideoParams,
								je->request->from->url->host,
								je->request->from->url->port,
								je->request->from->url->username);

							printf("msg body:%s\n", body->body);
						}
					}
					else
					{
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
				setdeviceinfo(pliveVideoParams, je->request->from->url->host, je->cid, je->did);
				printf("call answered method:%s, call_id:%d, dialog_id:%d\n", je->request->sip_method, je->cid, je->did);
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
	snprintf(dest_call, 256, "sip:%s@%s:%s", p->sipId, p->deviceip, p->deviceport);
	snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
	snprintf(subject, 128, "%s:0,%s:0", p->sipId, p28181Params->localSipId);

	osip_message_t *invite = NULL;
	struct eXosip_t *peCtx = p28181Params->eCtx;
	int ret = eXosip_call_build_initial_invite(peCtx, &invite, dest_call, source_call, NULL, subject);
	if (ret != 0)
	{
		printf("eXosip_call_build_initial_invite failed, %s,%s,%s", dest_call, source_call, subject);
		return -1;
	}

	//sdp
	char body[500];
	int bodyLen = snprintf(body, 500,
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
int sendPlayBye(liveVideoStreamParams *pliveVideoParams, CameraParams *p)
{
	struct eXosip_t *peCtx = pliveVideoParams->gb28181Param.eCtx;

	eXosip_lock(peCtx);
	eXosip_call_terminate(peCtx, p->call_id, p->dialog_id);
	eXosip_unlock(peCtx);
	return 0;
}

//验证相机状态
int checkCameraStatus(liveVideoStreamParams *pliveVideoParams, CameraParams *p)
{
	int i;
	gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

	if (p->status == 0)
	{
		p->statusErrCnt++;
		if (p->statusErrCnt % 10 == 0)
		{
			printf("camera %s is exception, restart it", p->sipId);
			p->call_id = -1;
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
