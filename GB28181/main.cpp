#include "gb28181.h"

//主函数
int main(int argc, char *argv[])
{

	HANDLE hHandle;

	//打印日志
	std::string strLogPath = GetMoudlePath();
	strLogPath += "log.txt";
	g_fp = fopen(strLogPath.c_str(), "wt");
	if (g_fp == NULL)
		return 0;


	//1.解析配置文件获取相机相关配置
	ParserIniFile();

	g_liveVideoParams.running = 1;
	g_liveVideoParams.gb28181Param.running = 1;

	//启动服务器线程，将监听端口传输给线程，用来监听相机传回来的消息
	if ((hHandle = (HANDLE)_beginthreadex(NULL, 0, gb28181ServerThread, (void*)&(g_liveVideoParams.gb28181Param), 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("error pthread_create gb28181ServerThread err");
		fprintf(g_fp, "error, pthread_create gb28181ServerThread err");
	}
	else
	{
		CloseHandle(hHandle);
	}

	int tmpCnt = 20;
	while ((!g_liveVideoParams.gb28181Param.registerOk) && (tmpCnt > 0))
	{
		printf("waiting register %d...\n", tmpCnt);
		fprintf(g_fp, "waiting register %d...\n", tmpCnt--);
		Sleep(1000);
		if (tmpCnt == 0)
			exit(-1);
	}

	return 0;

	//发送请求catalog消息
	sendQueryCatalog(&(g_liveVideoParams.gb28181Param));

	//接收视频流
	startStreamRecv(&g_liveVideoParams);
	Sleep(1000);

	int i = 0;

	//发送请求视频消息
	startCameraRealStream(&g_liveVideoParams);
	while (g_liveVideoParams.running)
	{
		i++;
		checkCameraStatus(&g_liveVideoParams);
		Sleep(2000);
		if (i == 20)
			break;
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