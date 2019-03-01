#include "gb28181.h"

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

	//��������catalog��Ϣ
	sendQueryCatalog(&(g_liveVideoParams.gb28181Param));

	//������Ƶ��
	startStreamRecv(&g_liveVideoParams);
	Sleep(1000);

	int i = 0;

	//����������Ƶ��Ϣ
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