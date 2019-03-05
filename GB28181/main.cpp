#include <thread>

#include "gb28181.h"

int main(int argc, char *argv[])
{

	void *handle = gb28181_init("10.0.1.59", 5060, "34020000002000000001");

	while (!gb28181_getregisterstatus(handle))
	{
		printf("gb28181_getregisterstatus \n");

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	//	return 0;

	gb28181_startstream(handle, "10.0.1.242", 5060, "34020000001320000001");

	//发送请求视频消息
	//	startCameraRealStream(&g_liveVideoParams);
	while (1)
	{
		//		checkCameraStatus(&g_liveVideoParams);
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		//		if (i == 20)
		//			break;
	}
	/*
	g_liveVideoParams.running = 0;
	stopCameraRealStream(&g_liveVideoParams);
	Sleep(300);
	stopStreamRecv(&g_liveVideoParams);
	g_liveVideoParams.gb28181Param.running = 0;
	Sleep(1000);
	printf("LiveVideoStream run over");
	*/
	return 0;
}