#include <thread>
#include <string>

#include "gb28181.h"

int main(int argc, char *argv[])
{

	void *handle = gb28181_init("10.0.1.222", 5060, "34020000002000000001");

	std::string deviceip = "10.0.1.242";
	while ( gb28181_getregisterstatus(handle, (char*)deviceip.c_str()) < 0 )
//	while (1)
	{
		printf("gb28181_getregisterstatus \n");

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	//	return 0;

	gb28181_startstream(handle, (char*)deviceip.c_str());

	int i = 0;
	while (1)
	{
		//		checkCameraStatus(&g_liveVideoParams);
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		if (i == 20)
			break;
//		i++;
	}

//	gb28181_stopstream(handle, (char*)deviceip.c_str());

	while (1)
	{
		//		checkCameraStatus(&g_liveVideoParams);
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		//		if (i == 20)
		//			break;
	}

	return 0;
}