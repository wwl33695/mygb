#include <thread>
#include <string>

//#include "gb28181.h"
#include "gbcamera.h"

uint8_t buffer[1024 * 1024 * 8] = {0};

int main(int argc, char *argv[])
{
	if( argc < 4 )
		return -1;

	char *localip = argv[1];
	int localport = atoi(argv[2]);
	char *cameraip = argv[3];

	GBCamera camera;
	camera.init(localip, localport, "34020000002000000001");

	camera.setdeviceip(cameraip);

	int width = 1080;
	int height = 720;
	int i = 0;
	while (1)
	{
		cv::Mat mat = camera.getframe();
		if( !mat.empty() )
		{
			char filename[128] = {0};
			sprintf(filename, "%d_1234.jpg", i);
			cv::imwrite(filename, mat);

			i++;
		}

		//		checkCameraStatus(&g_liveVideoParams);
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

/*
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

	int width = 1080;
	int height = 720;
	int i = 0;
	while (1)
	{
		if(  gb28181_getrgbdata(handle, (char*)deviceip.c_str(), buffer, width, height) >= 0 )
		{
			char filename[128] = {0};
			sprintf(filename, "%d_1234.rgb", i);
			FILE* file = fopen(filename, "wb");
			fwrite(buffer, 1, width*height*3, file);
			fclose(file);

			i++;
		}

		//		checkCameraStatus(&g_liveVideoParams);
		std::this_thread::sleep_for(std::chrono::milliseconds(10));

//		if (i == 20)
//			break;
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
*/
	return 0;
}