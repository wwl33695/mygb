#include "gbcamera.h"

int GBCamera::init(char* localip, int localport, char *localsipid)
{
	playrequested = 0;

	inst = gb28181_init(localip, localport, localsipid);
	if( !inst )
		return -1;

	return 0;
}

void GBCamera::setdeviceip(char* deviceip)
{
	m_deviceip = deviceip;
}

cv::Mat GBCamera::getframe()
{
	while ( gb28181_getregisterstatus(inst, (char*)m_deviceip.c_str() ) < 0 )
//	while (1)
	{
		printf("gb28181_getregisterstatus \n");

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	//	return 0;

	if( !playrequested )
	{
		gb28181_startstream(inst, (char*)m_deviceip.c_str());
		playrequested = 1;		
	}

    cv::Mat mat;
	int width, height;
	while (1)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));

		gb28181_getinfo(inst, (char*)m_deviceip.c_str(), &width, &height);
		if( width < 0 || height < 0 )
		{
			continue;
		}

	    mat.create(height, width, CV_8UC3);
		if(  gb28181_getrgbdata(inst, (char*)m_deviceip.c_str(), (uint8_t*)mat.ptr(), width, height) >= 0 )
		{
			break;
		}

		//		checkCameraStatus(&g_liveVideoParams);
	}

	return mat;
}
