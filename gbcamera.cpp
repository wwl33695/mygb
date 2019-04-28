#include "gbcamera.h"

int GBCamera::init(char* localip, int localport, char *localsipid, int gpu)
{
	playrequested = 0;
	m_gpu = gpu;

	inst = gb28181_init(localip, localport, localsipid);
	if( !inst )
		return -1;

	return 0;
}

int GBCamera::uninit()
{
	if( inst && !m_deviceip.empty() )
	{
		gb28181_stopstream(inst, (char*)m_deviceip.c_str());
	}

	gb28181_uninit(inst);
	inst = NULL;

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

	if( !playrequested && !m_deviceip.empty() )
	{
	    char* recordgb = getenv("recordgb");
	    int needrecord = 0;
	    if( recordgb )
	    	needrecord = atoi(recordgb);

		gb28181_startstream(inst, (char*)m_deviceip.c_str(), m_gpu, needrecord);
		playrequested = 1;		
	}

	while (1)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));

		int width = -1, height = -1;
		gb28181_getinfo(inst, (char*)m_deviceip.c_str(), &width, &height);
		if( width < 0 || height < 0 )
		{
			continue;
		}

		{		
	    	cv::Mat mat;
		    mat.create(height, width, CV_8UC3);
			if(  gb28181_getrgbdata(inst, (char*)m_deviceip.c_str(), (uint8_t*)mat.ptr(), width, height) >= 0 )
			{
				return mat;
				//break;
			}
		}

		//		checkCameraStatus(&g_liveVideoParams);
	}

//	return mat;
}
