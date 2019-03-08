#ifndef _GBCAMERA_H__
#define _GBCAMERA_H__

#include <stdint.h>
#include <thread>
#include <string>
#include <opencv2/opencv.hpp>

#include "gb28181.h"

class GBCamera
{
public:
	int init(char* localip, int localport, char *localsipid);

	cv::Mat getframe();

	void setdeviceip(char* deviceip);

private:
	void *inst;
	
	std::string m_deviceip;

	int playrequested;
};

#endif