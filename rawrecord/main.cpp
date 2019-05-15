#include <thread>
#include <string>
#include <time.h>  
#include <sys/time.h>  

#include "gb28181.h"

uint8_t buffer[1024 * 1024 * 8] = {0};

std::string sysUsecTime()  
{  
	struct timeval tv;
    struct timezone tz;  
    gettimeofday(&tv, &tz);  

    tm *p = localtime(&tv.tv_sec);  
//    printf("%d /%d /%d %d :%d :%d.%3ld\n", 1900+p->tm_year, 1+p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, tv.tv_usec);  
	char timestr[128] = {0};
	sprintf(timestr, "%04d%02d%02d_%02d%02d%02d_%d", 
		1900+p->tm_year, 1+p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, tv.tv_usec/1000);

	return timestr;
}  

int main(int argc, char *argv[])
{
	if( argc < 4 )
	{
		printf("usage: gb28181 [localip] [localport] [cameraip] \n");
		return -1;
	}

	char *localip = argv[1];
	int localport = atoi(argv[2]);
	char *cameraip = argv[3];

	int record2file = 1;//atoi(argv[4]);

	void *handle = gb28181_init(localip, localport, "34020000002000000001");
	std::string deviceip = cameraip;
	while ( gb28181_getregisterstatus(handle, (char*)deviceip.c_str()) < 0 )
	{
		printf("gb28181_getregisterstatus \n");

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	//	return 0;

	gb28181_startstream(handle, (char*)deviceip.c_str(), 0, record2file);

	int width = 1920;
	int height = 1080;
	int i = 1;
	uint32_t totalcount = 1;
	while (1)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

//	gb28181_stopstream(handle, (char*)deviceip.c_str());

	return 0;
}