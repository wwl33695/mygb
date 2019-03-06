#ifndef _GB28181_H__
#define _GB28181_H__

#include <stdio.h>

void *gb28181_init(char* localip, int localport, char *localsipid);

int gb28181_startstream(void *handle, char* deviceip);

int gb28181_stopstream(void *handle, char* deviceip);

int gb28181_getregisterstatus(void *handle, char* deviceip);

int gb28181_uninit(void *handle);

#endif