#ifndef _FILE_NAME_IO_H_
#define _FILE_NAME_IO_H_

#include <iostream>

/*��ȡִ�г���·��*/
std::string GetMoudlePath();

/*��ȡִ���ļ��ļ���*/
std::string GetMoudleName();

/*��ȡ�ļ���*/
std::string GetFileNameNoExt(std::string strFilePath);

/*��ȡ�ļ���׺��*/
std::string GetFileExt(std::string strFileName);

/*��ȡ�ļ�����������׺��*/
std::string GetFileName(std::string strFilePath);

/*��ȡ�ļ�·��*/
std::string GetFilePath(std::string strFilePath);

#endif