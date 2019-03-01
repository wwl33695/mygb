#include "filenameio.h"
#include <windows.h>

/*��ȡִ�г���·��*/
std::string GetMoudlePath()
{
	char chFullFileName[MAX_PATH];
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	GetModuleFileName(NULL, chFullFileName, MAX_PATH);
	//��ȡ�ļ�·��
	_splitpath(chFullFileName, chDrive, chDir, chFileName, chFileExt);

	//�ϲ��ļ�·��
	std::string strPath = chDrive;
	//strPath += "\\";
	strPath += chDir;
	//strPath += "\\";
	return strPath;
}

/*��ȡִ���ļ��ļ���*/
std::string GetMoudleName()
{
	char chFullFileName[MAX_PATH];
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	GetModuleFileName(NULL, chFullFileName, MAX_PATH);
	//��ȡ�ļ�·��
	_splitpath(chFullFileName, chDrive, chDir, chFileName, chFileExt);

	//�ϲ��ļ�·��
	std::string strPath = chFileName;
	strPath += ".";
	strPath += chFileExt;
	return strPath;
}

/*��ȡ�ļ���*/
std::string GetFileNameNoExt(std::string strFilePath)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//��ȡ�ļ�·��
	_splitpath(strFilePath.c_str(), chDrive, chDir, chFileName, chFileExt);

	//�ϲ��ļ�·��
	return std::string(chFileName);
}

/*��ȡ�ļ���׺��*/
std::string GetFileExt(std::string strFileName)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//��ȡ�ļ�·��
	_splitpath(strFileName.c_str(), chDrive, chDir, chFileName, chFileExt);

	//�ϲ��ļ�·��
	return std::string(chFileExt);
}

/*��ȡ�ļ�����������׺��*/
std::string GetFileName(std::string strFilePath)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//��ȡ�ļ�·��
	_splitpath(strFilePath.c_str(), chDrive, chDir, chFileName, chFileExt);

	//�ϲ��ļ�·��
	//�ϲ��ļ�·��
	std::string strPath = chFileName;
	strPath += ".";
	strPath += chFileExt;
	return strPath;
}

/*��ȡ�ļ�·��*/
std::string GetFilePath(std::string strFilePath)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//��ȡ�ļ�·��
	_splitpath(strFilePath.c_str(), chDrive, chDir, chFileName, chFileExt);

	//�ϲ��ļ�·��
	//�ϲ��ļ�·��
	std::string strPath = chDrive;
	strPath += "\\";
	strPath += chDir;
	strPath += "\\";
	return strPath;
}