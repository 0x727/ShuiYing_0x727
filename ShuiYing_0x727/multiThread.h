#include "tou.h"
#include "CommonApi.h"
#include "WNetApi.h"

#pragma once
class multiThread
{
	public:
		// ���캯��
		multiThread(LPWSTR lpDomainUserName, LPWSTR lpPassword, std::vector<std::wstring> stdPasswordList, 
			HANDLE hAliveFile, HANDLE hLocalFile, HANDLE hSuccessFile, HANDLE hNetSessionsFile);

		// ȡ����
		void attack(int i, std::vector<std::wstring>* hostnameList);

		// ��ʼ��
		void run(int i, LPCWSTR lpComputerName);

		// ��ȡ�������net session
		void multiThread::getNetSessions(int i, LPCWSTR ComputerName, LPWSTR aliveIp);

		// �������
		BOOL multiThread::weakPasswordBlasting(int i, LPCWSTR ComputerName, std::vector<std::wstring> ipAdministratorsGroup, 
			HANDLE SuccessFile);

		// ������������
		void multiThread::saveAlive(LPCWSTR ComputerName, LPWSTR ip);

		// �������������ı��ع�����
		void multiThread::saveLocal(LPCWSTR ComputerName, std::wstring eachAdministrator);

		// ����ÿ̨�������net sessions
		void multiThread::saveNetSessions(LPCWSTR ComputerName, LPSESSION_INFO_10 ipNetSession);

	private:
		CommonApi theCommonApi;
		WNetApi theWNetApi;
		LPWSTR DomainUserName;		// hack\iis_user
		LPWSTR DomainUserPassword;   // ���û�������
		LPCWSTR DomainName;
		LPCWSTR UserName;
		std::vector<std::wstring> PasswordList;
		HANDLE LocalFile;
		HANDLE AliveFile;
		HANDLE SuccessFile;
		HANDLE NetSessionsFile;
};

