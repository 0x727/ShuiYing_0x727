#include "tou.h"
#include "CommonApi.h"
#include "WNetApi.h"

#pragma once
class multiThread
{
	public:
		// 构造函数
		multiThread(LPWSTR lpDomainUserName, LPWSTR lpPassword, std::vector<std::wstring> stdPasswordList, 
			HANDLE hAliveFile, HANDLE hLocalFile, HANDLE hSuccessFile, HANDLE hNetSessionsFile);

		// 取数据
		void attack(int i, std::vector<std::wstring>* hostnameList);

		// 开始跑
		void run(int i, LPCWSTR lpComputerName);

		// 获取域机器的net session
		void multiThread::getNetSessions(int i, LPCWSTR ComputerName, LPWSTR aliveIp);

		// 弱口令爆破
		BOOL multiThread::weakPasswordBlasting(int i, LPCWSTR ComputerName, std::vector<std::wstring> ipAdministratorsGroup, 
			HANDLE SuccessFile);

		// 保存存活的域机器
		void multiThread::saveAlive(LPCWSTR ComputerName, LPWSTR ip);

		// 保存存活的域机器的本地管理组
		void multiThread::saveLocal(LPCWSTR ComputerName, std::wstring eachAdministrator);

		// 保存每台域机器的net sessions
		void multiThread::saveNetSessions(LPCWSTR ComputerName, LPSESSION_INFO_10 ipNetSession);

	private:
		CommonApi theCommonApi;
		WNetApi theWNetApi;
		LPWSTR DomainUserName;		// hack\iis_user
		LPWSTR DomainUserPassword;   // 域用户的密码
		LPCWSTR DomainName;
		LPCWSTR UserName;
		std::vector<std::wstring> PasswordList;
		HANDLE LocalFile;
		HANDLE AliveFile;
		HANDLE SuccessFile;
		HANDLE NetSessionsFile;
};

