#include "WNetApi.h"

// ����ipc����
int WNetApi::WNetAddConnection2Api(LPWSTR lpRemoteName, LPWSTR lpDomainUserName, LPWSTR lpPassword)
{
	// wprintf(L"net use %s /u:%s %s\n", lpRemoteName, lpDomainUserName, lpPassword);
	DWORD dwRetVal;
	NETRESOURCE nr;
	DWORD dwFlags;

	memset(&nr, 0, sizeof(NETRESOURCE));			// ��սṹ��������ڴ�


	// ���ṹ�������ֵ
	nr.dwType = RESOURCETYPE_ANY;
	nr.lpLocalName = NULL;					// F:  ӳ�䵽���صĴ��̣����磺Z�̵�. ����ַ���Ϊ�գ�����lpLocalNameΪNULL����ú�����������������Դ�����ӣ��������ض��򱾵��豸
	nr.lpRemoteName = lpRemoteName;				// \\192.168.232.128\temp	Ŀ��������Ź���Ĵ���
	nr.lpProvider = NULL;


	dwFlags = CONNECT_UPDATE_PROFILE;
	dwRetVal = WNetAddConnection2(&nr, lpPassword, lpDomainUserName, dwFlags);

	// �ж��Ƿ�ɹ���������
	if (dwRetVal == NO_ERROR)
	{
		// wprintf(L"[+] %s Connection success\n", nr.lpRemoteName);
		return 1;
	}
	else if (dwRetVal == 67)		// ����δ�ҵ�
	{
		// wprintf(L"[-] %s The network name could not be found.\n", nr.lpRemoteName);
		return 0;
	}
	else if (dwRetVal == 1326)	// �˺��������
	{
		// wprintf(L"[-] %s The user name or password is incorrect.\n", nr.lpRemoteName);
		return 0;
	}
	else						// ��������
	{
		// wprintf(L"[-] %s WNetAddConnection2 failed with error: %u\n", nr.lpRemoteName, dwRetVal);
		return 0;
	}

}

// ɾ��ipc����
int WNetApi::WNetCancelConnection2Api(LPWSTR lpRemoteName)
{
	DWORD dwRetVal;
	dwRetVal = WNetCancelConnection2(lpRemoteName, 0, TRUE);

	if (dwRetVal == NO_ERROR)
	{
		// wprintf(L"Connection cancel to %s\n", lpRemoteName);
		return 1;
	}
	else
	{
		// wprintf(L"WNetCancelConnection2 failed with error: %u\n", dwRetVal);
		return 0;
	}
}

// ��ȡ������б�
std::vector<std::wstring> WNetApi::NetGroupGetUsersApi(LPWSTR servername, LPWSTR groupname)
{
	wprintf(L"------------------------------------Get a list of domain computers------------------------------------\n");

	DWORD dwLevel = 1;
	GROUP_USERS_INFO_1* bufptr;
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesread;
	DWORD dwTotalentries;
	DWORD dwRetVul;
	std::vector<std::wstring> hostnameList;				// ����vector�����������

	dwRetVul = NetGroupGetUsers(servername, groupname, dwLevel, (LPBYTE*)&bufptr, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
	wprintf(L"num: %d\n", dwEntriesread);

	if (dwRetVul == NO_ERROR)
	{
		for (DWORD i = 0; i < dwEntriesread; i++)
		{
			// wprintf(L"[%u] %s   ", i, bufptr[i].grui1_name);
			std::wstring hostname(bufptr[i].grui1_name);
			hostname.replace(hostname.end() - 1, hostname.end(), 1, NULL);			// ��������ĩβ��$�滻Ϊ��
			hostnameList.push_back(hostname.data());							// 
			wprintf(L"%s\n", hostname.data());
		}



		return hostnameList;
	}
	else
	{
		wprintf(L"error : %u\nhttps://docs.microsoft.com/en-us/windows/win32/netmgmt/network-management-error-codes", dwRetVul);
		exit(0);
	}


}

// �г����ع�����
std::vector<std::wstring> WNetApi::NetLocalGroupGetMembersApi(LPWSTR aliveIp)
{
	std::vector<std::wstring> ipAdministratorsGroup;

	LPCWSTR servername = aliveIp;				// �Ѿ�����ipc���ӵ�IP
	LPCWSTR TargetGroup = L"administrators";				// ��������
	LOCALGROUP_MEMBERS_INFO_2* buff;			// LOCALGROUP_MEMBERS_INFO_2�ṹ������buff��Ż�ȡ������Ϣ
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;	// ָ���������ݵ���ѡ��󳤶ȣ����ֽ�Ϊ��λ�����ָ��MAX_PREFERRED_LENGTH���ú�������������������ڴ�����
	DWORD dwEntriesread;						// ָ��һ��ֵ��ָ�룬��ֵ����ʵ��ö�ٵ�Ԫ������
	DWORD dwTotalentries;
	NetLocalGroupGetMembers(servername, TargetGroup, 2, (LPBYTE*)&buff, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
	// wprintf(L"dwEntriesread: %d\ndwTotalentries: %d\n", dwEntriesread, dwTotalentries);
	for (DWORD i = 0; i < dwEntriesread; i++) {
		// wprintf(L"%s\n", buff[i].lgrmi2_domainandname);
		ipAdministratorsGroup.push_back(buff[i].lgrmi2_domainandname);
		// wprintf(L"SID:%d\n", buff[i].lgrmi2_sid);				// sid�����Ǻ���Ҫ������
		// wprintf(L"SIDUSAGE:%d\n",buff[i].lgrmi2_sidusage);
	}
	return ipAdministratorsGroup;
}


// ̽���������
BOOL WNetApi::detectAlive(int i, LPWSTR ip, LPCWSTR ComputerName)
{

	DWORD dwRetVal;
	ULONG dstMac[2] = { 0 };
	memset(dstMac, 0xff, sizeof(dstMac));
	ULONG MacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	dwRetVal = SendARP(inet_addr(theCommonApi.UnicodeToAnsi(ip)), 0, &MacAddr, &PhysAddrLen);		// ����arp��̽����   inet_addr()�ǽ�һ������Ƶ�IP��ַ(��192.168.0.1)ת��Ϊin_addr�ṹ

	if (dwRetVal == NO_ERROR)
	{
		wprintf(L"[#%d] %s -> %s is alive.\n", i, ComputerName, ip);
		return TRUE;
	}
	else {
		wprintf(L"[#%d] %s -> %s is die.  ", i, ComputerName, ip);
		// printf("[#%d] Error: %s SendArp failed with error: %d", i, ip, dwRetVal);
		switch (dwRetVal) {
		case ERROR_GEN_FAILURE:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_INVALID_PARAMETER:
			printf(" (ERROR_INVALID_PARAMETER)\n");
			break;
		case ERROR_INVALID_USER_BUFFER:
			printf(" (ERROR_INVALID_USER_BUFFER)\n");
			break;
		case ERROR_BAD_NET_NAME:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_BUFFER_OVERFLOW:
			printf(" (ERROR_BUFFER_OVERFLOW)\n");
			break;
		case ERROR_NOT_FOUND:
			printf(" (ERROR_NOT_FOUND)\n");
			break;
		default:
			printf("\n");
			break;
		}
		return FALSE;
	}
}


// �г�ָ���������net session�Ự
std::vector<LPSESSION_INFO_10> WNetApi::NetSessionEnumApi(LPWSTR aliveIp)
{
	std::vector<LPSESSION_INFO_10> ipNetSessions;


	LPSESSION_INFO_10 pBuf = NULL;
	LPSESSION_INFO_10 pTmpBuf;			// ����pBuf��ֵ
	DWORD dwLevel = 10;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	LPTSTR pszServerName = aliveIp;
	LPTSTR pszClientName = NULL;
	LPTSTR pszUserName = NULL;
	NET_API_STATUS nStatus;

	do
	{
		nStatus = NetSessionEnum(pszServerName,			// Ŀ�������
			pszClientName,			// ����˲���ΪNULL���� NetSessionEnum�����йط����������м�����Ự����Ϣ��
			pszUserName,			// ����˲���ΪNULL���� NetSessionEnum�����йط����������м�����Ự����Ϣ��
			dwLevel,				// �ȼ�10�� ���ؼ���������ƣ��û��������Լ��Ự�Ļʱ��Ϳ���ʱ��
			(LPBYTE*)&pBuf,			// ָ��������ݵĻ�������ָ�롣�����ݵĸ�ʽȡ����level������ֵ��
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle);

		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{

				for (i = 0; (i < dwEntriesRead); i++)
				{
					if (pTmpBuf == NULL)
					{
						fprintf(stderr, "An access violation has occurred\n");
						break;
					}
					ipNetSessions.push_back(pTmpBuf);

					/*
					wprintf(L"\tClient: %s\t", pTmpBuf->sesi10_cname);
					wprintf(L"\tUser:   %s\t", pTmpBuf->sesi10_username);
					printf("\tActive: %d\n", pTmpBuf->sesi10_time);
					*/

					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}

		else
			fprintf(stderr, "A system error has occurred: %d\n", nStatus);

		if (pBuf != NULL)
		{
			//NetApiBufferFree(pBuf);			// ����ڴ�		һ�����ڴ��ˣ����ܻ����
			pBuf = NULL;
		}
	}

	while (nStatus == ERROR_MORE_DATA); // end do


	//if (pBuf != NULL)
		//NetApiBufferFree(pBuf);				// ����ڴ�



	return ipNetSessions;
}