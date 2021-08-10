#include "WNetApi.h"

// 建立ipc连接
int WNetApi::WNetAddConnection2Api(LPWSTR lpRemoteName, LPWSTR lpDomainUserName, LPWSTR lpPassword)
{
	// wprintf(L"net use %s /u:%s %s\n", lpRemoteName, lpDomainUserName, lpPassword);
	DWORD dwRetVal;
	NETRESOURCE nr;
	DWORD dwFlags;

	memset(&nr, 0, sizeof(NETRESOURCE));			// 清空结构体变量的内存


	// 给结构体变量赋值
	nr.dwType = RESOURCETYPE_ANY;
	nr.lpLocalName = NULL;					// F:  映射到本地的磁盘，比如：Z盘等. 如果字符串为空，或者lpLocalName为NULL，则该函数将建立与网络资源的连接，而不会重定向本地设备
	nr.lpRemoteName = lpRemoteName;				// \\192.168.232.128\temp	目标机器开放共享的磁盘
	nr.lpProvider = NULL;


	dwFlags = CONNECT_UPDATE_PROFILE;
	dwRetVal = WNetAddConnection2(&nr, lpPassword, lpDomainUserName, dwFlags);

	// 判断是否成功建立连接
	if (dwRetVal == NO_ERROR)
	{
		// wprintf(L"[+] %s Connection success\n", nr.lpRemoteName);
		return 1;
	}
	else if (dwRetVal == 67)		// 网络未找到
	{
		// wprintf(L"[-] %s The network name could not be found.\n", nr.lpRemoteName);
		return 0;
	}
	else if (dwRetVal == 1326)	// 账号密码错误
	{
		// wprintf(L"[-] %s The user name or password is incorrect.\n", nr.lpRemoteName);
		return 0;
	}
	else						// 其他错误
	{
		// wprintf(L"[-] %s WNetAddConnection2 failed with error: %u\n", nr.lpRemoteName, dwRetVal);
		return 0;
	}

}

// 删除ipc连接
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

// 获取域机器列表
std::vector<std::wstring> WNetApi::NetGroupGetUsersApi(LPWSTR servername, LPWSTR groupname)
{
	wprintf(L"------------------------------------Get a list of domain computers------------------------------------\n");

	DWORD dwLevel = 1;
	GROUP_USERS_INFO_1* bufptr;
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesread;
	DWORD dwTotalentries;
	DWORD dwRetVul;
	std::vector<std::wstring> hostnameList;				// 定义vector，存放主机名

	dwRetVul = NetGroupGetUsers(servername, groupname, dwLevel, (LPBYTE*)&bufptr, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
	wprintf(L"num: %d\n", dwEntriesread);

	if (dwRetVul == NO_ERROR)
	{
		for (DWORD i = 0; i < dwEntriesread; i++)
		{
			// wprintf(L"[%u] %s   ", i, bufptr[i].grui1_name);
			std::wstring hostname(bufptr[i].grui1_name);
			hostname.replace(hostname.end() - 1, hostname.end(), 1, NULL);			// 主机名最末尾的$替换为空
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

// 列出本地管理组
std::vector<std::wstring> WNetApi::NetLocalGroupGetMembersApi(LPWSTR aliveIp)
{
	std::vector<std::wstring> ipAdministratorsGroup;

	LPCWSTR servername = aliveIp;				// 已经建立ipc连接的IP
	LPCWSTR TargetGroup = L"administrators";				// 本地组名
	LOCALGROUP_MEMBERS_INFO_2* buff;			// LOCALGROUP_MEMBERS_INFO_2结构，变量buff存放获取到的信息
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;	// 指定返回数据的首选最大长度，以字节为单位。如果指定MAX_PREFERRED_LENGTH，该函数将分配数据所需的内存量。
	DWORD dwEntriesread;						// 指向一个值的指针，该值接收实际枚举的元素数。
	DWORD dwTotalentries;
	NetLocalGroupGetMembers(servername, TargetGroup, 2, (LPBYTE*)&buff, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
	// wprintf(L"dwEntriesread: %d\ndwTotalentries: %d\n", dwEntriesread, dwTotalentries);
	for (DWORD i = 0; i < dwEntriesread; i++) {
		// wprintf(L"%s\n", buff[i].lgrmi2_domainandname);
		ipAdministratorsGroup.push_back(buff[i].lgrmi2_domainandname);
		// wprintf(L"SID:%d\n", buff[i].lgrmi2_sid);				// sid，不是很重要的数据
		// wprintf(L"SIDUSAGE:%d\n",buff[i].lgrmi2_sidusage);
	}
	return ipAdministratorsGroup;
}


// 探测主机存活
BOOL WNetApi::detectAlive(int i, LPWSTR ip, LPCWSTR ComputerName)
{

	DWORD dwRetVal;
	ULONG dstMac[2] = { 0 };
	memset(dstMac, 0xff, sizeof(dstMac));
	ULONG MacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	dwRetVal = SendARP(inet_addr(theCommonApi.UnicodeToAnsi(ip)), 0, &MacAddr, &PhysAddrLen);		// 发送arp，探测存活   inet_addr()是将一个点分制的IP地址(如192.168.0.1)转换为in_addr结构

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


// 列出指定域机器的net session会话
std::vector<LPSESSION_INFO_10> WNetApi::NetSessionEnumApi(LPWSTR aliveIp)
{
	std::vector<LPSESSION_INFO_10> ipNetSessions;


	LPSESSION_INFO_10 pBuf = NULL;
	LPSESSION_INFO_10 pTmpBuf;			// 接收pBuf的值
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
		nStatus = NetSessionEnum(pszServerName,			// 目标服务器
			pszClientName,			// 如果此参数为NULL，则 NetSessionEnum返回有关服务器上所有计算机会话的信息。
			pszUserName,			// 如果此参数为NULL，则 NetSessionEnum返回有关服务器上所有计算机会话的信息。
			dwLevel,				// 等级10， 返回计算机的名称，用户的名称以及会话的活动时间和空闲时间
			(LPBYTE*)&pBuf,			// 指向接收数据的缓冲区的指针。该数据的格式取决于level参数的值。
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
			//NetApiBufferFree(pBuf);			// 清空内存		一旦清内存了，可能会出错
			pBuf = NULL;
		}
	}

	while (nStatus == ERROR_MORE_DATA); // end do


	//if (pBuf != NULL)
		//NetApiBufferFree(pBuf);				// 清空内存



	return ipNetSessions;
}