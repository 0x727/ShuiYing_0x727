#pragma once
#include "tou.h"
#define BUFFSIZE 1024


class LdapApi
{
public:
	// ���캯��
	LdapApi(std::wstring Host, PWCHAR UserName, PWCHAR Password, HANDLE DelegFile);

	// ldap ����
	int connect();

	// ί��©����������Դ��Լ��ί�ɣ�
	int delegationVul(PWSTR pMyFilter, PWCHAR pMyAttributes[]);

	// ������Դ��Լ��ί�� Resource-based constrained delegation
	void RBCD();

	// Լ��ί��
	void CD();

	// ��Լ��ί�� unconstrained delegation
	void ud();

private:
	std::wstring sHost;
	PWCHAR pUserName;
	PWCHAR pPassword;
	HANDLE hDelegFile;
	PWSTR pMyDN;
	LDAP* pLdapConnection;
	std::wstring wsHost;
};

