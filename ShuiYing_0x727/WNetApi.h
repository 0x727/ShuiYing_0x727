#include "tou.h"
#include "CommonApi.h"
#pragma once
class WNetApi
{
	public:
		// ����ipc����
		int WNetAddConnection2Api(LPWSTR lpRemoteName, LPWSTR lpDomainUserName, LPWSTR lpPassword);

		// ɾ��ipc����
		int WNetCancelConnection2Api(LPWSTR lpRemoteName);

		// ��ȡ������б�
		std::vector<std::wstring> NetGroupGetUsersApi(LPWSTR servername, LPWSTR groupname);

		// �г����ع�����
		std::vector<std::wstring> NetLocalGroupGetMembersApi(LPWSTR aliveIp);

		// �г�ָ���������net session�Ự
		std::vector<LPSESSION_INFO_10> NetSessionEnumApi(LPWSTR aliveIp);

		// ̽���������
		BOOL detectAlive(int i, LPWSTR ip, LPCWSTR ComputerName);

	private:
		CommonApi theCommonApi;

};