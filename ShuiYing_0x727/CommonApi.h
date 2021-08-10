#include "tou.h"
#pragma once
class CommonApi
{
public:
	// ��Unicodeת��ΪANSI
	char* UnicodeToAnsi(const wchar_t* szStr);

	// ��ANSIת��ΪUnicode
	wchar_t* AnsiToUnicode(const char* str);

	// �ַ����ָ�
	std::vector<std::wstring> splitString(std::wstring strSrc, std::wstring pattern);

	// �����ļ�
	HANDLE CreateFileApi(LPCWSTR fileName);

	// �ļ�д������
	VOID WriteFileApi(HANDLE hFile, LPWSTR content);

	// ����ɹ�����IPC�Ľ��
	void saveIPCok(HANDLE SuccessFile, LPWSTR lpUncComputerName, LPWSTR lpTotalAdministratorName, LPWSTR password);

};