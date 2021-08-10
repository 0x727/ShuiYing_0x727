#include "CommonApi.h"


// ��Unicodeת��ΪANSI
char* CommonApi::UnicodeToAnsi(const wchar_t* szStr)
{
	int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
	if (nLen == 0)
	{
		return NULL;
	}
	char* pResult = new char[nLen];
	WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
	return pResult;
}

// ��ANSIת��ΪUnicode
wchar_t* CommonApi::AnsiToUnicode(const char* str)
{
	int textlen;
	wchar_t* result;
	textlen = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	result = (wchar_t*)malloc((textlen + 1) * sizeof(wchar_t));
	memset(result, 0, (textlen + 1) * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str, -1, (LPWSTR)result, textlen);
	return result;
}



// �ַ����ָ�
std::vector<std::wstring> CommonApi::splitString(std::wstring strSrc, std::wstring pattern)
{
	std::vector<std::wstring> resultstr;

	// ������ַ�����󣬿��Խ�ȡ���һ������
	std::wstring strcom = strSrc.append(pattern);
	// wprintf(L"%s\n", strcom);
	auto pos = strSrc.find(pattern);
	auto len = strcom.size();

	//
	while (pos != std::wstring::npos)
	{
		std::wstring coStr = strcom.substr(0, pos);
		// wprintf(L"%s ", coStr.c_str());
		resultstr.push_back(coStr);

		strcom = strcom.substr(pos + pattern.size(), len);
		pos = strcom.find(pattern);
	}

	return resultstr;
}

// �����ļ�
HANDLE CommonApi::CreateFileApi(LPCWSTR fileName)
{
	HANDLE hFile;		// ���
	hFile = CreateFile(fileName,                // name of the write
		GENERIC_WRITE,          // open for writing
		FILE_SHARE_READ,                      // do not share
		NULL,                   // default security
		OPEN_ALWAYS,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	return hFile;
}

// �ļ�д������
VOID CommonApi::WriteFileApi(HANDLE hFile, LPWSTR content)
{
	LPSTR lpContent = UnicodeToAnsi(content);								// д���ļ�������
	DWORD dwBytesToWrite = (DWORD)strlen(lpContent);		// ���ݳ���
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;

	bErrorFlag = WriteFile(
		hFile,           // open file handle	
		lpContent,      // start of data to write
		dwBytesToWrite,  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);            // no overlapped structure

	if (FALSE == bErrorFlag)
	{
		printf("Terminal failure: Unable to write to file.\n");
	}
	else
	{
		if (dwBytesWritten != dwBytesToWrite)
		{
			// This is an error because a synchronous write that results in
			// success (WriteFile returns TRUE) should write all data as
			// requested. This would not necessarily be the case for
			// asynchronous writes.
			printf("Error: dwBytesWritten != dwBytesToWrite\n");
		}
		/*
		else
		{
			wprintf(TEXT("Wrote %d bytes to successfully.\n"), dwBytesWritten);
		}
		*/
	}
}

// ����ɹ�����IPC�Ľ��
void CommonApi::saveIPCok(HANDLE SuccessFile, LPWSTR lpUncComputerName, LPWSTR lpTotalAdministratorName, LPWSTR password)
{
	PWCHAR wstr = new WCHAR[MAX_PATH];
	wprintf(L"[OK] net use %s /u:%s %s\n", lpUncComputerName, lpTotalAdministratorName, password);
	StringCchPrintfW(wstr, MAX_PATH, L"net use %s /u:%s %s\n", lpUncComputerName, lpTotalAdministratorName, password);
	WriteFileApi(SuccessFile, wstr);
	delete wstr;
}