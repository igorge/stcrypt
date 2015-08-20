// inj_controller.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "detours.h"

const size_t large_buffer_for_sys_msg_size = 1024;

template <typename char_t_t>
const std::basic_string<char_t_t> format_sys_message(const DWORD msg_id, const bool remove_line_breaks = true)
{
	TCHAR format_buffer[ large_buffer_for_sys_msg_size ];
	DWORD count = FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
		, NULL  //cause from system
		, msg_id
		, 0 //any lang
		, format_buffer
		, sizeof(format_buffer)
		, NULL
		);

	if(remove_line_breaks)
		for( unsigned int i=0; i<count; ++i)
			if( format_buffer[i]==_TEXT('\n') || format_buffer[i]==_TEXT('\r') ) format_buffer[i]=_TEXT(' ');

	assert(count!=0);

	return  std::basic_string<char_t_t>(format_buffer, count);
}

typedef 	HCRYPTPROV (WINAPI *I_CryptGetDefaultCryptProv_TYPE)(ALG_ID algid);

int _tmain(int argc, _TCHAR* argv[])
{


	HINSTANCE hinstDLL = LoadLibrary((LPCTSTR) "..\\inj_dll\\Debug\\inj_dll.dll"); 
	if( hinstDLL == NULL )
	{
		DWORD const error = GetLastError();
		format_sys_message<char>(error);
		std::string const& msg = format_sys_message<char>(error) ;
		std::cerr << msg << "\n"; 

		std::cout<<"failed to load hook dll\n";
		return 666;

	}

	HOOKPROC hkprcSysMsg = (HOOKPROC)GetProcAddress(hinstDLL, "_CallWndProc@12"); 
	HHOOK  hook = SetWindowsHookEx(WH_CALLWNDPROC,hkprcSysMsg,hinstDLL,0); 

	if( hook != NULL )
	{
	}
	else
	{
		std::cout<<"failed to install hook\n";
	}


	//deinit
	std::cout<<"Press enter to exit.\n";
	getchar();

	BOOL r = UnhookWindowsHookEx (hook);
// 	if( argc!=3 )
// 	{
// 		std::cout<<"No process id given.\n";
// 		return 1;
// 	}
// 	
// 	DWORD iProcess = atoi(argv[1]);
// 
// 	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE, iProcess );
// 
//     if( hProcess == NULL )
// 	{
// 		std::cout<<"failed to open proccess\n";
// 		return 2;
// 	}
// 
// 	if (!DetourContinueProcessWithDllA(hProcess, argv[2] /*"D:\\My Documents\\PROJECTS\\.test\\api_intercept\\inj_dll\\Debug\\inj_dll.dll"*/ )) 
// 	{
// 		std::cout<<"failed\n";
// 		return 3;
// 	}
// 
// 	CloseHandle(hProcess);
// 
	return 0;
}

