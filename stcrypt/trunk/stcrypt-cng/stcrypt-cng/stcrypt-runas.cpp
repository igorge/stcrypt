//================================================================================================================================================
// FILE: stcrypt-runas.cpp
// (c) GIE 2011-02-18  20:02
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-runas.hpp"
//================================================================================================================================================
#include "util-scope-exit.hpp"
#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"

#include <vector>
#include <boost/scope_exit.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/filesystem/path.hpp>

#define SECURITY_WIN32
#include <Security.h>
#include <Ntsecapi.h>
#include <Psapi.h>
#include <Sddl.h>
//================================================================================================================================================
namespace {

	std::vector<DWORD> get_all_pids(){
		CSP_LOG_TRACE

		std::vector<DWORD> all_pids;
		all_pids.reserve( 1024 );

		unsigned int pids_to_query = all_pids.capacity() / 2;

		unsigned int pids_current_returned;
		unsigned int pids_returned=0;

		for(;;){

			DWORD bytes_returned;
			all_pids.resize( pids_to_query );

			STCRYPT_CHECK_WIN( EnumProcesses(all_pids.data(), all_pids.size() * sizeof(DWORD), &bytes_returned) );
			STCRYPT_CHECK( bytes_returned%sizeof(DWORD)==0 );
			pids_current_returned=bytes_returned/sizeof(DWORD);

			if(pids_current_returned==pids_to_query ){
				pids_to_query*=2;
				continue;
			}

			if(pids_current_returned<=pids_returned){
				break;
			}

			pids_returned = pids_current_returned;

		}

		all_pids.resize( pids_current_returned );

		return all_pids;
	}



	DWORD find_lsass_pid () {
		CSP_LOG_TRACE

		auto const& all_pids = get_all_pids();

		auto const pid_iter = 
		boost::find_if( all_pids, [](DWORD const pid)->bool{

				auto const process_handle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );
				if (!process_handle){
					STCRYPT_LOG_PRINT_W_EX(L"OpenProcess() have failed", pid);
				} else  {
					wchar_t tmp_buffer[2*1024];
					auto const str_len=GetProcessImageFileName(process_handle, &tmp_buffer[0], sizeof(tmp_buffer)-1 );
					tmp_buffer[str_len]=0;
					if(!str_len){
						STCRYPT_LOG_PRINT_W_EX(L"GetProcessImageFileName() have failed", pid);
					} else {
						if( boost::filesystem::wpath( tmp_buffer ).leaf()==L"lsass.exe" ){//TODO:: case sensetive?
							return true;
						}
					}
				}


				return false;
		});

		STCRYPT_CHECK( pid_iter!=all_pids.end() );

		return *pid_iter;
	};


	std::unique_ptr<BYTE, std::default_delete<BYTE[]> >  get_from_token(HANDLE const token, TOKEN_INFORMATION_CLASS const tic)
	{
		DWORD n;
		BOOL const rv = GetTokenInformation(token, tic, 0, 0, &n);
		if(!rv){
			auto const last_error = GetLastError();
			STCRYPT_CHECK_EX( last_error == ERROR_INSUFFICIENT_BUFFER, stcrypt::exception::condition_check_failed() << stcrypt::exception::getlasterror_einfo(last_error) );
		}
		std::unique_ptr<BYTE, std::default_delete<BYTE[]> > tmp( new BYTE[n] );
		STCRYPT_CHECK_WIN ( GetTokenInformation(token, tic, tmp.get(), n, &n) );

		return tmp;
	};



	void enable_privilege(HANDLE const token,LPCTSTR const priv,bool do_enable = true) 	{ 
		CSP_LOG_TRACE

		TOKEN_PRIVILEGES tp = { 0 }; 
		// Initialize everything to zero 
		LUID luid; 
		DWORD cb=sizeof(TOKEN_PRIVILEGES); 
		STCRYPT_CHECK_WIN( LookupPrivilegeValue( NULL, priv, &luid ) );

		tp.PrivilegeCount = 1; 
		tp.Privileges[0].Luid = luid; 
		if(do_enable) { 
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
		} else { 
			tp.Privileges[0].Attributes = 0; 
		} 
		STCRYPT_CHECK_WIN( AdjustTokenPrivileges( token, FALSE, &tp, cb, NULL, NULL ) ); 
	}


	typedef struct _OBJECT_ATTRIBUTES {
		ULONG           Length;
		HANDLE          RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG           Attributes;
		PVOID           SecurityDescriptor;
		PVOID           SecurityQualityOfService;
	}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


	typedef NTSTATUS (NTAPI*ZwCreateToken_t)(
		OUT PHANDLE TokenHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN TOKEN_TYPE Type,
		IN PLUID AuthenticationId,
		IN PLARGE_INTEGER ExpirationTime,
		IN PTOKEN_USER User,
		IN PTOKEN_GROUPS Groups,
		IN PTOKEN_PRIVILEGES Privileges,
		IN PTOKEN_OWNER Owner,
		IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
		IN PTOKEN_DEFAULT_DACL DefaultDacl,
		IN PTOKEN_SOURCE Source
		);


} //end anon ns


namespace stcrypt {

	void runas_trustedinstaller( boost::function<void()> const& fun){
		CSP_LOG_TRACE

		//getting ZwCreateToken
		auto const ntdll_module = LoadLibraryW(L"ntdll.dll");
		STCRYPT_CHECK_WIN( ntdll_module );
		STCRYPT_SCOPE_EXIT([ntdll_module](){ STCRYPT_CHECK_WIN( FreeLibrary(ntdll_module) ); });

		ZwCreateToken_t stcrypt_ZwCreateToken = reinterpret_cast<ZwCreateToken_t>( GetProcAddress( ntdll_module, "ZwCreateToken" ) );
		STCRYPT_CHECK_WIN(stcrypt_ZwCreateToken);

		// getting TrustedInstaller sid
		PSID ti_sid = 0;
		STCRYPT_CHECK_WIN( ConvertStringSidToSid(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti_sid) );
		BOOST_SCOPE_EXIT((ti_sid)) { auto const status = LocalFree(ti_sid); assert(!status); }  BOOST_SCOPE_EXIT_END

 		// enable debug privilege
		HANDLE this_proc_token = 0;
 		STCRYPT_CHECK_WIN( OpenProcessToken( GetCurrentProcess(), TOKEN_ALL_ACCESS_P, &this_proc_token ) );
 		BOOST_SCOPE_EXIT((this_proc_token)) {auto const status = CloseHandle(this_proc_token); assert(status); }  BOOST_SCOPE_EXIT_END

		enable_privilege(this_proc_token, SE_DEBUG_NAME);

		// stealing lsass security token
		auto lsass_process_handle = OpenProcess(PROCESS_ALL_ACCESS , false, find_lsass_pid() );
		STCRYPT_CHECK_WIN( lsass_process_handle );
		BOOST_SCOPE_EXIT((lsass_process_handle)) {auto const status = CloseHandle(lsass_process_handle); assert(status); }  BOOST_SCOPE_EXIT_END

		HANDLE lsass_token;
		STCRYPT_CHECK_WIN( OpenProcessToken(lsass_process_handle,	TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE,	&lsass_token) );
		BOOST_SCOPE_EXIT((lsass_token)) {auto const status = CloseHandle(lsass_token); assert(status); }  BOOST_SCOPE_EXIT_END

		STCRYPT_CHECK_WIN( ImpersonateLoggedOnUser( lsass_token ) );
		BOOST_SCOPE_EXIT((lsass_token)) { auto const status = RevertToSelf(); assert(status); }  BOOST_SCOPE_EXIT_END

		
		//setting up new TrustedInstaller token
		TOKEN_USER user = {{ti_sid, 0}};
		LUID luid;
		STCRYPT_CHECK_WIN( AllocateLocallyUniqueId(&luid) );

		TOKEN_SOURCE source = {{'*', '*', '*', '*', '*', '*', '*', '*'}, {luid.LowPart, luid.HighPart}};


		LUID authid = SYSTEM_LUID;
		auto token_statistics_data = get_from_token(lsass_token, TokenStatistics);
		PTOKEN_STATISTICS stats = PTOKEN_STATISTICS( token_statistics_data.get() );

		SECURITY_QUALITY_OF_SERVICE sqos = {sizeof sqos, SecurityAnonymous,		SECURITY_STATIC_TRACKING, FALSE};

		OBJECT_ATTRIBUTES oa = {sizeof oa, 0, 0, 0, 0, &sqos};

		auto token_groups_data = get_from_token(lsass_token, TokenGroups);
		PTOKEN_GROUPS token_group_caller = reinterpret_cast<PTOKEN_GROUPS>( token_groups_data.get() );
		auto const token_group_count = token_group_caller->GroupCount+1;
		std::vector<BYTE> token_group_data( sizeof(TOKEN_GROUPS)+sizeof(SID_AND_ATTRIBUTES)*(token_group_count-1) );
		auto token_group = reinterpret_cast<PTOKEN_GROUPS>( token_group_data.data() );
		token_group->GroupCount = token_group_count;
		std::copy(&token_group_caller->Groups[0], &token_group_caller->Groups[0] + token_group_caller->GroupCount, &token_group->Groups[0]);

		auto & ti_grp = token_group->Groups[token_group->GroupCount-1];
		ti_grp.Sid = ti_sid;
		ti_grp.Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;

		TOKEN_PRIMARY_GROUP token_pimary_group = {0};
		token_pimary_group.PrimaryGroup = ti_sid;

		TOKEN_OWNER token_owner = {0};
		token_owner.Owner = ti_sid;

		HANDLE trusted_installer_token = 0;
		auto const nt_status = stcrypt_ZwCreateToken(&trusted_installer_token, TOKEN_ALL_ACCESS, &oa, TokenPrimary,
			PLUID(&authid),
			PLARGE_INTEGER(&stats->ExpirationTime),
			&user,
			token_group,//PTOKEN_GROUPS(get_from_token(hToken, TokenGroups).get() ),
			PTOKEN_PRIVILEGES(get_from_token(lsass_token, TokenPrivileges).get() ),
			&token_owner,//PTOKEN_OWNER(get_from_token(hToken, TokenOwner).get() ),
			&token_pimary_group, //PTOKEN_PRIMARY_GROUP(get_from_token(hToken, TokenPrimaryGroup).get() ),
			PTOKEN_DEFAULT_DACL(get_from_token(lsass_token, TokenDefaultDacl).get() ),
			&source);

		//switch(nt_status){
		//case 0xC0000061 /*STATUS_PRIVILEGE_NOT_HELD*/: STCRYPT_UNEXPECTED1("STATUS_PRIVILEGE_NOT_HELD");
		/*default:*/ STCRYPT_CHECK_EX( nt_status==STATUS_SUCCESS, exception::condition_check_failed() << exception::ntstatus_einfo(nt_status) );
		//}


		STCRYPT_CHECK_WIN( ImpersonateLoggedOnUser( trusted_installer_token ) );
		BOOST_SCOPE_EXIT((trusted_installer_token)) { auto const status = RevertToSelf(); assert(status); }  BOOST_SCOPE_EXIT_END

		fun();
	}

}
//================================================================================================================================================
