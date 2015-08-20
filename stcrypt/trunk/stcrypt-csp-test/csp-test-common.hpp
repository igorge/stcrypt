//================================================================================================================================================
// FILE: csp-test-common.h
// (c) GIE 2010-03-02  12:27
//
//================================================================================================================================================
#ifndef H_GUARD_CSP_TEST_COMMON_2010_03_02_12_27
#define H_GUARD_CSP_TEST_COMMON_2010_03_02_12_27
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <assert.h>
//================================================================================================================================================
const size_t large_buffer_for_sys_msg_size = 1024;

namespace {

	std::string recur_msg( char const) { return "Error while formatting error: "; }
	std::wstring recur_msg( wchar_t const) { return L"Error while formatting error: "; }

}

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

    if(count==0){
		auto const recur_id  = GetLastError();
		return recur_msg( char_t_t() ) +format_sys_message<char_t_t>(recur_id, remove_line_breaks);
	}

    return  std::basic_string<char_t_t>(format_buffer, count);
}


//================================================================================================================================================
#endif
//================================================================================================================================================
