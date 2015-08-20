//================================================================================================================================================
// FILE: stcrypt-cng-status.h
// (c) GIE 2010-08-09  19:48
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_STATUS_2010_08_09_19_48
#define H_GUARD_STCRYPT_CNG_STATUS_2010_08_09_19_48
//================================================================================================================================================
#pragma once
//================================================================================================================================================
//#include "NTSTATUS.H"

///////////////////////////////////////////////////////////////////////////////
//
// These NTSTATUS items are not currently defined in BCRYPT.H. Unitl this is
// corrected, the easiest way to make them available is to cut and paste them 
// from NTSTATUS.H...
//
#ifndef NTSTATUS
typedef LONG NTSTATUS, *PNSTATUS;
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_INVALID_SIGNATURE
	#define STATUS_INVALID_SIGNATURE         ((NTSTATUS)0xC000A000L)
#endif

#ifndef STATUS_SUCCESS
	#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
	#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
	#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
	#define STATUS_HMAC_NOT_SUPPORTED        ((NTSTATUS)0xC000A001L)
	#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
	#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_INVALID_PARAMETER
	#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif


//================================================================================================================================================
#endif
//================================================================================================================================================
