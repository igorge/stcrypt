// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the STCRYPTCSP_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// STCRYPTCSP_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
//================================================================================================================================================
#ifdef STCRYPTCSP_EXPORTS
#define STCRYPTCSP_API __declspec(dllexport)
#else
#define STCRYPTCSP_API __declspec(dllimport)
#endif
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "stcrypt-exception-filter.hpp"
//================================================================================================================================================

//================================================================================================================================================
