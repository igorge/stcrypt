// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the INJ_DLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// INJ_DLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef INJ_DLL_EXPORTS
#define INJ_DLL_API __declspec(dllexport)
#else
#define INJ_DLL_API __declspec(dllimport)
#endif


extern INJ_DLL_API int ninj_dll;

INJ_DLL_API int fninj_dll(void);
