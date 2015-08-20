// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>


#include "stcrypt-debug.hpp"

#include <boost/format.hpp>



#define GIE_DEBUG_LOG4(x,y,z,u)  do{ auto const xx = x+std::string("\n"); OutputDebugStringA( (boost::format(xx) %y%z%u).str().c_str() ); }while(false)




// TODO: reference additional headers your program requires here
