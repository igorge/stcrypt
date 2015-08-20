#pragma once

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#define WIN32_LEAN_AND_MEAN

#include <crtdbg.h>
#include <assert.h> 
#include <Windows.h>

#include <QtGui>
#include <QMessageBox>


