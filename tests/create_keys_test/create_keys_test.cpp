// create_keys_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>

//-------------------------------------------------------------------
// This example uses the function MyHandleError, a simple error
// handling function to print an error message and exit 
// the program. 
// For most applications, replace this function with one 
// that does more extensive error reporting.

void MyHandleError(LPTSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	exit(1);
} // End of MyHandleError.



int _tmain(int argc, _TCHAR* argv[])
{
		// Handle for the cryptographic provider context.
		HCRYPTPROV hCryptProv;        

		// The name of the container.
		LPCTSTR pszContainerName = TEXT("My Sample Key Container");

		//---------------------------------------------------------------
		// Begin processing. Attempt to acquire a context by using the 
		// specified key container.
		if(CryptAcquireContext(
			&hCryptProv,
			pszContainerName,
			NULL,
			PROV_RSA_FULL,
			0))
		{
			_tprintf(
				TEXT("A crypto context with the %s key container ")
				TEXT("has been acquired.\n"), 
				pszContainerName);
		}
		else
		{ 
			//-----------------------------------------------------------
			// Some sort of error occurred in acquiring the context. 
			// This is most likely due to the specified container 
			// not existing. Create a new key container.
			if(GetLastError() == NTE_BAD_KEYSET)
			{
				if(CryptAcquireContext(
					&hCryptProv, 
					pszContainerName, 
					NULL, 
					PROV_RSA_FULL, 
					CRYPT_NEWKEYSET)) 
				{
					_tprintf(TEXT("A new key container has been ")
						TEXT("created.\n"));
				}
				else
				{
					MyHandleError(TEXT("Could not create a new key ")
						TEXT("container.\n"));
				}
			}
			else
			{
				MyHandleError(TEXT("CryptAcquireContext failed.\n"));
			}
		}

		//---------------------------------------------------------------
		// A context with a key container is available.
		// Attempt to get the handle to the signature key. 

		// Public/private key handle.
		HCRYPTKEY hKey;               

		if(CryptGetUserKey(
			hCryptProv,
			AT_SIGNATURE,
			&hKey))
		{
			_tprintf(TEXT("A signature key is available.\n"));
		}
		else
		{
			_tprintf(TEXT("No signature key is available.\n"));
			if(GetLastError() == NTE_NO_KEY) 
			{
				//-------------------------------------------------------
				// The error was that there is a container but no key.

				// Create a signature key pair. 
				_tprintf(TEXT("The signature key does not exist.\n"));
				_tprintf(TEXT("Create a signature key pair.\n")); 
				if(CryptGenKey(
					hCryptProv,
					AT_SIGNATURE,
					0,
					&hKey)) 
				{
					_tprintf(TEXT("Created a signature key pair.\n"));
				}
				else
				{
					MyHandleError(TEXT("Error occurred creating a ")
						TEXT("signature key.\n")); 
				}
			}
			else
			{
				MyHandleError(TEXT("An error other than NTE_NO_KEY ")
					TEXT("getting a signature key.\n"));
			}
		} // End if.

		_tprintf(TEXT("A signature key pair existed, or one was ")
			TEXT("created.\n\n"));

		// Destroy the signature key.
		if(hKey)
		{
			if(!(CryptDestroyKey(hKey)))
			{
				MyHandleError(TEXT("Error during CryptDestroyKey."));
			}

			hKey = NULL;
		} 

		// Next, check the exchange key. 
		if(CryptGetUserKey(
			hCryptProv,
			AT_KEYEXCHANGE,
			&hKey)) 
		{
			_tprintf(TEXT("An exchange key exists.\n"));
		}
		else
		{
			_tprintf(TEXT("No exchange key is available.\n"));

			// Check to determine whether an exchange key 
			// needs to be created.
			if(GetLastError() == NTE_NO_KEY) 
			{ 
				// Create a key exchange key pair.
				_tprintf(TEXT("The exchange key does not exist.\n"));
				_tprintf(TEXT("Attempting to create an exchange key ")
					TEXT("pair.\n"));
				if(CryptGenKey(
					hCryptProv,
					AT_KEYEXCHANGE,
					0,
					&hKey)) 
				{
					_tprintf(TEXT("Exchange key pair created.\n"));
				}
				else
				{
					MyHandleError(TEXT("Error occurred attempting to ")
						TEXT("create an exchange key.\n"));
				}
			}
			else
			{
				MyHandleError(TEXT("An error other than NTE_NO_KEY ")
					TEXT("occurred.\n"));
			}
		}

		// Destroy the exchange key.
		if(hKey)
		{
			if(!(CryptDestroyKey(hKey)))
			{
				MyHandleError(TEXT("Error during CryptDestroyKey."));
			}

			hKey = NULL;
		}

		// Release the CSP.
		if(hCryptProv)
		{
			if(!(CryptReleaseContext(hCryptProv, 0)))
			{
				MyHandleError(TEXT("Error during CryptReleaseContext."));
			}
		} 

		_tprintf(TEXT("Everything is okay. A signature key "));
		_tprintf(TEXT("pair and an exchange key exist in "));
		_tprintf(TEXT("the %s key container.\n"), pszContainerName);  
	
		getchar();
	return 0;
}

