// stcrypt-cng-config.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "../stcrypt-cng/stcrypt-debug.hpp"
#include "../stcrypt-cng/stcrypt-crypto-alg-ids.h"
#include "../stcrypt-cng/stcrypt-exceptions.hpp"
#include "../stcrypt-cng/stcrypt-cng-status.hpp"

#include <bcrypt.h>

#include <boost/program_options.hpp>
#include <iostream>


namespace stcrypt {

	void cng_register_algorithms(){
		CSP_LOG_TRACE

			PWSTR	cng_hash_functions[1] = {0};
		cng_hash_functions[0]=CNG_G34311_ALGORITHM;


		CRYPT_INTERFACE_REG	cng_prov_intrface_hash = {0};
		cng_prov_intrface_hash.dwInterface = BCRYPT_HASH_INTERFACE;
		cng_prov_intrface_hash.dwFlags = CRYPT_LOCAL;
		cng_prov_intrface_hash.cFunctions = 1;
		cng_prov_intrface_hash.rgpszFunctions = &cng_hash_functions[0];

		PCRYPT_INTERFACE_REG cng_prov_intrfaces[1] = {0};
		cng_prov_intrfaces[0] = &cng_prov_intrface_hash;

		CRYPT_IMAGE_REG	   	cng_prov_use_mode_info = {0};
		cng_prov_use_mode_info.pszImage = L"stcrypt-cng.dll"; //TODO: extract name from rt module
		cng_prov_use_mode_info.cInterfaces = 1;
		cng_prov_use_mode_info.rgpInterfaces = &cng_prov_intrfaces[0];

		CRYPT_PROVIDER_REG	cng_prov_reg_info = {0};
		cng_prov_reg_info.pUM = &cng_prov_use_mode_info;
		NTSTATUS const r1 = BCryptRegisterProvider(STCRYPT_PROVIDER_NAME_W, CRYPT_OVERWRITE, &cng_prov_reg_info);
		if(r1!=STATUS_SUCCESS) STCRYPT_UNEXPECTED();

		NTSTATUS const r2 = BCryptAddContextFunctionProvider(
			CRYPT_LOCAL, 
			NULL, // Default context.
			BCRYPT_HASH_INTERFACE, 
			CNG_G34311_ALGORITHM,
			STCRYPT_PROVIDER_NAME_W,
			CRYPT_PRIORITY_TOP);

		if(r2!=STATUS_SUCCESS) STCRYPT_UNEXPECTED();

	}

	void cng_unregister_algorithms(){

	}

}



int _tmain(int argc, _TCHAR* argv[])
{
	namespace po = boost::program_options;

	try{


		po::options_description options_desc("Allowed options");
		po::variables_map       options_values;

		options_desc.add_options()
			("help", "produce help message")
			("install","install stcrypt-cng")
			("uninstall","uninstall stcrypt-cng")
			;

		po::store(po::wcommand_line_parser(argc, argv)
			.options(options_desc).run()
			,options_values);

		po::notify( options_values );

		if( options_values.count("help") || ( options_values.count("install") && options_values.count("uninstall") ) 
										 || ( !options_values.count("install") && !options_values.count("uninstall") ) )	{ 
			std::clog << options_desc << "\n"; return EXIT_FAILURE; 
		}

		if( options_values.count("install") ){

			stcrypt::cng_register_algorithms();

		} else if( options_values.count("uninstall") ){
			STCRYPT_UNEXPECTED();
		}



	} catch (boost::exception const& e) {
		std::cerr << boost::diagnostic_information(e) << std::endl;
		return (EXIT_FAILURE);

	} catch (std::exception const& e) {
		std::cerr << e.what() << std::endl;
		return (EXIT_FAILURE);

	}

	return EXIT_SUCCESS;
}

