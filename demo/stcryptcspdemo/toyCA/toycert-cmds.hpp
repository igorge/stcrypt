//================================================================================================================================================
// FILE: toycert-cmds.h
// (c) GIE 2010-04-01  21:04
//
//================================================================================================================================================
#ifndef H_GUARD_TOYCERT_CMDS_2010_04_01_21_04
#define H_GUARD_TOYCERT_CMDS_2010_04_01_21_04
//================================================================================================================================================
#pragma once
//================================================================================================================================================
namespace stcrypt { namespace ca { namespace cmd {
	//
	// request:  | cmd-id | cmd-payload-size-if-any | payload |
	// response: | response-payload-size | payload |
	//
	typedef unsigned int packet_size_t;
	typedef unsigned int type;

	cmd::type const none = 0;
	cmd::type const request_ca_root_certificate = 1;
	cmd::type const request_certificate_signing = 2;
	cmd::type const certificate_signing_status = 3;
	cmd::type const request_cert_and_status = 4;

	cmd::type const response_cert_and_status_not_found = 1;
	cmd::type const response_cert_and_status_not_found_pending = 4;
	cmd::type const response_cert_and_status_valid = 2;
	cmd::type const response_cert_and_status_revoked = 3;

	
	cmd::type const response_certificate_signing_status_pending = 1;
	cmd::type const response_certificate_signing_status_rejected = 2;
	cmd::type const response_certificate_signing_status_signed_data_follows = 3;

	packet_size_t const max_packet_size = 64*1024;

} } }
//================================================================================================================================================
#endif
//================================================================================================================================================
