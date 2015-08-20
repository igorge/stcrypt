// certcreate.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <new>

#include "../common/asn1/Certificate.h"
#include "../common/toycert/stcrypt-toycert.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-exceptions.hpp"

#include "boost/assign.hpp"

#include <fstream>

namespace stcrypt {
}
std::vector<char> sig1, sig2;

void dummy_sign_func(char const * const data, size_t const size, stcrypt::toycert_t::signature_blob_t& signature){
    using boost::assign::operator+=;

    signature.clear();
    signature+=3,0,3;

    sig1.assign(data, data+size);
}


bool dummy_verify_func(char const * const data, size_t const size, stcrypt::oid::oid_type const& sign_alg_oid ,stcrypt::toycert_t::signature_blob_t const& signature){
    sig2.assign(data, data+size);

    return true;
}


int _tmain(int argc, _TCHAR* argv[])
{
    using boost::assign::operator+=;
    _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_DELAY_FREE_MEM_DF);

    try {

        {
            std::vector<char> pub_key;
            pub_key+=1,2,3;

            stcrypt::oid::oid_type oid;
            oid+=1,2,840,113549,1,1,1;

            stcrypt::oid::oid_type sign_oid;
            sign_oid+=1,2,840,113549,1,1,2;

            stcrypt::toycert_t cert2;

            cert2.set_public_key_blob(pub_key, oid);

            boost::posix_time::ptime const not_before_time = boost::posix_time::second_clock::universal_time();
            boost::posix_time::ptime const not_after_time = ( not_before_time + boost::gregorian::days(7) ); 
            cert2.validity().set(not_before_time, not_after_time);


            cert2.issuer().set_country_name( "UA" );
            cert2.issuer().set_state_or_province_name("Province");

            cert2.subject().set_country_name( "UA" );
            cert2.subject().set_state_or_province_name("Province");

            std::ofstream test_cert("test_cert.ber", std::ios::out | std::ios::binary);
            cert2.x509_save(test_cert, sign_oid, dummy_sign_func);
            test_cert.close();
            if(test_cert.bad()) 
                STCRYPT_UNEXPECTED();

        }

        {
            std::ifstream test_cert("test_cert.ber", std::ios::in | std::ios::binary);

            stcrypt::toycert_t cert;
            bool r = cert.x509_load(test_cert, dummy_verify_func );

        }
        bool const is_equal = sig1.size()==sig2.size()? std::equal(sig1.begin(), sig1.end(), sig2.begin()) : false;
        assert(is_equal);


        std::cerr << "OK\n";
    } catch(boost::exception const& e) {
        std::cerr << boost::diagnostic_information(e) << std::endl;
    } catch(std::exception const& e) {
        std::cerr << e.what()<< std::endl;
    }
    getchar();


/*    Certificate_t *cert = stcrypt::asn1_alloc<Certificate_t>();


    FILE *fp = fopen("encoded_cert.ber", "wb");
    assert(fp);
    der_encode(&asn_DEF_Certificate, cert, write_out, fp);
    fclose(fp);

    ASN_STRUCT_FREE(asn_DEF_Certificate, cert);*/

	return 0;
}

