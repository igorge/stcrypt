//================================================================================================================================================
// FILE: cert_name.h
// (c) GIE 2011-01-20  17:38
//
//================================================================================================================================================
#ifndef H_GUARD_CERT_NAME_2011_01_20_17_38
#define H_GUARD_CERT_NAME_2011_01_20_17_38
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <boost/preprocessor.hpp>
#include <boost/preprocessor/wstringize.hpp>
#include <boost/optional.hpp>

#include <string>
//================================================================================================================================================
namespace stcrypt {


    #define STCRYPT_CNAME_TUPLE_S 3
    #define STCRYPT_ISSUER_FIELDS									            \
        ((country_name,				C, (2,(5,(4,(6, BOOST_PP_NIL))))))				\
        ((state_or_province_name,	ST, (2,(5,(4,(8, BOOST_PP_NIL))))))	            \
        ((locality_name ,			L, (2,(5,(4,(7, BOOST_PP_NIL))))))			    \
        ((organization_name,		O, (2,(5,(4,(10, BOOST_PP_NIL))))))		    \
        ((organization_unit_name,	OU, (2,(5,(4,(11, BOOST_PP_NIL))))))            \
        ((common_name,				CN, (2,(5,(4,(3, BOOST_PP_NIL))))))				\
		((email_name,				E, (1,(2,(840,(113549, (1, (9, (1, BOOST_PP_NIL)))))))))				\
        /**/
        struct cert_name_t {

            typedef boost::optional<std::wstring> optional_string;

            #define STCRYPT_ISSUER_T_MEMBERS_GEN(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)							\
                private: optional_string BOOST_PP_CAT(m_, BOOST_PP_TUPLE_ELEM(STCRYPT_CNAME_TUPLE_S/*size*/, 0/*extract idx*/, oid_def /*tuple*/) ) ;	\
                public:  void BOOST_PP_CAT(set_,BOOST_PP_TUPLE_ELEM(STCRYPT_CNAME_TUPLE_S/*size*/, 0/*extract idx*/, oid_def /*tuple*/)) (std::wstring const& data){            \
                    BOOST_PP_CAT(m_,BOOST_PP_TUPLE_ELEM(STCRYPT_CNAME_TUPLE_S/*size*/, 0/*extract idx*/, oid_def /*tuple*/)) = data;                                           \
                }                                                                           \
                optional_string const& BOOST_PP_CAT(get_,BOOST_PP_TUPLE_ELEM(STCRYPT_CNAME_TUPLE_S/*size*/, 0/*extract idx*/, oid_def /*tuple*/)) ()const{			\
                    return BOOST_PP_CAT(m_,BOOST_PP_TUPLE_ELEM(STCRYPT_CNAME_TUPLE_S/*size*/, 0/*extract idx*/, oid_def /*tuple*/));								\
                }																			\
                /**/
                
            BOOST_PP_SEQ_FOR_EACH_I( STCRYPT_ISSUER_T_MEMBERS_GEN, 0/*aux data*/, STCRYPT_ISSUER_FIELDS )
            #undef STCRYPT_ISSUER_T_MEMBERS_GEN

			#define STCRYPT_X509_T_MEMBERS_GEN(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)					\
				{	\
					auto const& this_field = BOOST_PP_CAT(m_, BOOST_PP_TUPLE_ELEM(STCRYPT_CNAME_TUPLE_S/*size*/, 0/*extract idx*/, oid_def /*tuple*/) ) ; \
					if(this_field) {\
						BOOST_PP_EXPR_IF(i, tmp+=L";"); \
						tmp+=BOOST_PP_WSTRINGIZE(  BOOST_PP_TUPLE_ELEM(STCRYPT_CNAME_TUPLE_S/*size*/, 1/*extract idx*/, oid_def /*tuple*/) );	\
						tmp+=L"=\"";	\
						tmp+=*this_field;	\
						tmp+=L"\"";	\
					} \
				}  \

			/**/

			std::wstring x500_string()const{
				std::wstring tmp;

				BOOST_PP_SEQ_FOR_EACH_I( STCRYPT_X509_T_MEMBERS_GEN, 0/*aux data*/, STCRYPT_ISSUER_FIELDS )

				return tmp;
			}
			#undef STCRYPT_X509_T_MEMBERS_GEN

            //STCRYPT_ISSUER_FIELD(country_name); //2.5.4.6 - id-at-countryName
            //STCRYPT_ISSUER_FIELD(state_or_province_name);    //2.5.4.8 - id-at-stateOrProvinceName
            //STCRYPT_ISSUER_FIELD(locality_name);    //2.5.4.7 - id-at-localityName
            //STCRYPT_ISSUER_FIELD(organization_name); //2.5.4.10 - id-at-organizationName
            //STCRYPT_ISSUER_FIELD(organization_unit_name);   //2.5.4.11 - id-at-organizationalUnitName
            //STCRYPT_ISSUER_FIELD(common_name); //2.5.4.3 - id-at-commonName
        };

}
//================================================================================================================================================
#endif
//================================================================================================================================================
