//================================================================================================================================================
// FILE: stcrypt-toycert.h
// (c) GIE 2010-03-24  17:02
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_TOYCERT_2010_03_24_17_02
#define H_GUARD_STCRYPT_TOYCERT_2010_03_24_17_02
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "../../../../stcrypt/trunk/stcrypt-csp/stcrypt-debug.hpp"
#include "../../../../stcrypt/trunk/stcrypt-csp/stcrypt-exceptions.hpp"

#include "asn_application.h"	/* Application-visible API */
#include "OBJECT_IDENTIFIER.h"
#include "PrintableString.h"

#include "../asn1/TBSCertificate.h"

#include "boost/optional.hpp"
#include "boost/noncopyable.hpp"
#include "boost/array.hpp"
#include "boost/preprocessor.hpp"
#include "boost/function.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include <iostream>
//================================================================================================================================================
namespace stcrypt {

    namespace asn1 {

        template <class T>
        T* alloc(){
            void * const p = calloc(1,sizeof(T));
            if(!p)
                throw std::bad_alloc();

            return static_cast<T*>(p);
        }

        template <class T>
        T* alloc(size_t const size){
            void * const p = calloc(size,sizeof(T));
            if(!p)
                throw std::bad_alloc();

            return static_cast<T*>(p);
        }


        /*template <class T>
        void free(T * const p){
            ::free( p );
        }*/

        template <class T> 
        struct scoped_ptr 
            : boost::noncopyable
        {
            typedef T element_type;

            T* operator->(){
                assert(m_p);
                return m_p;
            }

            T& operator*(){
                assert(m_p);
                return *m_p;
            }

            element_type * release() /*nothrow*/ { element_type * tmp = m_p; m_p = 0; return tmp;}
            element_type * get()const{ return m_p; }

            asn_TYPE_descriptor_t* get_asn_type()const{ return &m_type_desc;}

            explicit scoped_ptr(asn_TYPE_descriptor_t & asn_type_descriptor, element_type* const p) : m_type_desc(asn_type_descriptor), m_p(p){} 
            ~scoped_ptr(){ if(m_p) {ASN_STRUCT_FREE(m_type_desc,m_p);} } //nothrow
        private:
            T* m_p;
            asn_TYPE_descriptor_t& m_type_desc;
        };

        #define ASN_SCOPED_PTR(asn_type, name, ptr) ::stcrypt::asn1::scoped_ptr<asn_type##_t> name( asn_DEF_##asn_type, (ptr) )
        #define ASN_SCOPED_TYPE_ALLOC(asn_type, name) ASN_SCOPED_PTR(asn_type, name, ::stcrypt::asn1::alloc<asn_type##_t>())


    } //ns asn1 

    #define STCRYPT_ISSUER_FIELDS                       \
        ((country_name,(2,(5,(4,(6, BOOST_PP_NIL))))))  \
        ((state_or_province_name,(2,(5,(4,(8, BOOST_PP_NIL))))))  \
        ((locality_name , (2,(5,(4,(7, BOOST_PP_NIL))))))  \
        ((organization_name, (2,(5,(4,(10, BOOST_PP_NIL))))))  \
        ((organization_unit_name, (2,(5,(4,(11, BOOST_PP_NIL))))))  \
        ((common_name, (2,(5,(4,(3, BOOST_PP_NIL))))))  \
        /**/

    namespace oid {
        typedef int oid_elem_type;
        typedef std::vector<oid_elem_type> oid_type;

        size_t const good_enough_num_of_oid_elements = 16;

        #define STCRYPT_ISSUER_T_OID_GEN(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)   \
            extern boost::array<oid_elem_type, BOOST_PP_LIST_SIZE( BOOST_PP_TUPLE_ELEM(2/*size*/, 1/*extract idx*/, oid_def /*tuple*/) )>   \
                BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/);    \
            /**/

        BOOST_PP_SEQ_FOR_EACH_I( STCRYPT_ISSUER_T_OID_GEN, 0/*aux data*/, STCRYPT_ISSUER_FIELDS )
        #undef STCRYPT_ISSUER_T_OID_GEN

    }

    template <class OidType>
    void oid2asn(OidType const& oid_array, OBJECT_IDENTIFIER_t & asn_oid){
        if( OBJECT_IDENTIFIER_set_arcs(& asn_oid, oid_array.data(), sizeof(OidType::value_type), static_cast<unsigned int>( oid_array.size() ) ) !=0 ){
            STCRYPT_UNEXPECTED();
        }
    }

    inline
    void oid2asn(oid::oid_type const& oid_array, OBJECT_IDENTIFIER_t & asn_oid){
        if( OBJECT_IDENTIFIER_set_arcs(& asn_oid, &oid_array[0], sizeof(oid::oid_type::value_type), static_cast<unsigned int>( oid_array.size() ) ) !=0 ){
            STCRYPT_UNEXPECTED();
        }
    }

    inline
    void asn2oid(OBJECT_IDENTIFIER_t const& asn_oid_const, oid::oid_type & oid_array){
        BOOST_STATIC_ASSERT(oid::good_enough_num_of_oid_elements>=1);

        OBJECT_IDENTIFIER_t & asn_oid = const_cast<OBJECT_IDENTIFIER_t&>( asn_oid_const ); //work around C API

        oid_array.resize(oid::good_enough_num_of_oid_elements);
        int const count = OBJECT_IDENTIFIER_get_arcs( &asn_oid, &oid_array[0],sizeof(oid::oid_type::value_type), static_cast<unsigned int>( oid_array.size() ) );
        if( count>static_cast<int>( oid_array.size() ) ) {
            oid_array.resize(count);
            int const count = OBJECT_IDENTIFIER_get_arcs(&asn_oid, &oid_array[0],sizeof(oid::oid_type::value_type), static_cast<unsigned int>( oid_array.size() ) );
            if(count!=oid_array.size()){STCRYPT_UNEXPECTED();}
        } else if( count==oid_array.size() ) {
            /*do nothing*/
        } else if( count<0 ) {
            STCRYPT_UNEXPECTED();
        } else if( count< static_cast<int>( oid_array.size() ) ) {
            oid_array.resize(count);
        }
    }


    inline
    void to_asn_string(std::string const& from, PrintableString_t* to){
        if( OCTET_STRING_fromBuf(to, from.data(), static_cast<unsigned int>( from.size() ) )!=0){STCRYPT_UNEXPECTED();}
    }


    typedef boost::optional<std::string> optional_string;

    struct toycert_t {
        typedef long serial_number_type;
        typedef std::vector<char> pub_key_blob_t;
        typedef std::vector<char> signature_blob_t;

        typedef boost::function<void(char const * const data, size_t const size, signature_blob_t& signature)> signature_callback_type;
        typedef boost::function<bool(char const * const data, size_t const size, oid::oid_type const& sign_alg_oid,  signature_blob_t const& signature)> signature_verify_callback_type;

        struct issuer_t {

            #define STCRYPT_ISSUER_T_MEMBERS_GEN(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)   \
                private: optional_string BOOST_PP_CAT(m_, BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/) ) ;  \
                public:  void BOOST_PP_CAT(set_,BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/)) (std::string const& data){            \
                    BOOST_PP_CAT(m_,BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/)) = data;                                           \
                }                                                                           \
                optional_string const& BOOST_PP_CAT(get_,BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/)) ()const{       \
                    return BOOST_PP_CAT(m_,BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/));                            \
                }                                               \
                /**/
                
            BOOST_PP_SEQ_FOR_EACH_I( STCRYPT_ISSUER_T_MEMBERS_GEN, 0/*aux data*/, STCRYPT_ISSUER_FIELDS )
            #undef STCRYPT_ISSUER_T_MEMBERS_GEN

            //STCRYPT_ISSUER_FIELD(country_name); //2.5.4.6 - id-at-countryName
            //STCRYPT_ISSUER_FIELD(state_or_province_name);    //2.5.4.8 - id-at-stateOrProvinceName
            //STCRYPT_ISSUER_FIELD(locality_name);    //2.5.4.7 - id-at-localityName
            //STCRYPT_ISSUER_FIELD(organization_name); //2.5.4.10 - id-at-organizationName
            //STCRYPT_ISSUER_FIELD(organization_unit_name);   //2.5.4.11 - id-at-organizationalUnitName
            //STCRYPT_ISSUER_FIELD(common_name); //2.5.4.3 - id-at-commonName
        };

        typedef issuer_t subject_t;

        void set_public_key_blob(pub_key_blob_t const& public_key, oid::oid_type const& oid);
        void get_public_key_blob(pub_key_blob_t & public_key, oid::oid_type & oid);

        void x509_save(std::ostream &out_stream, oid::oid_type const& sign_alg_oid, signature_callback_type const& sign_proc);
        bool x509_load(std::istream &in_stream, signature_verify_callback_type const& verify_proc);

        toycert_t()
            : m_serial_number(0)
            , m_version(1)
        {}
        
        issuer_t& issuer(){
            return m_issuer;
        }

        subject_t& subject(){
            return m_subject;
        }

        struct validity_t {
            void set_not_before(boost::posix_time::ptime const& t){m_not_before = t;}
            void set_not_after(boost::posix_time::ptime const& t){m_not_after = t;}
            void set(boost::posix_time::ptime const& not_before, boost::posix_time::ptime const& not_after){
                this->set_not_before(not_before);
                this->set_not_after(not_after);
            }

            boost::posix_time::ptime const& get_not_before()const{ return m_not_before; }
            boost::posix_time::ptime const& get_not_after()const{ return m_not_after; }
        private:
            boost::posix_time::ptime    m_not_before;
            boost::posix_time::ptime    m_not_after;
        };

        validity_t& validity(){return m_validity;}
        validity_t const& validity()const{return m_validity;}

		void set_serial(serial_number_type const serial){m_serial_number = serial;}
		serial_number_type get_serial()const{return m_serial_number;}
    private:
        void prepare_tbs_cert_(TBSCertificate_t& tbsCertificate, oid::oid_type const& sign_alg_oid);
        void prepare_this_form_tbs_cert_(TBSCertificate_t& tbsCertificate);
    private:
        unsigned int        m_version;

        oid::oid_type       m_sign_alg_oid;

        serial_number_type  m_serial_number;
        issuer_t            m_issuer;
        subject_t           m_subject;

        pub_key_blob_t      m_public_key_blob;
        oid::oid_type       m_public_key_oid;

        validity_t          m_validity;
    };

}
//================================================================================================================================================
#endif
//================================================================================================================================================
