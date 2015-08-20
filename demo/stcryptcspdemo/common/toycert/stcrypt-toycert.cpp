//================================================================================================================================================
// FILE: stcrypt-toycert.cpp
// (c) GIE 2010-03-24  17:02
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-toycert.hpp"

#include "../asn1/Certificate.h"
#include "../asn1/X520countryName.h"
#include "../asn1/X520StateOrProvinceName.h"
#include "../asn1/X520LocalityName.h"
#include "../asn1/X520OrganizationName.h"
#include "../asn1/X520OrganizationalUnitName.h"
#include "../asn1/X520StateOrProvinceName.h"
#include "../asn1/X520CommonName.h"

#include "boost/static_assert.hpp"
#include "boost/scope_exit.hpp"

#include "boost/type_traits.hpp"
#include <sstream>

#include <time.h>
//================================================================================================================================================
namespace stcrypt {

    inline
    void to_asn_string(std::string const& from, X520StateOrProvinceName_t* to){
        assert(to);
        to->present = X520StateOrProvinceName_PR_printableString;

        return to_asn_string(from, & to->choice.printableString);
    }


    inline
    void to_asn_string(std::string const& from, X520LocalityName_t* to){
        assert(to);
        to->present = X520LocalityName_PR_printableString;

        return to_asn_string(from, & to->choice.printableString);
    }

    inline
    void to_asn_string(std::string const& from, X520OrganizationName_t* to){
        assert(to);
        to->present = X520OrganizationName_PR_printableString;

        return to_asn_string(from, & to->choice.printableString);
    }


    inline
    void to_asn_string(std::string const& from, X520CommonName_t* to){
        assert(to);
        to->present = X520CommonName_PR_printableString;
        return to_asn_string(from, & to->choice.printableString);
    }

    inline
    void to_asn_string(std::string const& from, X520OrganizationalUnitName_t* to){
        assert(to);
        to->present = X520OrganizationalUnitName_PR_printableString;
        return to_asn_string(from, & to->choice.printableString);
    }



    namespace oid {
        
        #define STCRYPT_OID_ARRAY_GEN(r, aux/*aux data*/, i/*iter counter*/, oid_elem /*data*/)   \
             BOOST_PP_COMMA_IF(i) oid_elem  \
         /**/
            

        #define STCRYPT_ISSUER_T_OID_IMPL_GEN(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)   \
        boost::array<oid::oid_elem_type, BOOST_PP_LIST_SIZE( BOOST_PP_TUPLE_ELEM(2/*size*/, 1/*extract idx*/, oid_def /*tuple*/) )>   \
                BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/) =    \
                {   \
  BOOST_PP_LIST_FOR_EACH_I( STCRYPT_OID_ARRAY_GEN, 0 , BOOST_PP_TUPLE_ELEM(2/*size*/, 1/*extract idx*/, oid_def /*tuple*/)  ) \
                };  \
            /**/

        BOOST_PP_SEQ_FOR_EACH_I( STCRYPT_ISSUER_T_OID_IMPL_GEN, 0/*aux data*/, STCRYPT_ISSUER_FIELDS )
        #undef STCRYPT_ISSUER_T_OID_GEN

        //boost::array<oid_elem_type, 4> country_name = { 2,5,4,6 };
    }

 
    namespace impl {

        int toycert_t__x509_save__out(const void *buffer, size_t size, void *key) {
            assert(key);

            if(size!=0){
                assert(buffer);
                std::ostream & out_stream = *static_cast<std::ostream*>(key);
                if( out_stream.bad() ) {
                    assert(!"stream.bad()");
                    return -1;
                }
                BOOST_STATIC_ASSERT(sizeof(size_t)==sizeof(std::streamsize));
                out_stream.write( static_cast<char const*>( buffer ), static_cast<std::streamsize>( size ) );
                if( !out_stream.good() ) {
                    assert(!"!stream.good()");
                    return -1;
                }
            } else {
                STCRYPT_LOG_PRINT_EX("x509asn-warning","ASN.1 generator requested 0-sized write");
            }

            return 0;            
        }

    } // ns impl

// UGLY MACROS
//
#define STCRYPT_X509_SAVE_ISSUER_FIELD(AttrValueAsnType, AttrOid, OptString)\
    {                                                                       \
        optional_string const & opt_value=OptString;                        \
                                                                            \
        if( opt_value ) {                                                   \
            ASN_SCOPED_TYPE_ALLOC(RelativeDistinguishedName, rnd);          \
            ASN_SCOPED_TYPE_ALLOC(AttributeTypeAndValue, attr);             \
                                                                            \
            oid2asn( AttrOid, attr->type );                                 \
            ASN_SCOPED_TYPE_ALLOC(AttrValueAsnType, any_name);              \
            to_asn_string( *opt_value , any_name.get());                    \
                                                                            \
            if( ANY_fromType(& (attr->value), any_name.get_asn_type(), any_name.get() ) !=0){STCRYPT_UNEXPECTED();}     \
                                                                            \
            if(ASN_SEQUENCE_ADD(rnd.get(), attr.get())!=0) {STCRYPT_UNEXPECTED();}  \
            attr.release();                                                 \
                                                                            \
            if( ASN_SEQUENCE_ADD(&asn_issuer_or_subject.choice.rdnSequence, rnd.get()) !=0 ) {STCRYPT_UNEXPECTED();}    \
            rnd.release();                                                  \
            if(asn_issuer_or_subject.present==Name_PR_NOTHING) asn_issuer_or_subject.present=Name_PR_rdnSequence;       \
        }       \
                \
    }           \
    /**/

    void encode_issuer_or_subject_(toycert_t::issuer_t const& issuer_or_subject, Name_t& asn_issuer_or_subject){
        asn_issuer_or_subject.present=Name_PR_NOTHING;

        STCRYPT_X509_SAVE_ISSUER_FIELD(X520countryName, oid::country_name, issuer_or_subject.get_country_name());
        STCRYPT_X509_SAVE_ISSUER_FIELD(X520StateOrProvinceName, oid::state_or_province_name, issuer_or_subject.get_state_or_province_name());
        STCRYPT_X509_SAVE_ISSUER_FIELD(X520LocalityName, oid::locality_name, issuer_or_subject.get_locality_name());
        STCRYPT_X509_SAVE_ISSUER_FIELD(X520OrganizationName, oid::organization_name, issuer_or_subject.get_organization_name());
        STCRYPT_X509_SAVE_ISSUER_FIELD(X520OrganizationalUnitName, oid::organization_unit_name, issuer_or_subject.get_organization_unit_name());
        STCRYPT_X509_SAVE_ISSUER_FIELD(X520CommonName, oid::common_name, issuer_or_subject.get_common_name());

    }

    template <class vectorType>
    void vector2bitstring(vectorType const& data_in, BIT_STRING_t& data_out){
        BOOST_STATIC_ASSERT( sizeof(uint8_t)==sizeof(char) );
        BOOST_STATIC_ASSERT( sizeof(typename vectorType::value_type)==sizeof(char) ) ;
        assert(data_out.buf==0);

        size_t const size_in_chars = data_in.size()*sizeof(vectorType::value_type);
        data_out.buf = asn1::alloc<uint8_t>(size_in_chars);

        memcpy(data_out.buf, &data_in[0], size_in_chars); //nothrow
        data_out.size = static_cast<int>(size_in_chars); //nothrow
        data_out.bits_unused = 0; //nothrow
       
    }

    template <class vectorType>
    void bitstring2vector(BIT_STRING_t const& data_in, vectorType & data_out){
        BOOST_STATIC_ASSERT( sizeof(uint8_t)==sizeof(char) );
        BOOST_STATIC_ASSERT( sizeof(typename vectorType::value_type)==sizeof(char) ) ;

        if(data_in.bits_unused!=0) {
            STCRYPT_UNEXPECTED();
        }
        data_out.resize(data_in.size);
        memcpy(&data_out[0], data_in.buf, data_out.size());

    }


    void x509_encode_public_key_info (SubjectPublicKeyInfo_t & pk_info, toycert_t::pub_key_blob_t const& pk, oid::oid_type const& oid){
        oid2asn( oid, pk_info.algorithm.algorithm);
        vector2bitstring(pk, pk_info.subjectPublicKey);
    }

    void x509_encode_signature_info (Certificate_t & cert, toycert_t::signature_blob_t const& sign_blob, oid::oid_type const& oid){
        oid2asn( oid, cert.signatureAlgorithm.algorithm);
        vector2bitstring(sign_blob, cert.signature);
    }

    void toycert_t::set_public_key_blob(pub_key_blob_t const& public_key, oid::oid_type const& oid){
        m_public_key_blob = public_key;
        m_public_key_oid = oid;
    }

    void toycert_t::get_public_key_blob(pub_key_blob_t & public_key, oid::oid_type & oid){
        public_key = m_public_key_blob;
        oid = m_public_key_oid;
    }


    void toycert_t::x509_save(std::ostream &out_stream, oid::oid_type const& sign_alg_oid, signature_callback_type const& sign_proc){
        Certificate_t x509_cert = {0};
        BOOST_SCOPE_EXIT ( (&x509_cert) ){
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, &x509_cert);
        }BOOST_SCOPE_EXIT_END

        prepare_tbs_cert_(x509_cert.tbsCertificate, sign_alg_oid);

        { // sign tbs blob
            std::ostringstream cert_blob_to_sign(std::ios::binary | std::ios::out );

            if( der_encode(&asn_DEF_TBSCertificate, &x509_cert.tbsCertificate, impl::toycert_t__x509_save__out, static_cast<void*>( &cert_blob_to_sign ) ).encoded==-1 ) {
                STCRYPT_UNEXPECTED();
            }

            std::string const& cert_blob_to_sign_as_str = cert_blob_to_sign.str();
            signature_blob_t signature;

			sign_proc(cert_blob_to_sign_as_str.data(), cert_blob_to_sign_as_str.size(), signature);

            x509_encode_signature_info(x509_cert, signature, sign_alg_oid);
        }

        if( der_encode(&asn_DEF_Certificate, &x509_cert, impl::toycert_t__x509_save__out, static_cast<void*>( &out_stream ) ).encoded==-1 ) {
            STCRYPT_UNEXPECTED();
        }

    }

    void toycert_t::prepare_tbs_cert_( TBSCertificate_t& tbsCertificate, oid::oid_type const& sign_alg_oid )
    {

        tbsCertificate.version = m_version;
        tbsCertificate.serialNumber=m_serial_number;

        oid2asn(sign_alg_oid, tbsCertificate.signature.algorithm);

        encode_issuer_or_subject_(issuer(), tbsCertificate.issuer);
        encode_issuer_or_subject_(subject(), tbsCertificate.subject);

        //validity
        {
           
            tm const& tm_not_before_time = boost::posix_time::to_tm( this->validity().get_not_before() );
            tm const& tm_not_after_time = boost::posix_time::to_tm(this->validity().get_not_after() );

            tbsCertificate.validity.notBefore.present = Time_PR_utcTime;
            if( asn_time2UT( & tbsCertificate.validity.notBefore.choice.utcTime, &tm_not_before_time, 1) ==0 ) {STCRYPT_UNEXPECTED();}

            tbsCertificate.validity.notAfter.present = Time_PR_utcTime;
            if( asn_time2UT( & tbsCertificate.validity.notAfter.choice.utcTime, &tm_not_after_time, 1) ==0 ) {STCRYPT_UNEXPECTED();}
        }

        //public key
        {
            if( !m_public_key_blob.empty() ){
                x509_encode_public_key_info(tbsCertificate.subjectPublicKeyInfo, m_public_key_blob, m_public_key_oid);
            }
        }
    }

    namespace asn1{
        template <class SequenceType, class SequenceElementType>
        struct sequence_wrap {

            typedef size_t size_type;
            typedef unsigned int index_type;
            typedef SequenceElementType value_type;

            sequence_wrap(SequenceType const&sequence)
                : m_sequence( sequence )
            {}

            size_type size()const{
                return m_sequence.list.count;
            }
            SequenceElementType const& operator[](index_type const idx)const{
                if(idx>size()){
                    STCRYPT_UNEXPECTED();
                }

                return *(m_sequence.list.array[idx]);

            }

            SequenceType const&m_sequence;
        };
    }

    template<class T, size_t N, class VectorType>
    bool operator==(boost::array<T,N> const& l, VectorType const& r){
        BOOST_STATIC_ASSERT( (boost::is_same<T, typename VectorType::value_type>::value) );
        if(l.size()!=r.size()) return false;
        return std::equal(l.begin(), l.end(), r.begin());

    }

    
    std::string asn2string(PrintableString_t const& ps){
        if(ps.size==0)
            return std::string();
        else return std::string(reinterpret_cast<char const*>(ps.buf), ps.size);
    }

#define STCRYPT_asn2string_NAME_TEMPLATE(ActualType)                            \
    std::string asn2string( BOOST_PP_CAT(ActualType,_t) const& ps){             \
        if(ps.present==BOOST_PP_CAT(ActualType,_PR_NOTHING) )                   \
            return std::string();                                               \
        else if (ps.present==BOOST_PP_CAT(ActualType,_PR_printableString) ){    \
            return  asn2string(ps.choice.printableString);                      \
        } else {                                                                \
            STCRYPT_UNEXPECTED();                                               \
        }                                                                       \
    }                                                                           \
    /**/

    STCRYPT_asn2string_NAME_TEMPLATE(X520StateOrProvinceName);
    STCRYPT_asn2string_NAME_TEMPLATE(X520LocalityName);
    STCRYPT_asn2string_NAME_TEMPLATE(X520OrganizationName);
    STCRYPT_asn2string_NAME_TEMPLATE(X520OrganizationalUnitName);
    STCRYPT_asn2string_NAME_TEMPLATE(X520CommonName);

#undef STCRYPT_asn2string_NAME_TEMPLATE


#define STCRYPT_load_issuer_or_subject_item__PARAMS AttributeTypeAndValue_t const& attr

#define STCRYPT_load_issuer_or_subject_item__BODY(ActualType)   \
    BOOST_PP_CAT(ActualType,_t) * tmp = 0;                                                                                                \
    int const r =  ANY_to_type( const_cast<ANY_t*>( &attr.value ), & BOOST_PP_CAT(asn_DEF_,ActualType),  (void**)&tmp );        \
    asn1::scoped_ptr<BOOST_PP_CAT(ActualType,_t)> attr_as_pstring(  BOOST_PP_CAT(asn_DEF_,ActualType), tmp);                    \
    if(r ==-1 ) {STCRYPT_UNEXPECTED();}                                                                                         \
    return asn2string( *attr_as_pstring );                                                                                      \
    /**/


    std::string load_issuer_or_subject_item__country_name(STCRYPT_load_issuer_or_subject_item__PARAMS){
        STCRYPT_load_issuer_or_subject_item__BODY(PrintableString)
    }
    std::string load_issuer_or_subject_item__state_or_province_name(STCRYPT_load_issuer_or_subject_item__PARAMS){
        STCRYPT_load_issuer_or_subject_item__BODY(X520StateOrProvinceName)
    }
    std::string load_issuer_or_subject_item__locality_name(STCRYPT_load_issuer_or_subject_item__PARAMS){
        STCRYPT_load_issuer_or_subject_item__BODY(X520LocalityName)
    }
    std::string load_issuer_or_subject_item__organization_name(STCRYPT_load_issuer_or_subject_item__PARAMS){
        STCRYPT_load_issuer_or_subject_item__BODY(X520OrganizationName)
    }
    std::string load_issuer_or_subject_item__organization_unit_name(STCRYPT_load_issuer_or_subject_item__PARAMS){
        STCRYPT_load_issuer_or_subject_item__BODY(X520OrganizationalUnitName)
    }
    std::string load_issuer_or_subject_item__common_name(STCRYPT_load_issuer_or_subject_item__PARAMS){
        STCRYPT_load_issuer_or_subject_item__BODY(X520CommonName)
    }
#undef STCRYPT_load_issuer_or_subject_item__PARAMS

    void load_issuer_or_subject_item(RelativeDistinguishedName_t const& item, toycert_t::issuer_t& issuer_or_subject){
        typedef  asn1::sequence_wrap<RelativeDistinguishedName_t, AttributeTypeAndValue_t> rdn_t;
        rdn_t rdn_items(item);
        if(rdn_items.size()!=1){
            STCRYPT_UNEXPECTED();
        }

        AttributeTypeAndValue_t const& attr =  rdn_items[0];
        oid::oid_type attr_oid;
        asn2oid(attr.type, attr_oid);

        oid::country_name == attr_oid;

            #define STCRYPT_ISSUER_T_SWICTH_GEN(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)                                        \
            BOOST_PP_EXPR_IF(i, else ) if(oid:: BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/) == attr_oid)   {            \
                issuer_or_subject. \
                 BOOST_PP_CAT(set_,BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/)) (\
                BOOST_PP_CAT(load_issuer_or_subject_item__, BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/)( attr ) )      \
                );  \
            }                                                                                                                                   \
               /**/
                
            BOOST_PP_SEQ_FOR_EACH_I( STCRYPT_ISSUER_T_SWICTH_GEN, 0/*aux data*/, STCRYPT_ISSUER_FIELDS )
            #undef STCRYPT_ISSUER_T_SWICTH_GEN


    }

    void load_issuer_or_subject(Name_t const& name_fields, toycert_t::issuer_t& issuer_or_subject){
        if( name_fields.present==Name_PR_NOTHING) { 
            return;
        } else if(name_fields.present==Name_PR_rdnSequence){
            typedef asn1::sequence_wrap<RDNSequence_t, RelativeDistinguishedName_t> rnd_seq_t;
            rnd_seq_t rnd(name_fields.choice.rdnSequence);
            size_t const elem_count = rnd.size();
            for(rnd_seq_t::index_type i=0;i<elem_count;++i){
                load_issuer_or_subject_item(rnd[i], issuer_or_subject);
            }
            
        } else {
            STCRYPT_UNEXPECTED();
        }

    }
    boost::posix_time::ptime asn2ptime(Time_t const& t){
        if(t.present==Time_PR_NOTHING) {
            return boost::posix_time::ptime();
        } else if( t.present==Time_PR_utcTime ) {
            tm tm_time={0};
            time_t const t2 = asn_UT2time( &t.choice.utcTime, &tm_time, 1);
            return boost::posix_time::ptime_from_tm(tm_time);
        } else {
            STCRYPT_UNEXPECTED();
        }

    }

    void x509_decode_public_key_info (SubjectPublicKeyInfo_t const& pk_info, toycert_t::pub_key_blob_t& pk, oid::oid_type & oid){
        asn2oid(pk_info.algorithm.algorithm, oid);
        bitstring2vector(pk_info.subjectPublicKey, pk);
    }


    void toycert_t::prepare_this_form_tbs_cert_(TBSCertificate_t& tbsCertificate){

        m_version = tbsCertificate.version;
        m_serial_number = tbsCertificate.serialNumber;

        asn2oid(tbsCertificate.signature.algorithm, m_sign_alg_oid);

        load_issuer_or_subject(tbsCertificate.issuer, issuer() );
        load_issuer_or_subject(tbsCertificate.subject, subject() );

        //validity
        this->validity().set( asn2ptime(tbsCertificate.validity.notBefore),  asn2ptime(tbsCertificate.validity.notAfter) );

        //public key info
        x509_decode_public_key_info(tbsCertificate.subjectPublicKeyInfo, m_public_key_blob, m_public_key_oid);


    }


    bool toycert_t::x509_load( std::istream &in_stream, signature_verify_callback_type const& verify_proc )
    {
        
        Certificate_t* x509_cert = 0;
        std::vector<char> buff;
        size_t const block_size=1024;
        buff.reserve(4*block_size);

        while( !in_stream.eof() ){ //TODO: redesign this ad-hoc code
            if(!in_stream.good()){STCRYPT_UNEXPECTED();}
            size_t const old_size = buff.size();
            size_t const new_size = old_size + block_size;

            buff.resize(new_size);
            in_stream.read( &buff[old_size], block_size );
            size_t const actually_read = in_stream.gcount();
            if(actually_read!=block_size)
                buff.resize(old_size+actually_read);
        }

        asn_dec_rval_t const status = ber_decode(0, &asn_DEF_Certificate, (void**)(&x509_cert), &buff[0], buff.size() );
        if( status.code!=RC_OK ){ //TODO
            ASN_STRUCT_FREE(asn_DEF_Certificate, x509_cert);
            STCRYPT_UNEXPECTED1("ber_decode have failed");
        }

        asn1::scoped_ptr<Certificate_t> x509_cert_sp(asn_DEF_Certificate, x509_cert);

        prepare_this_form_tbs_cert_(x509_cert_sp->tbsCertificate);

        if(verify_proc) { // verify tbs blob
            std::ostringstream cert_blob_to_verify(std::ios::binary | std::ios::out );

            if( der_encode(&asn_DEF_TBSCertificate, &x509_cert_sp->tbsCertificate, impl::toycert_t__x509_save__out, static_cast<void*>( &cert_blob_to_verify ) ).encoded==-1 ) {
                STCRYPT_UNEXPECTED1("der_encode have failed");
            }

            std::string const& cert_blob_to_verify_as_str = cert_blob_to_verify.str();
            signature_blob_t signature;
            bitstring2vector(x509_cert_sp->signature, signature);

            return verify_proc(cert_blob_to_verify_as_str.data(), cert_blob_to_verify_as_str.size(), m_sign_alg_oid, signature);
        }


        return false;
    }


}
//================================================================================================================================================
