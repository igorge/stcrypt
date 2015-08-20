//================================================================================================================================================
// FILE: test-here.cpp
// (c) GIE 2010-01-08  16:07
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "test-here.hpp"
#include "stcrypt-cryptolib.hpp"

#include <vector>
//================================================================================================================================================
namespace stcrypt {

	void test__(){
		
		 CL_CONTEXT  m_ctx;
		 DWORD res;
		 TGFELEMENT d; //private
		 TECPOINT	Q; //public

		 {
			 res=DSTU4145AcquireContext(&m_ctx);
			 assert(res==0);
			 res=DSTU4145InitStd(m_ctx,9); // [0-9]
			 assert(res==0);

			 res=DSTU4145GenKeys(m_ctx, &d, &Q);
			 assert(res==0);

			 res=DestroyContext(m_ctx);
			 assert(res==0);

		 }
		 std::vector<BYTE> buffer;

		 {
			 res=DSTU4145AcquireContext(&m_ctx);
			 assert(res==0);

			 res=DSTU4145InitStd(m_ctx,9); // [0-9] //0-5 -- fail
			 assert(res==0);


			 DWORD buffer_size = 0;
			 TBLOCK256 key="key"; //data to encrypt;
			 res=AsymmetricEncryption(m_ctx, &key, &Q, 0, &buffer_size);
			 assert(res==0);

			 buffer.resize(buffer_size);
			 DWORD old_buffer_size = buffer_size;
			 res=AsymmetricEncryption(m_ctx, &key, &Q, &buffer[0], &buffer_size);
			 assert(res==0);

			 assert(old_buffer_size == buffer_size );

			 res=DestroyContext(m_ctx);
			 assert(res==0);


		 }

		 {
			 res=DSTU4145AcquireContext(&m_ctx);
			 assert(res==0);

			 res=DSTU4145InitStd(m_ctx,9); // [0-9] //0-5 -- fail
			 assert(res==0);


			 DWORD buffer_size = 0;
			 TBLOCK256 key={0};
			 res=AsymmetricDecryption(m_ctx, &d, &buffer[0], buffer.size(), &key);
			 assert(res==0);

			 res=DestroyContext(m_ctx);
			 assert(res==0);


		 }

	}


}
//================================================================================================================================================
