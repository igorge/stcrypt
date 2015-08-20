// Copyright (C) 2009 Christian Schladetsch
// (c) 2010 GIE
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying 
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_MONOTONIC_FIXED_STORAGE_HPP_GIE6476
#define BOOST_MONOTONIC_FIXED_STORAGE_HPP_GIE6476

#include <boost/array.hpp>
#include <boost/aligned_storage.hpp>

//#define BOOST_MONOTONIC_STORAGE_EARLY_OUT

#ifndef GIE_DEBUG_LOG4
    #define GIE_DEBUG_LOG4(x,y,z,u) (void)0
#endif


namespace gie
{
    namespace monotonic
    {

		#ifndef NDEBUG
			size_t const magic_cookie = 0xbadf00d1;
		#endif

        /// storage for an allocator that is on the stack or heap
        template <size_t InlineSize>
        struct fixed_storage
        {
            typedef typename boost::aligned_storage<InlineSize>::type  buffer_type;

        private:
			#ifndef NDEBUG
				size_t m_cookie1;
			#endif

            buffer_type buffer;            ///< the storage

			#ifndef NDEBUG
				size_t m_cookie2;
			#endif


            size_t cursor;            ///< pointer to current index within storage for next allocation
#ifndef NDEBUG
            size_t num_allocations;
			size_t m_num_deallocations;
			size_t num_failed;
			size_t m_max_request;
#endif
        public:
            fixed_storage() 
                : cursor(0)
#ifndef NDEBUG
                , num_allocations(0)
				, m_num_deallocations(0)
				, num_failed(0)
				, m_max_request(0)
				, m_cookie1(magic_cookie)
				, m_cookie2(magic_cookie)
#endif
            {
            }

			#ifndef NDEBUG
				void check_cookie_()const{
					assert(m_cookie1==magic_cookie && m_cookie2==magic_cookie);
				}

			#endif

			~fixed_storage(){
				#ifndef NDEBUG
					check_cookie_();
					assert(num_allocations==m_num_deallocations);
				#endif
			}

            /*Buffer const &get_buffer()  const
            {
                return buffer;
            }*/

            char * data(){
                return static_cast<char *>(  buffer.address() );
            }
            char const* data() const {
                return static_cast<char const*>(  buffer.address() );
            }

            const char *begin() const
            {
                return this->data();
            }
            const char *end() const
            {
                return this->begin() + InlineSize; //buffer.data() + InlineSize;
            }
            void reset()
            {
                cursor = 0;
#ifndef NDEBUG
				check_cookie_();
                num_allocations = 0;
				num_failed = 0;
#endif
            }
            void release()
            {
                reset();
            }

            size_t get_cursor() const
            {
                return cursor;
            }

            void set_cursor(size_t c)
            {
                cursor = c;
            }

            
        public:
            /// allocate storage, given alignment requirement
            void *allocate(size_t num_bytes, size_t alignment)
            {

				#ifndef NDEBUG
					check_cookie_();
					m_max_request = (std::max)(m_max_request, num_bytes);
				#endif

                assert(alignment==1 || alignment%2 == 0);

                size_t extra = cursor & (alignment - 1);
                if (extra > 0)
                    extra = alignment - extra;
                size_t const required = num_bytes + extra;
                if (cursor + required > InlineSize)
                {
#ifndef NDEBUG
					++num_failed;
					GIE_DEBUG_LOG4("inline allocation of %1% failed (inline size: %2%, cursor: %3%)", required, InlineSize, cursor);
#endif
                    return 0;
                }
#ifndef NDEBUG
                ++num_allocations;

                //volatile auto const d_1 = sizeof(buffer);
                //volatile auto const d_2  = boost::alignment_of<buffer_type>::value;
#endif
                char *ptr = this->data()+cursor;
                cursor += required;

                auto const new_ptr = ptr + extra;

                assert( reinterpret_cast<size_t>(new_ptr) % alignment ==0 );

                return new_ptr;
            }

            void deallocate(void *ptr)
            {
                // do nothing
				#ifndef NDEBUG
					++m_num_deallocations;
				#endif
            }

            size_t max_size() const
            {
                return InlineSize;
            }

            size_t remaining() const
            {
                return InlineSize - cursor;
            }

            size_t used() const
            {
                return cursor;
            }

#ifndef NDEBUG
            size_t num_allocs() const
            {
                return num_allocations;
            }

            size_t num_failed_allocs() const
            {
                return num_failed;
            }
#endif
            //-----------------------------------------------------------------


            template <class Ty>
            Ty *uninitialised_create()
            {
                return reinterpret_cast<Ty *>(allocate_bytes<sizeof(Ty)>());
            }

            template <class Ty>
            void construct(Ty *ptr, const boost::true_type& /*is_pod*/)
            {
                // do nothing
            }

            template <class Ty>
            void construct(Ty *ptr, const boost::false_type&)
            {
                new (ptr) Ty();
            }

            template <class Ty>
            Ty &create()
            {
                Ty *ptr = uninitialised_create<Ty>();
                construct(ptr, boost::is_pod<Ty>());

                #ifndef NDEBUG
                    check_cookie_();
                #endif

                return *ptr;
            }

            template <class Ty, class A0>
            Ty &create(A0 a0)
            {
                Ty *ptr = uninitialised_create<Ty>();
                new (ptr) Ty(a0);

                #ifndef NDEBUG
                    check_cookie_();
                #endif

                return *ptr;
            }

            template <class Ty, class A0, class A1>
            Ty &create(A0 a0, A1 a1)
            {
                Ty *ptr = uninitialised_create<Ty>();
                new (ptr) Ty(a0, a1);

                #ifndef NDEBUG
                    check_cookie_();
                #endif

                return *ptr;
            }

            template <class Ty>
            void destroy(Ty &object)
            {

                #ifndef NDEBUG
                    check_cookie_();
                #endif

                object.~Ty();


                #ifndef NDEBUG
                    check_cookie_();
                #endif
            }

            template <class Ty>
            void destroy(Ty const &object)
            {
                destroy(const_cast<Ty &>(object));
            }

            template <size_t N>
            char *allocate_bytes()
            {
                return allocate_bytes(N, boost::aligned_storage<N>::alignment);
            }

            char *allocate_bytes(size_t num_bytes, size_t alignment = 1)
            {
                return reinterpret_cast<char *>(allocate(num_bytes, alignment));
            }

        };
    
    } // namespace monotonic

} // namespace boost


#endif // BOOST_MONOTONIC_FIXED_STORAGE_HPP

//EOF
