/*
#
#    Copyright 2008-2011, Lukas Lueg, lukas.lueg@gmail.com
#
#    This file is part of Pyrit.
#
#    Pyrit is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Pyrit is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Pyrit.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef __i386__
    #define COMPILE_PADLOCK
    #if defined(linux)
        #define MCTX_EIP(context) ((context)->uc_mcontext.gregs[REG_EIP])
    #elif defined(__APPLE__)
        #ifdef __DARWIN_UNIX03
            #define MCTX_EIP(context) (*((unsigned long*)&(context)->uc_mcontext->__ss.__eip))
        #else
            #define MCTX_EIP(context) (*((unsigned long*)&(context)->uc_mcontext->ss.eip))
        #endif
        #define MAP_ANONYMOUS MAP_ANON
    #else
        #undef COMPILE_PADLOCK
    #endif
#endif


#if (defined(__i386__) || defined(__x86_64__))
    #define COMPILE_SSE2
    #define PUT_BE(n,b,i)                            \
    {                                                       \
        (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
        (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
        (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
        (b)[(i) + 3] = (unsigned char) ( (n)       );       \
    }
#endif

#define HMAC_MD5_RC4 0
#define HMAC_SHA1_AES 1
