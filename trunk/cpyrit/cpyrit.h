/*
#
#    Copyright 2008, Lukas Lueg, knabberknusperhaus@yahoo.de
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

#ifndef CPYRIT
#define CPYRIT

#define HAVE_CUDA
#define HAVE_OPENSSL

#define uchar  unsigned char

#include <python2.5/Python.h>

#ifndef GET_BE
#define GET_BE(n,b,i)                            \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_BE
#define PUT_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


#include <pthread.h>
#include <sched.h>
struct thread_ctr {
    pthread_t thread_id;
    void* keyptr;
    unsigned int keycount;
    unsigned int keyoffset;
    unsigned int keystep;
    void* bufferptr;
    char* essid;
};

#ifdef HAVE_OPENSSL
    #include <openssl/hmac.h>
    #include <openssl/sha.h>
#else
    typedef struct {
      unsigned long Nh,Nl;
      unsigned long h0,h1,h2,h3,h4;
      unsigned char buffer[64];
    } SHA_CTX;
    #ifdef __cplusplus
    extern "C"
    {
    #endif
    void SHA1_Init( SHA_CTX* ctx );
    void SHA1_Update ( SHA_CTX *ctx, unsigned char *input, int ilen );
    void HMAC(uchar *key, int keylen, uchar *msg, int msglen, uchar *output);
    #ifdef __cplusplus
    }
    #endif
#endif

#ifdef HAVE_CUDA

    typedef struct {
        unsigned long h0,h1,h2,h3,h4;
    } SHA_DEV_CTX;
    
    #define CPY_DEVCTX(src, dst) \
    { \
        dst.h0 = src.h0; dst.h1 = src.h1; \
        dst.h2 = src.h2; dst.h3 = src.h3; \
        dst.h4 = src.h4; \
    }
 
    typedef struct {
        SHA_DEV_CTX ctx_ipad;
        SHA_DEV_CTX ctx_opad;
        SHA_DEV_CTX e1;
        SHA_DEV_CTX e2;
    } gpu_inbuffer;
    
    typedef struct {
        SHA_DEV_CTX pmk1;
        SHA_DEV_CTX pmk2;
    } gpu_outbuffer;

#endif

#endif
