/*
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

#include "cpyrit.h"

#ifdef HAVE_CUDA
    #include <cuda_runtime.h>
#endif

#ifndef HAVE_OPENSSL

void SHA1_Init( SHA_CTX* ctx ) {
  ctx->Nl = 0;
  ctx->Nh = 0;
  
  ctx->h0 = 0x67452301;
  ctx->h1 = 0xEFCDAB89;
  ctx->h2 = 0x98BADCFE;
  ctx->h3 = 0x10325476;
  ctx->h4 = 0xC3D2E1F0;
}

static void sha1_cpu_process( SHA_CTX *ctx, unsigned char data[64]) {
  unsigned long temp, W[16], A, B, C, D, E;
  
  GET_BE( W[ 0], data,  0 );
  GET_BE( W[ 1], data,  4 );
  GET_BE( W[ 2], data,  8 );
  GET_BE( W[ 3], data, 12 );
  GET_BE( W[ 4], data, 16 );
  GET_BE( W[ 5], data, 20 );
  GET_BE( W[ 6], data, 24 );
  GET_BE( W[ 7], data, 28 );
  GET_BE( W[ 8], data, 32 );
  GET_BE( W[ 9], data, 36 );
  GET_BE( W[10], data, 40 );
  GET_BE( W[11], data, 44 );
  GET_BE( W[12], data, 48 );
  GET_BE( W[13], data, 52 );
  GET_BE( W[14], data, 56 );
  GET_BE( W[15], data, 60 );
  
#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)						\
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

  A = ctx->h0;
  B = ctx->h1;
  C = ctx->h2;
  D = ctx->h3;
  E = ctx->h4;
  

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
  
  P( A, B, C, D, E, W[0]  );
  P( E, A, B, C, D, W[1]  );
  P( D, E, A, B, C, W[2]  );
  P( C, D, E, A, B, W[3]  );
  P( B, C, D, E, A, W[4]  );
  P( A, B, C, D, E, W[5]  );
  P( E, A, B, C, D, W[6]  );
  P( D, E, A, B, C, W[7]  );
  P( C, D, E, A, B, W[8]  );
  P( B, C, D, E, A, W[9]  );
  P( A, B, C, D, E, W[10] );
  P( E, A, B, C, D, W[11] );
  P( D, E, A, B, C, W[12] );
  P( C, D, E, A, B, W[13] );
  P( B, C, D, E, A, W[14] );
  P( A, B, C, D, E, W[15] );
  P( E, A, B, C, D, R(16) );
  P( D, E, A, B, C, R(17) );
  P( C, D, E, A, B, R(18) );
  P( B, C, D, E, A, R(19) );
  
  
#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
  
  P( A, B, C, D, E, R(20) );
  P( E, A, B, C, D, R(21) );
  P( D, E, A, B, C, R(22) );
  P( C, D, E, A, B, R(23) );
  P( B, C, D, E, A, R(24) );
  P( A, B, C, D, E, R(25) );
  P( E, A, B, C, D, R(26) );
  P( D, E, A, B, C, R(27) );
  P( C, D, E, A, B, R(28) );
  P( B, C, D, E, A, R(29) );
  P( A, B, C, D, E, R(30) );
  P( E, A, B, C, D, R(31) );
  P( D, E, A, B, C, R(32) );
  P( C, D, E, A, B, R(33) );
  P( B, C, D, E, A, R(34) );
  P( A, B, C, D, E, R(35) );
  P( E, A, B, C, D, R(36) );
  P( D, E, A, B, C, R(37) );
  P( C, D, E, A, B, R(38) );
  P( B, C, D, E, A, R(39) );
  
#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

  P( A, B, C, D, E, R(40) );
  P( E, A, B, C, D, R(41) );
  P( D, E, A, B, C, R(42) );
  P( C, D, E, A, B, R(43) );
  P( B, C, D, E, A, R(44) );
  P( A, B, C, D, E, R(45) );
  P( E, A, B, C, D, R(46) );
  P( D, E, A, B, C, R(47) );
  P( C, D, E, A, B, R(48) );
  P( B, C, D, E, A, R(49) );
  P( A, B, C, D, E, R(50) );
  P( E, A, B, C, D, R(51) );
  P( D, E, A, B, C, R(52) );
  P( C, D, E, A, B, R(53) );
  P( B, C, D, E, A, R(54) );
  P( A, B, C, D, E, R(55) );
  P( E, A, B, C, D, R(56) );
  P( D, E, A, B, C, R(57) );
  P( C, D, E, A, B, R(58) );
  P( B, C, D, E, A, R(59) );
  
#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
  
  P( A, B, C, D, E, R(60) );
  P( E, A, B, C, D, R(61) );
  P( D, E, A, B, C, R(62) );
  P( C, D, E, A, B, R(63) );
  P( B, C, D, E, A, R(64) );
  P( A, B, C, D, E, R(65) );
  P( E, A, B, C, D, R(66) );
  P( D, E, A, B, C, R(67) );
  P( C, D, E, A, B, R(68) );
  P( B, C, D, E, A, R(69) );
  P( A, B, C, D, E, R(70) );
  P( E, A, B, C, D, R(71) );
  P( D, E, A, B, C, R(72) );
  P( C, D, E, A, B, R(73) );
  P( B, C, D, E, A, R(74) );
  P( A, B, C, D, E, R(75) );
  P( E, A, B, C, D, R(76) );
  P( D, E, A, B, C, R(77) );
  P( C, D, E, A, B, R(78) );
  P( B, C, D, E, A, R(79) );
  
#undef K
#undef F

  ctx->h0 += A;
  ctx->h1 += B;
  ctx->h2 += C;
  ctx->h3 += D;
  ctx->h4 += E;
}

void SHA1_Update ( SHA_CTX *ctx, unsigned char *input, int ilen ) {
  int fill;
  unsigned long left;
  
  if ( ilen <= 0 )
    return;
  
  left = ctx->Nl & 0x3F;
  fill = 64 - left;
  
  ctx->Nl += ilen;
  ctx->Nl &= 0xFFFFFFFF;
  
  if ( ctx->Nl < (unsigned long) ilen )
    ctx->Nh++;
  
  if ( left && ilen >= fill ) {
    memcpy( (void *) (ctx->buffer + left),
	    (void *) input, fill );
    
    sha1_cpu_process( ctx, ctx->buffer );
    input += fill;
    ilen  -= fill;
    left = 0;
  }
  
  while ( ilen >= 64 ) {
    sha1_cpu_process( ctx, input );
    input += 64;
    ilen  -= 64;
  }
  
  if ( ilen > 0 ) {
    memcpy( (void *) (ctx->buffer + left),
	    (void *) input, ilen );
  }
}

void SHA1_Final( unsigned char *output, SHA_CTX *ctx ) {
  unsigned long last, padn;
  unsigned long high, low;
  unsigned char msglen[8];
  static const unsigned char sha1_padding[64] =
    {
     0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

  
  high = ( ctx->Nl >> 29 ) | ( ctx->Nh <<  3 );
  low  = ( ctx->Nl <<  3 );
  
  PUT_BE( high, msglen, 0 );
  PUT_BE( low,  msglen, 4 );
  
  last = ctx->Nl & 0x3F;
  padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );
  
  SHA1_Update( ctx, (unsigned char *) sha1_padding, padn );
  SHA1_Update( ctx, msglen, 8 );
  
  PUT_BE( ctx->h0, output,  0 );
  PUT_BE( ctx->h1, output,  4 );
  PUT_BE( ctx->h2, output,  8 );
  PUT_BE( ctx->h3, output, 12 );
  PUT_BE( ctx->h4, output, 16 );

}

void SHA1( unsigned char *input, int ilen,
			unsigned char *output ) {
  SHA_CTX ctx;
  
  SHA1_Init( &ctx );
  SHA1_Update( &ctx, input, ilen );
  SHA1_Final( output, &ctx);

}

void HMAC(uchar *key, int keylen, uchar *msg, int msglen, uchar *output)
{
    int i;
    SHA_CTX ctx;
    unsigned char k_ipad[64];
    unsigned char k_opad[64];
    unsigned char tmpbuf[20];

    memset( k_ipad, 0, sizeof( k_ipad ) );
    memset( k_opad, 0, sizeof( k_opad ) );

    memcpy( k_ipad, key, keylen );
    memcpy( k_opad, key, keylen );

    for( i = 0; i < 64; i++ )
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }
    
    SHA1_Init( &ctx );
    SHA1_Update( &ctx, k_ipad, 64 );
    SHA1_Update( &ctx, msg, msglen );
    SHA1_Final( tmpbuf, &ctx );

    SHA1_Init( &ctx );
    SHA1_Update( &ctx, k_opad, 64 );
    SHA1_Update( &ctx, tmpbuf, 20 );
    SHA1_Final( output, &ctx );

}

#endif

void calc_pmk(const char *key,const char *essid_pre, uchar pmk[32] )
{
	int i, j, slen;
	uchar buffer[64];
    uchar pmkbuffer[40];
	char essid[33+4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	memset(essid,0,sizeof(essid));
    slen = strlen(essid_pre);
    slen = slen <= 32 ? slen : 32;
	memcpy(essid,essid_pre,slen);
	slen = strlen(essid)+4;

	strncpy( (char *) buffer, key, sizeof( buffer ));
	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x36;
	SHA1_Init( &ctx_ipad );
	SHA1_Update( &ctx_ipad, buffer, 64 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x6A;
	SHA1_Init( &ctx_opad );
	SHA1_Update( &ctx_opad, buffer, 64 );

	essid[slen - 1] = '\1';
	#ifdef HAVE_OPENSSL
	    HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, pmkbuffer, NULL);
	#else
	    HMAC((uchar *)key, strlen(key), (uchar*)essid, slen, pmkbuffer);
	#endif
	memcpy( buffer, pmkbuffer, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ )
			pmkbuffer[j] ^= buffer[j];
	}

	essid[slen - 1] = '\2';
	#ifdef HAVE_OPENSSL
	    HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, pmkbuffer+20, NULL);
	#else
	    HMAC((uchar*)key, strlen(key), (uchar*)essid, slen, pmkbuffer+20);
	#endif
	memcpy( buffer, pmkbuffer + 20, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ )
			pmkbuffer[j + 20] ^= buffer[j];
	}
    
    memcpy( pmk,pmkbuffer,32);
}

static PyObject *
cpyrit_pmk(PyObject *self, PyObject *args)
{
    const char *key;
    const char *essid;
    unsigned char pmk[40];
    
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    if (!PyArg_ParseTuple(args, "ss", &essid, &key))
        return NULL;
    calc_pmk(key,essid,pmk);
    PyGILState_Release(gstate);
    return Py_BuildValue("s#", pmk, 32);
}

void*
pmkthread(void *ctr)
{   
    struct thread_ctr *myctr = (struct thread_ctr*)ctr;
    int i;
    void **inbuffer = myctr->keyptr;
    
    for (i = myctr->keyoffset; i < myctr->keycount; i += myctr->keystep) {
        calc_pmk(inbuffer[i], myctr->essid, myctr->bufferptr + (i*32));
    };
    return NULL;
}

PyObject *
cpyrit_pmklist(PyObject *self, PyObject *args)
{
    char *essid;
    PyObject *listObj;
    int numLines;
    int numThreads = 4;
    int i;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    if (!PyArg_ParseTuple(args, "sO!", &essid, &PyList_Type, &listObj)) return NULL;
    numLines = PyList_Size(listObj);
    if (numLines < 0) return NULL;

    void* outbuffer = malloc(numLines * 32);
    PyObject *destlist = PyList_New(numLines);
    void** inbuffer = malloc(numLines * sizeof(void*));
 
    int pwsize = 0;
    for (i = 0; i < numLines; i++)
    {
        pwsize += strlen(PyString_AsString(PyList_GetItem(listObj,i)));
    }
    void* pwbuffer = malloc(pwsize + numLines); 
    void* p = pwbuffer;
    void* t = NULL;
    for (i = 0; i < numLines; i++)
    {
        t = PyString_AsString(PyList_GetItem(listObj,i));
        strcpy(p, t);
        inbuffer[i] = p;
        p += strlen(t) + 1;
    }
    
    Py_BEGIN_ALLOW_THREADS;

    struct thread_ctr ctr[numThreads];
    for (i = 0; i < numThreads; i++)
    {
        ctr[i].keyptr = inbuffer;
        ctr[i].bufferptr = outbuffer;
        ctr[i].keycount = numLines;
        ctr[i].keyoffset = i;
        ctr[i].keystep = numThreads;
        ctr[i].essid = essid;
        pthread_create(&ctr[i].thread_id, NULL, pmkthread, (void *)&ctr[i]);
    };

    for (i = 0; i < numThreads; i++)
    {
        pthread_join(ctr[i].thread_id,NULL);
    };
    
    Py_END_ALLOW_THREADS;
    
    for (i = 0; i < numLines; i++)
    {
        PyList_SetItem(destlist, i, Py_BuildValue("(s,s#)", inbuffer[i], outbuffer+(32*i), 32));
    };
    
    free(outbuffer);
    free(inbuffer);
    free(pwbuffer);

    PyGILState_Release(gstate);
    return destlist;
}

#ifdef HAVE_CUDA
    PyObject *cpyrit_cuda(PyObject *self, PyObject *args);
#endif

static PyMethodDef SpamMethods[] = {
    {"calc_pmk",  cpyrit_pmk, METH_VARARGS, "Calculate something."},
    {"calc_pmklist", cpyrit_pmklist, METH_VARARGS, "Calculate something from a list."},
    #ifdef HAVE_CUDA
        {"calc_cuda", cpyrit_cuda, METH_VARARGS, "Calculate something from a list using CUDA."},
    #endif
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_cpyrit(void)
{
    (void) Py_InitModule("_cpyrit", SpamMethods);
}

int
main(int argc, char *argv[])
{
    /* Initialize the Python interpreter.  Required. */
    Py_Initialize();

    /* Add a static module */
    init_cpyrit();
    
    #ifdef HAVE_CUDA
        char* buffer;
        cudaMallocHost( (void**) &buffer, 4 );
        cudaFreeHost( buffer );
    #endif
    
    return -1;
}
