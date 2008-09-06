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
#include "cpyrit.h"
#include <cuda/cuda.h>
#include <cuda_runtime.h>


/* This is a 'special-version' of the SHA1 round function. *ctx is the current state,
   that gets updated by *data. See comments for the cpyrit_pmk function. Also notice the lack
   of endianess-changes here.
   This follows the more-instructions-less-space paradigm, since registers
   and (fast) memory on the device are precious, threads are not.
   Only the starting values of W[0] to W[4] are undefined, we fix the rest and
   leave the possible register allocation optimization to the compiler
*/
__device__
void sha1_process( const SHA_DEV_CTX *ctx, SHA_DEV_CTX *data) {

  unsigned long temp, W[16], A, B, C, D, E;

  W[ 0] = data->h0; W[ 1] = data->h1;
  W[ 2] = data->h2; W[ 3] = data->h3;
  W[ 4] = data->h4; W[ 5] = 0x80000000;
  W[ 6] = 0; W[ 7] = 0;
  W[ 8] = 0; W[ 9] = 0;
  W[10] = 0; W[11] = 0;
  W[12] = 0; W[13] = 0;
  W[14] = 0; W[15] = (64+20)*8;

  A = ctx->h0;
  B = ctx->h1;
  C = ctx->h2;
  D = ctx->h3;
  E = ctx->h4;

#undef S
#define S(x,n) ((x << n) | (x >> (32 - n)))

#undef R
#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)
#undef P
#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

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

  data->h0 = ctx->h0 + A;
  data->h1 = ctx->h1 + B;
  data->h2 = ctx->h2 + C;
  data->h3 = ctx->h3 + D;
  data->h4 = ctx->h4 + E;

}

/* This is the kernel called by the cpu. We grab as many as we can from
   global (slow) memory, the IPAD and OPAD values are cached */
__global__
void cuda_pmk_kernel( gpu_inbuffer *inbuffer, gpu_outbuffer *outbuffer, const int numLines) {
    int i;
    SHA_DEV_CTX temp_ctx, pmk_ctx;
    __shared__ SHA_DEV_CTX ipad[64], opad[64];
    
    int idx = blockIdx.x * blockDim.x + threadIdx.x;  
    if (idx > numLines-1) return;
    
    CPY_DEVCTX(inbuffer[idx].ctx_ipad, ipad[threadIdx.x]);
    CPY_DEVCTX(inbuffer[idx].ctx_opad, opad[threadIdx.x]);    
    
    CPY_DEVCTX(inbuffer[idx].e1, temp_ctx);
    CPY_DEVCTX(temp_ctx, pmk_ctx);
    for( i = 0; i < 4096-1; i++ )
    {
        sha1_process( &ipad[threadIdx.x], &temp_ctx);
        sha1_process( &opad[threadIdx.x], &temp_ctx);
        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;
        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;
        pmk_ctx.h4 ^= temp_ctx.h4;
    }
    CPY_DEVCTX(pmk_ctx, outbuffer[idx].pmk1);
    
    CPY_DEVCTX(inbuffer[idx].e2, temp_ctx);
    CPY_DEVCTX(temp_ctx, pmk_ctx);
    for( i = 0; i < 4096-1; i++ )
    {
        sha1_process( &ipad[threadIdx.x], &temp_ctx);
        sha1_process( &opad[threadIdx.x], &temp_ctx);
        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;
        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;
        pmk_ctx.h4 ^= temp_ctx.h4;
    }
    CPY_DEVCTX(pmk_ctx, outbuffer[idx].pmk2);
    
}

/* Takes list of passwords, gives PMKs... Since the size of passwords
   may exceed one block of SHA-1 (64-padding), the first HMAC is done on the cpu while
   the other 8190 rounds can then be easily done on the gpu - the block is always
   20 bytes wide then. Notice that we only have to change the endianess once here, not
   between every single round of SHA-1
*/
extern "C"
PyObject *cpyrit_cuda(PyObject *self, PyObject *args)
{
    char *essid_pre;
	char essid[33+4];
	unsigned char temp[32];
    PyObject *listObj;
    int numLines;
    int i;
    int line;
	SHA_CTX ctx_pad;
	unsigned char pad[64];
	int slen;
    void* g_inbuffer;
    gpu_inbuffer* c_inbuffer;
    void* g_outbuffer;
    gpu_outbuffer* c_outbuffer;
    cudaEvent_t evt;    

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    if (!PyArg_ParseTuple(args, "sO!", &essid_pre, &PyList_Type, &listObj)) return NULL;
    numLines = PyList_Size(listObj);
    if (numLines < 0) return NULL;

    c_inbuffer = (gpu_inbuffer *)malloc(numLines*sizeof(gpu_inbuffer));
    c_outbuffer = (gpu_outbuffer *)malloc(numLines*sizeof(gpu_outbuffer));

	memset( essid, 0, sizeof(essid) );
    slen = strlen(essid_pre);
    slen = slen <= 32 ? slen : 32;
	memcpy(essid, essid_pre, slen);
	slen = strlen(essid)+4;

    for (line = 0; line < numLines; line++)
    {
        char *key = PyString_AsString(PyList_GetItem(listObj, line));
        
	    strncpy((char*)pad, key, sizeof(pad));
	    for( i = 0; i < sizeof(pad); i++ )
		    pad[i] ^= 0x36;
	    SHA1_Init( &ctx_pad );
	    SHA1_Update( &ctx_pad, pad, sizeof(pad) );
	    CPY_DEVCTX(ctx_pad, c_inbuffer[line].ctx_ipad);

	    for ( i = 0; i < sizeof(pad); i++ )
	        pad[i] ^= (0x36 ^ 0x5c);
        SHA1_Init(&ctx_pad);
        SHA1_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX(ctx_pad, c_inbuffer[line].ctx_opad);
	    
	    essid[slen - 1] = '\1';
	    #ifdef HAVE_OPENSSL
	        HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, temp, NULL);
	    #else
	        HMAC((uchar *)key, strlen(key), (uchar*)essid, slen, temp);
	    #endif
        GET_BE(c_inbuffer[line].e1.h0, temp, 0); GET_BE(c_inbuffer[line].e1.h1, temp, 4);
        GET_BE(c_inbuffer[line].e1.h2, temp, 8); GET_BE(c_inbuffer[line].e1.h3, temp, 12);
        GET_BE(c_inbuffer[line].e1.h4, temp, 16);

	    
	    essid[slen - 1] = '\2';
	    #ifdef HAVE_OPENSSL
	        HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, temp, NULL);
	    #else
	        HMAC((uchar *)key, strlen(key), (uchar*)essid, slen, temp);
	    #endif
        GET_BE(c_inbuffer[line].e2.h0, temp, 0); GET_BE(c_inbuffer[line].e2.h1, temp, 4);
        GET_BE(c_inbuffer[line].e2.h2, temp, 8); GET_BE(c_inbuffer[line].e2.h3, temp, 12);
        GET_BE(c_inbuffer[line].e2.h4, temp, 16);
    }

    // We promise not to touch python objects beyond this point 
    Py_BEGIN_ALLOW_THREADS;

    cudaMalloc(&g_inbuffer, numLines*sizeof(gpu_inbuffer));
    cudaMemcpy(g_inbuffer, c_inbuffer, numLines*sizeof(gpu_inbuffer), cudaMemcpyHostToDevice);
    cudaMalloc(&g_outbuffer, numLines*sizeof(gpu_outbuffer));
    free(c_inbuffer);
 
    // Execute the kernel in blocks of 64 threads each. The GPU can decide to execute as many blocks
    // as possible and needed to complete the task. Remember to fix the size of ipad[] and opad[] in the
    // kernel if you change this value. You must also use the occupancy calculator - more may be worse!   
    int block_size = 64;
    int n_blocks = numLines / block_size + (numLines % block_size == 0 ? 0 : 1);
    cudaEventCreate(&evt);
    cuda_pmk_kernel<<<n_blocks, block_size>>>((gpu_inbuffer*)g_inbuffer, (gpu_outbuffer*)g_outbuffer, numLines);
    cudaEventRecord(evt, NULL);
    while (cudaEventQuery(evt) == cudaErrorNotReady) { usleep(500); }
    cudaEventDestroy(evt);

    cudaFree(g_inbuffer);
    cudaMemcpy(c_outbuffer, g_outbuffer, numLines*sizeof(gpu_outbuffer), cudaMemcpyDeviceToHost);
    cudaFree(g_outbuffer);
    
    Py_END_ALLOW_THREADS;
	
    PyObject *destlist = PyList_New(numLines);
    for (i = 0; i < numLines; i++)
    {
        PUT_BE(c_outbuffer[i].pmk1.h0, temp, 0); PUT_BE(c_outbuffer[i].pmk1.h1, temp, 4);
        PUT_BE(c_outbuffer[i].pmk1.h2, temp, 8); PUT_BE(c_outbuffer[i].pmk1.h3, temp, 12); 
        PUT_BE(c_outbuffer[i].pmk1.h4, temp, 16);PUT_BE(c_outbuffer[i].pmk2.h0, temp, 20); 
        PUT_BE(c_outbuffer[i].pmk2.h1, temp, 24);PUT_BE(c_outbuffer[i].pmk2.h2, temp, 28); 
        PyList_SetItem(destlist, i, Py_BuildValue("(s,s#)", PyString_AsString(PyList_GetItem(listObj, i)), temp, 32));
    }    
    free(c_outbuffer);
    
    PyGILState_Release(gstate);
    return destlist;
}
