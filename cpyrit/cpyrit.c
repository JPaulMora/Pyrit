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

#ifdef HAVE_PADLOCK

// This instruction is not available on all CPUs (do we really care about those?)
// Therefor it is only used on padlock-enabled machines
static inline int bswap(int x)
{
    asm volatile ("bswap %0":
                "=r" (x):
                "0" (x));
    return x;
}

static inline int
padlock_xsha1_lowlevel(char *input, unsigned int *output, int count)
{
    int done = 0;
    asm volatile ("xsha1"
              : "+S"(input), "+D"(output), "+a"(done)
              : "c"(count));
    return done;
}

// See the padlock programming guide. XSHA1 always finalizes the hash
// (including msglen) by itself. Therefor we can't use cached values for
// ipad/opad. The SIGSEV-trick is even slower than this due to pipeline stalls.
static inline int
padlock_xsha1(const unsigned char* pad, unsigned char* buffer)
{
    struct xsha1_ctx ctx;
    size_t hashed;

    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xEFCDAB89;
    ctx.state[2] = 0x98BADCFE;
    ctx.state[3] = 0x10325476;
    ctx.state[4] = 0xC3D2E1F0;

    memcpy(ctx.inputbuffer, pad, 64);
    memcpy(ctx.inputbuffer+64, buffer, 20);
    hashed = padlock_xsha1_lowlevel(ctx.inputbuffer, ctx.state, 64+20);

    ((int*)buffer)[0] = bswap(ctx.state[0]); ((int*)buffer)[1] = bswap(ctx.state[1]); 
    ((int*)buffer)[2] = bswap(ctx.state[2]); ((int*)buffer)[3] = bswap(ctx.state[3]); 
    ((int*)buffer)[4] = bswap(ctx.state[4]); 

    return hashed;
}

void calc_pmk(const char *key, const char *essid_pre, unsigned char pmk[32])
{
    int i, slen;
    unsigned char ipad[64], opad[64];
    char essid[33+4];
    unsigned int pmkbuffer[8], lbuffer[5], rbuffer[5];

	memset(essid,0,sizeof(essid));
    slen = strlen(essid_pre);
    slen = slen <= 32 ? slen : 32;
	memcpy(essid,essid_pre,slen);
	slen = strlen(essid)+4;

    strncpy((char *)ipad, key, sizeof(ipad));
    strncpy((char *)opad, key, sizeof(opad));
    for (i = 0; i < 64; i++)
    {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5C;
    }
    
    essid[slen - 1] = '\1';
    HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, (unsigned char*)lbuffer, NULL);
    memcpy(pmkbuffer, lbuffer, 20);    
    
    essid[slen - 1] = '\2';
    HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, (unsigned char*)rbuffer, NULL);
    memcpy(&(pmkbuffer[5]), rbuffer, 12);

    for (i = 0; i < 4096-1; i++)
    {
        padlock_xsha1(ipad, (unsigned char*)lbuffer);
        padlock_xsha1(opad, (unsigned char*)lbuffer);
        padlock_xsha1(ipad, (unsigned char*)rbuffer);
        padlock_xsha1(opad, (unsigned char*)rbuffer);
                
		pmkbuffer[0] ^= lbuffer[0]; pmkbuffer[1] ^= lbuffer[1];
		pmkbuffer[2] ^= lbuffer[2]; pmkbuffer[3] ^= lbuffer[3];
		pmkbuffer[4] ^= lbuffer[4];
		pmkbuffer[5] ^= rbuffer[0]; pmkbuffer[6] ^= rbuffer[1];
		pmkbuffer[7] ^= rbuffer[2];

	}

    memcpy(pmk, pmkbuffer, 32);
}

#else

void calc_pmk(const char *key, const char *essid_pre, unsigned char pmk[32])
{
	int i, slen;
	unsigned char buffer[64];
	unsigned int pmkbuffer[10];
	char essid[33+4];
	SHA_CTX ctx_ipad, ctx_opad, sha1_ctx;

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
    HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, (unsigned char*)pmkbuffer, NULL);
	memcpy( buffer, pmkbuffer, 20 );
	
	essid[slen - 1] = '\2';
    HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, (unsigned char *)(&pmkbuffer[5]), NULL);
	memcpy( buffer+20, (unsigned char*)(&pmkbuffer[5]), 20 );

	for( i = 0; i < 4096-1; i++ )
	{
		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);
		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer+20, 20);
		SHA1_Final(buffer+20, &sha1_ctx);
		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer+20, 20);
		SHA1_Final(buffer+20, &sha1_ctx);

		pmkbuffer[0] ^= ((unsigned int*)buffer)[0];	pmkbuffer[1] ^= ((unsigned int*)buffer)[1];
		pmkbuffer[2] ^= ((unsigned int*)buffer)[2];	pmkbuffer[3] ^= ((unsigned int*)buffer)[3];
		pmkbuffer[4] ^= ((unsigned int*)buffer)[4];	pmkbuffer[5] ^= ((unsigned int*)buffer)[5];
		pmkbuffer[6] ^= ((unsigned int*)buffer)[6]; pmkbuffer[7] ^= ((unsigned int*)buffer)[7];		

	}

    memcpy(pmk, pmkbuffer, 32);
}

#endif

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

// The basic plan is to first copy the input list to an internal buffer, allow other
// python thread to run while calculating the results and then build a result list.
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
    
    // Don't touch Python-objects beyond this point!
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
    
    // Re-acquire the GIL
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

    init_cpyrit();
    
    #ifdef HAVE_CUDA
        char* buffer;
        cudaMallocHost( (void**) &buffer, 4 );
        cudaFreeHost( buffer );
    #endif
    
    return -1;
}
