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

int numThreads = 4;

#ifdef HAVE_CUDA
    int cudadev;
    int cudadevcount;
    struct cudaDeviceProp cuda_devprop;
#endif

#ifdef HAVE_PADLOCK

pthread_mutex_t padlock_sigmutex;

// This instruction is not available on all CPUs (do we really care about those?)
// Therefor it is only used on padlock-enabled machines
static inline int bswap(int x)
{
    asm volatile ("bswap %0":
                "=r" (x):
                "0" (x));
    return x;
}

static int
padlock_xsha1_lowlevel(char *input, unsigned int *output, int done, int count)
{
    int d = done;
    asm volatile ("xsha1"
              : "+S"(input), "+D"(output), "+a"(d)
              : "c"(count));
    return d;
}

// This handler will ignore the SIGSEGV caused by the padlock_xsha1_prepare
static void
segv_action(int sig, siginfo_t *info, void *uctxp)
{
    ucontext_t *uctx = uctxp;
    uctx->uc_mcontext.gregs[14] += 4;
    return;
}

// REP XSHA1 is crashed into the mprotect'ed page so we can
// steal the state at *EDI before finalizing.
static int
padlock_xsha1_prepare(const unsigned char* input, unsigned char* output)
{
    size_t page_size = getpagesize(), buffersize = 2 * page_size, hashed = 0;
    struct sigaction act, oldact;
    unsigned char* inputbuffer = mmap(0, buffersize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    mprotect(inputbuffer + page_size, page_size, PROT_NONE);

    struct xsha1_ctx ctx;
    ((int*)ctx.state)[0] = 0x67452301;
    ((int*)ctx.state)[1] = 0xEFCDAB89;
    ((int*)ctx.state)[2] = 0x98BADCFE;
    ((int*)ctx.state)[3] = 0x10325476;
    ((int*)ctx.state)[4] = 0xC3D2E1F0;

    unsigned char *cnt = inputbuffer + page_size - (64*2);
    memcpy(cnt, input, 64);
    memset(&act, 0, sizeof(act));

    // not smart but effective
    pthread_mutex_lock(&padlock_sigmutex);
    act.sa_sigaction = segv_action;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, &oldact);

    hashed = padlock_xsha1_lowlevel(cnt, ctx.state, 0, (64*2));

    sigaction(SIGSEGV, &oldact, NULL);
    pthread_mutex_unlock(&padlock_sigmutex);

    munmap(inputbuffer, buffersize);
    memcpy(output, ctx.state, 20);

    return hashed;
}

// Now lie about the total number of bytes hashed by this call to get the correct hash
static inline int
padlock_xsha1_finalize(unsigned char* prestate, unsigned char* buffer)
{
    struct xsha1_ctx ctx;
    size_t hashed;

    memcpy(ctx.state, prestate, 20);
    memcpy(ctx.inputbuffer, buffer, 20);
    hashed = padlock_xsha1_lowlevel(ctx.inputbuffer, ctx.state, 64, 64+20);

    ((int*)buffer)[0] = bswap(ctx.state[0]); ((int*)buffer)[1] = bswap(ctx.state[1]);
    ((int*)buffer)[2] = bswap(ctx.state[2]); ((int*)buffer)[3] = bswap(ctx.state[3]);
    ((int*)buffer)[4] = bswap(ctx.state[4]);

    return hashed;
}

void calc_pmk(const char *key, const char *essid_pre, unsigned char pmk[32])
{
    int i, slen;
    unsigned char pad[64], ipad_state[20], opad_state[20];
    char essid[33+4];
    unsigned int pmkbuffer[8], lbuffer[5], rbuffer[5];

    memset(essid,0,sizeof(essid));
    slen = strlen(essid_pre);
    slen = slen <= 32 ? slen : 32;
    memcpy(essid,essid_pre,slen);
    slen = strlen(essid)+4;

    strncpy((char *)pad, key, sizeof(pad));
    for (i = 0; i < 16; i++)
        ((unsigned int*)pad)[i] ^= 0x36363636;
    padlock_xsha1_prepare(pad, ipad_state);

    strncpy((char *)pad, key, sizeof(pad));
    for (i = 0; i < 16; i++)
        ((unsigned int*)pad)[i] ^= 0x5C5C5C5C;
    padlock_xsha1_prepare(pad, opad_state);

    essid[slen - 1] = '\1';
    HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, (unsigned char*)lbuffer, NULL);
    memcpy(pmkbuffer, lbuffer, 20);

    essid[slen - 1] = '\2';
    HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, (unsigned char*)rbuffer, NULL);
    memcpy(&(pmkbuffer[5]), rbuffer, 12);

    for (i = 0; i < 4096-1; i++)
    {
        padlock_xsha1_finalize(ipad_state, (unsigned char*)lbuffer);
        padlock_xsha1_finalize(opad_state, (unsigned char*)lbuffer);
        padlock_xsha1_finalize(ipad_state, (unsigned char*)rbuffer);
        padlock_xsha1_finalize(opad_state, (unsigned char*)rbuffer);

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

        pmkbuffer[0] ^= ((unsigned int*)buffer)[0]; pmkbuffer[1] ^= ((unsigned int*)buffer)[1];
        pmkbuffer[2] ^= ((unsigned int*)buffer)[2]; pmkbuffer[3] ^= ((unsigned int*)buffer)[3];
        pmkbuffer[4] ^= ((unsigned int*)buffer)[4]; pmkbuffer[5] ^= ((unsigned int*)buffer)[5];
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

static PyObject *
cpyrit_set_numThreads(PyObject *self, PyObject *args)
{
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    int nthreads;

    if (!PyArg_ParseTuple(args, "i", &nthreads))
        return NULL;

    nthreads = nthreads > 32 ? 32 : (nthreads < 1 ? 1 : nthreads);
    numThreads = nthreads;

    PyGILState_Release(gstate);
    return Py_BuildValue("i", numThreads);
}

void*
pmkthread(void *ctr)
{
    struct thread_ctr *myctr = (struct thread_ctr*)ctr;
    int i;
    void **inbuffer = myctr->keyptr;

    for (i = myctr->keyoffset; i < myctr->keycount; i += myctr->keystep)
        calc_pmk(inbuffer[i], myctr->essid, myctr->bufferptr + (i*32));
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
        PyList_SetItem(destlist, i, Py_BuildValue("(s,s#)", inbuffer[i], outbuffer+(32*i), 32));

    free(outbuffer);
    free(inbuffer);
    free(pwbuffer);

    PyGILState_Release(gstate);
    return destlist;
}

#ifdef HAVE_CUDA
    //Will be linked as object file
    PyObject *cpyrit_cuda(PyObject *self, PyObject *args);
    
    PyObject *cpyrit_devprops(PyObject *self, PyObject *args)
    {
        if (!PyArg_ParseTuple(args, "")) return NULL;
    
        return Py_BuildValue("iisiiii", cudadevcount, cudadev, &cuda_devprop.name, cuda_devprop.totalGlobalMem,
                                        cuda_devprop.regsPerBlock, cuda_devprop.clockRate, cuda_devprop.multiProcessorCount);
    }
#endif

static PyMethodDef SpamMethods[] = {
    {"set_numThreads", cpyrit_set_numThreads, METH_VARARGS, "Set number of threads for CPU-bound calculations"},
    
    #ifdef HAVE_PADLOCK
        {"calc_pmk",  cpyrit_pmk, METH_VARARGS, "Calculate PMK from ESSID and string (VIA Padlock)"},
    #else
        {"calc_pmk",  cpyrit_pmk, METH_VARARGS, "Calculate PMK from ESSID and string (x86)"},
    #endif
    {"calc_pmklist", cpyrit_pmklist, METH_VARARGS, "Calculate PMKs from ESSID and list of strings"},
    
    #ifdef HAVE_CUDA
        {"calc_cuda", cpyrit_cuda, METH_VARARGS, "Calculate PMKs from ESSID and list of strings"},
        {"cudaprops", cpyrit_devprops, METH_VARARGS, "Returns a tuple with some properties about main device"},
    #endif
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_cpyrit(void)
{
    (void) Py_InitModule("_cpyrit", SpamMethods);


    #ifdef HAVE_CUDA
    
        // This is a somewhat awkward way to initialize the GPU as a CUDA-context
        // is thread specific. There is no guarantee that the cuda functions above will be called
        // by the same thread which called this code. However we will not force that as at
        // some point in the future we need multi-gpu functionality anyway.
        char* buffer;
        cudaMallocHost((void**) &buffer, 4);
        cudaFreeHost(buffer);
        
        cudaGetDeviceCount(&cudadevcount);
        cudaGetDevice(&cudadev);
        cudaGetDeviceProperties(&cuda_devprop, cudadev);
        int ret = cudaGetLastError();
        if (ret != cudaSuccess)
        {
            PyErr_SetString(PyExc_SystemError, cudaGetErrorString(ret));
            return;
        }

    #endif

    #ifdef HAVE_PADLOCK
        pthread_mutex_init(&padlock_sigmutex, NULL);
    #endif
}

int
main(int argc, char *argv[])
{
    Py_Initialize();

    init_cpyrit();

    return -1;
}
