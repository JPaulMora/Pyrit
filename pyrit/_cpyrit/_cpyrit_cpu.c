/*
#
#    Copyright 2008, 2009, Lukas Lueg, knabberknusperhaus@yahoo.de
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

#include <Python.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

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

static PyTypeObject CPUDevice_type;

typedef struct
{
    PyObject_HEAD
} CPUDevice;

struct pmk_ctr
{
    SHA_CTX ctx_ipad;
    SHA_CTX ctx_opad;
    unsigned int e1[5];
    unsigned int e2[5];
};

// Execution path depends on having Padlock vs. pure x86
void (*prepare_pmk)(const char*, const char*, struct pmk_ctr*) = NULL;
void (*finalize_pmk)(struct pmk_ctr*) = NULL;

#ifdef COMPILE_PADLOCK
    #include <sys/ucontext.h>
    #include <signal.h>
    #include <errno.h>
    #include <sys/mman.h>

    struct xsha1_ctx {
        unsigned int state[32];
        unsigned char inputbuffer[20+64];
    } __attribute__((aligned(16)));

    // Snippet taken from OpenSSL 0.9.8
    static unsigned char
    padlock_available(void)
    {
        char vendor_string[16];
        unsigned int eax, edx;

        eax = 0x00000000;
        vendor_string[12] = 0;
        asm volatile (
                "pushl  %%ebx\n"
                "cpuid\n"
                "movl   %%ebx,(%%edi)\n"
                "movl   %%edx,4(%%edi)\n"
                "movl   %%ecx,8(%%edi)\n"
                "popl   %%ebx"
                : "+a"(eax) : "D"(vendor_string) : "ecx", "edx");
        if (strcmp(vendor_string, "CentaurHauls") != 0)
                return 0;

        /* Check for Centaur Extended Feature Flags presence */
        eax = 0xC0000000;
        asm volatile ("pushl %%ebx; cpuid; popl %%ebx"
                : "+a"(eax) : : "ecx", "edx");
        if (eax < 0xC0000001)
                return 0;

        /* Read the Centaur Extended Feature Flags */
        eax = 0xC0000001;
        asm volatile ("pushl %%ebx; cpuid; popl %%ebx"
                : "+a"(eax), "=d"(edx) : : "ecx");

        return (edx & 0x300) == 0x300;
    }

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
    padlock_xsha1(unsigned char *input, unsigned int *output, int done, int count)
    {
        int volatile d = done;
        asm volatile ("xsha1"
                  : "+S"(input), "+D"(output), "+a"(d)
                  : "c"(count));
        return d;
    }

    // This handler will ignore the SIGSEGV deliberately caused by padlock_xsha1_prepare
    static void
    segv_action(int sig, siginfo_t *info, void *uctxp)
    {
        ucontext_t *uctx = uctxp;
        MCTX_EIP(uctx) += 4;
        return;
    }

    // REP XSHA1 is crashed into the mprotect'ed page so we can
    // steal the state at *EDI before finalizing.
    static int
    padlock_xsha1_prepare(const unsigned char *input, SHA_CTX *output)
    {
        size_t page_size = getpagesize(), buffersize = 2 * page_size, hashed = 0;
        struct sigaction act, oldact;
        unsigned char *cnt;
        unsigned char* inputbuffer = mmap(0, buffersize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

        mprotect(inputbuffer + page_size, page_size, PROT_NONE);

        struct xsha1_ctx ctx;
        ((int*)ctx.state)[0] = 0x67452301;
        ((int*)ctx.state)[1] = 0xEFCDAB89;
        ((int*)ctx.state)[2] = 0x98BADCFE;
        ((int*)ctx.state)[3] = 0x10325476;
        ((int*)ctx.state)[4] = 0xC3D2E1F0;

        cnt = inputbuffer + page_size - (64*2);
        memcpy(cnt, input, 64);
        memset(&act, 0, sizeof(act));
        act.sa_sigaction = segv_action;
        act.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &act, &oldact);
        hashed = padlock_xsha1(cnt, ctx.state, 0, (64*2));        
        sigaction(SIGSEGV, &oldact, NULL);

        munmap(inputbuffer, buffersize);
        
        output->h0 = ((int*)ctx.state)[0];
        output->h1 = ((int*)ctx.state)[1];
        output->h2 = ((int*)ctx.state)[2];
        output->h3 = ((int*)ctx.state)[3];
        output->h4 = ((int*)ctx.state)[4];

        return hashed;
    }

    // Now lie about the total number of bytes hashed by this call to get the correct hash
    static inline int
    padlock_xsha1_finalize(SHA_CTX *prestate, unsigned char *buffer)
    {
        struct xsha1_ctx ctx;
        size_t hashed;

        ((int*)ctx.state)[0] = prestate->h0;
        ((int*)ctx.state)[1] = prestate->h1;
        ((int*)ctx.state)[2] = prestate->h2;
        ((int*)ctx.state)[3] = prestate->h3;
        ((int*)ctx.state)[4] = prestate->h4;
            
        memcpy(ctx.inputbuffer, buffer, 20);
        hashed = padlock_xsha1(ctx.inputbuffer, ctx.state, 64, 64+20);

        ((int*)buffer)[0] = bswap(ctx.state[0]); ((int*)buffer)[1] = bswap(ctx.state[1]);
        ((int*)buffer)[2] = bswap(ctx.state[2]); ((int*)buffer)[3] = bswap(ctx.state[3]);
        ((int*)buffer)[4] = bswap(ctx.state[4]);

        return hashed;
    }

    static void
    prepare_pmk_padlock(const char *essid_pre, const char *password, struct pmk_ctr *ctr)
    {

        int i, slen;
        unsigned char pad[64];
        char essid[33+4];

        memset(essid,0,sizeof(essid));
        slen = strlen(essid_pre);
        slen = slen <= 32 ? slen : 32;
        memcpy(essid,essid_pre,slen);
        slen = strlen(essid)+4;

        strncpy((char *)pad, password, sizeof(pad));
        for (i = 0; i < 16; i++)
            ((unsigned int*)pad)[i] ^= 0x36363636;
        padlock_xsha1_prepare(pad, &ctr->ctx_ipad);

        for (i = 0; i < 16; i++)
            ((unsigned int*)pad)[i] ^= 0x6A6A6A6A;
        padlock_xsha1_prepare(pad, &ctr->ctx_opad);

        essid[slen - 1] = '\1';
        HMAC(EVP_sha1(), (unsigned char *)password, strlen(password), (unsigned char*)essid, slen, (unsigned char*)ctr->e1, NULL);

        essid[slen - 1] = '\2';
        HMAC(EVP_sha1(), (unsigned char *)password, strlen(password), (unsigned char*)essid, slen, (unsigned char*)ctr->e2, NULL);

    }

    static void
    finalize_pmk_padlock(struct pmk_ctr *ctr)
    {
        int i;
        unsigned int e1_buffer[5];
        unsigned int e2_buffer[5];

        memcpy(e1_buffer, ctr->e1, 20);
        memcpy(e2_buffer, ctr->e2, 20);
        for (i = 0; i < 4096-1; i++)
        {
            padlock_xsha1_finalize(&ctr->ctx_ipad, (unsigned char*)e1_buffer);
            padlock_xsha1_finalize(&ctr->ctx_opad, (unsigned char*)e1_buffer);
            ctr->e1[0] ^= e1_buffer[0]; ctr->e1[1] ^= e1_buffer[1]; ctr->e1[2] ^= e1_buffer[2];
            ctr->e1[3] ^= e1_buffer[3]; ctr->e1[4] ^= e1_buffer[4];
            
            padlock_xsha1_finalize(&ctr->ctx_ipad, (unsigned char*)e2_buffer);
            padlock_xsha1_finalize(&ctr->ctx_opad, (unsigned char*)e2_buffer);
            ctr->e2[0] ^= e2_buffer[0]; ctr->e2[1] ^= e2_buffer[1]; ctr->e2[2] ^= e2_buffer[2];
        }
    }

#endif // COMPILE_PADLOCK

static void
prepare_pmk_openssl(const char *essid_pre, const char *password, struct pmk_ctr *ctr)
{
    int i, slen;
    unsigned char pad[64];
    char essid[33+4];

    memset(essid, 0, sizeof(essid));
    slen = strlen(essid_pre);
    slen = slen <= 32 ? slen : 32;
    memcpy(essid,essid_pre,slen);
    slen = strlen(essid)+4;

    strncpy((char *)pad, password, sizeof(pad));
    for( i = 0; i < 16; i++ )
	    ((unsigned int*)pad)[i] ^= 0x36363636;
    SHA1_Init(&ctr->ctx_ipad);
    SHA1_Update(&ctr->ctx_ipad, pad, 64);

    for( i = 0; i < 16; i++ )
	    ((unsigned int*)pad)[i] ^= 0x6A6A6A6A;
    SHA1_Init(&ctr->ctx_opad);
    SHA1_Update(&ctr->ctx_opad, pad, 64);

    essid[slen - 1] = '\1';
    HMAC(EVP_sha1(), (unsigned char *)password, strlen(password), (unsigned char*)essid, slen, (unsigned char*)ctr->e1, NULL);
    
    essid[slen - 1] = '\2';
    HMAC(EVP_sha1(), (unsigned char *)password, strlen(password), (unsigned char*)essid, slen, (unsigned char*)ctr->e2, NULL);

}

static void
finalize_pmk_openssl(struct pmk_ctr *ctr)
{
    int i;
    SHA_CTX ctx;
    unsigned int e1_buffer[5];
    unsigned int e2_buffer[5];

    memcpy(e1_buffer, ctr->e1, 20);
    memcpy(e2_buffer, ctr->e2, 20);
    for(i = 0; i < 4096-1; i++)
    {
        memcpy(&ctx, &ctr->ctx_ipad, sizeof(ctx));
        SHA1_Update(&ctx, (unsigned char*)e1_buffer, 20);
        SHA1_Final((unsigned char*)e1_buffer, &ctx);
        
        memcpy(&ctx, &ctr->ctx_opad, sizeof(ctx));
        SHA1_Update(&ctx, (unsigned char*)e1_buffer, 20);
        SHA1_Final((unsigned char*)e1_buffer, &ctx);

        ctr->e1[0] ^= e1_buffer[0]; ctr->e1[1] ^= e1_buffer[1]; ctr->e1[2] ^= e1_buffer[2]; 
        ctr->e1[3] ^= e1_buffer[3]; ctr->e1[4] ^= e1_buffer[4]; 

        memcpy(&ctx, &ctr->ctx_ipad, sizeof(ctx));
        SHA1_Update(&ctx, (unsigned char*)e2_buffer, 20);
        SHA1_Final((unsigned char*)e2_buffer, &ctx);
        
        memcpy(&ctx, &ctr->ctx_opad, sizeof(ctx));
        SHA1_Update(&ctx, (unsigned char*)e2_buffer, 20);
        SHA1_Final((unsigned char*)e2_buffer, &ctx);

        ctr->e2[0] ^= e2_buffer[0]; ctr->e2[1] ^= e2_buffer[1]; ctr->e2[2] ^= e2_buffer[2]; 
    }
    
}

static PyObject *
cpyrit_getPlatform(PyObject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
			
    #ifdef COMPILE_PADLOCK
        if (padlock_available())
        {
            return PyString_FromString("VIA Padlock");
        } else {
            return PyString_FromString("x86");
        }
	#elif defined(__x86_64__)
		return PyString_FromString("x86_64");
	#else
		return PyString_FromString("unknown");
    #endif
}

static PyObject *
cpyrit_solve(PyObject *self, PyObject *args)
{
    char *essid, *passwd;
    PyObject *passwd_seq, *passwd_obj, *result;
    int i, arraysize;
    struct pmk_ctr *pmk_buffer, *t;

    if (!PyArg_ParseTuple(args, "sO", &essid, &passwd_seq)) return NULL;
    passwd_seq = PyObject_GetIter(passwd_seq);
    if (!passwd_seq) return NULL;
    
    arraysize = 0;
    pmk_buffer = NULL;
    while ((passwd_obj=PyIter_Next(passwd_seq)))
    {
        if (arraysize % 100 == 0)
        {
            t = PyMem_Realloc(pmk_buffer, sizeof(struct pmk_ctr)*(arraysize+100));
            if (!t)
            {
                Py_DECREF(passwd_seq);
                PyMem_Free(pmk_buffer);
                PyErr_NoMemory();
                return NULL;
            }
            pmk_buffer = t;
        }
        passwd = PyString_AsString(passwd_obj);
        if (passwd == NULL || strlen(passwd) < 8 || strlen(passwd) > 63)
        {
            Py_DECREF(passwd_seq);
            PyMem_Free(pmk_buffer);
            PyErr_SetString(PyExc_ValueError, "All items must be strings between 8 and 63 characters");
            return NULL;
        }
        prepare_pmk(essid, passwd, &pmk_buffer[arraysize]);
        arraysize++;
    }
            
    Py_BEGIN_ALLOW_THREADS;
    for (i = 0; i < arraysize; i++)
        finalize_pmk(&pmk_buffer[i]);
    Py_END_ALLOW_THREADS;

    result = PyTuple_New(arraysize);
    for (i = 0; i < arraysize; i++)
        PyTuple_SetItem(result, i, Py_BuildValue("s#", pmk_buffer[i].e1, 32));

    Py_DECREF(passwd_seq);
    PyMem_Free(pmk_buffer);

    return result;
}

static PyMethodDef CPUDevice_methods[] =
{
    {"solve", (PyCFunction)cpyrit_solve, METH_VARARGS, "Calculate PMKs from ESSID and iterable of strings."},
    {NULL, NULL}
};

static PyTypeObject CPUDevice_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_cpu.CPUDevice",    /*tp_name*/
    sizeof(CPUDevice),          /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    0,                          /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    0,                          /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash*/
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    0,                          /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT          /*tp_flags*/
     | Py_TPFLAGS_BASETYPE,
    0,                          /*tp_doc*/
    0,                          /*tp_traverse*/
    0,                          /*tp_clear*/
    0,                          /*tp_richcompare*/
    0,                          /*tp_weaklistoffset*/
    0,                          /*tp_iter*/
    0,                          /*tp_iternext*/
    CPUDevice_methods,          /*tp_methods*/
    0,                          /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    0,                          /*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};

static PyMethodDef CPyritCPUMethods[] = {
    {"getPlatform", cpyrit_getPlatform, METH_VARARGS, "Determine CPU-type/name"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_cpyrit_cpu(void)
{
    PyObject *m;

    #ifdef COMPILE_PADLOCK
        if (padlock_available())
        {
            prepare_pmk = prepare_pmk_padlock;
            finalize_pmk = finalize_pmk_padlock;
        } else {
            prepare_pmk = prepare_pmk_openssl;
            finalize_pmk = finalize_pmk_openssl;
        }
    #else
        prepare_pmk = prepare_pmk_openssl;
        finalize_pmk = finalize_pmk_openssl;
    #endif

    CPUDevice_type.tp_getattro = PyObject_GenericGetAttr;
    CPUDevice_type.tp_setattro = PyObject_GenericSetAttr;
    CPUDevice_type.tp_alloc  = PyType_GenericAlloc;
    CPUDevice_type.tp_new = PyType_GenericNew;
    CPUDevice_type.tp_free = _PyObject_Del;  
    if (PyType_Ready(&CPUDevice_type) < 0)
	    return;
    
    m = Py_InitModule("_cpyrit_cpu", CPyritCPUMethods);

    Py_INCREF(&CPUDevice_type);
    PyModule_AddObject(m, "CPUDevice", (PyObject*)&CPUDevice_type);
}

