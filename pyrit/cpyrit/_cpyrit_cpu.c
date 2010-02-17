/*
#
#    Copyright 2008-2010, Lukas Lueg, lukas.lueg@gmail.com
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
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "_cpyrit_cpu.h"

typedef struct {
    uint32_t h0[4];
    uint32_t h1[4];
    uint32_t h2[4];
    uint32_t h3[4];
    uint32_t h4[4];
    uint32_t cst[6][4];
} fourwise_sha1_ctx;

struct pmk_ctr
{
    SHA_CTX ctx_ipad;
    SHA_CTX ctx_opad;
    uint32_t e1[5];
    uint32_t e2[5];
};

typedef struct
{
    PyObject_HEAD
    char keyscheme;
    unsigned char *pke;
    unsigned char keymic[16];
    size_t eapolframe_size;
    unsigned char *eapolframe;
} EAPOLCracker;

typedef struct
{
    PyObject_HEAD
} CPUDevice;

typedef struct
{
    PyObject_HEAD
} CowpattyFile;

typedef struct
{
    PyObject_HEAD
    unsigned char *buffer, *current_ptr;
    Py_ssize_t buffersize;
    int current_idx, itemcount;
} CowpattyResult;

static PyObject *PlatformString;
static PyTypeObject CowpattyResult_type;

static void (*prepare_pmk)(const unsigned char *essid_pre, int essidlen, const unsigned char *password, int passwdlen, struct pmk_ctr *ctr) = NULL;
static int (*finalize_pmk)(struct pmk_ctr *ctr) = NULL;
static void (*fourwise_sha1hmac)(unsigned char* message, int message_length, unsigned char* keys, int key_length, unsigned char* hmacs) = NULL;
static unsigned char* (*fourwise_sha1hmac_prepare)(unsigned char* msg, int msg_len) = NULL;

#ifdef COMPILE_SSE2
    extern int detect_sse2(void);
    extern int sse2_sha1_update(uint32_t ctx[4*5+4*6], uint32_t data[4*16], uint32_t wrkbuf[4*80]) __attribute__ ((regparm(3)));
    extern int sse2_sha1_finalize(uint32_t ctx[4*5+4*6], uint32_t digests[4*5]) __attribute__ ((regparm(2)));
#endif

/*
    ###########################################################################
    
    CPUDevice
    
    ###########################################################################
*/

#ifdef COMPILE_PADLOCK
    struct xsha1_ctx {
        unsigned int state[32];
        unsigned char inputbuffer[20+64];
    } __attribute__((aligned(16)));

    #include <sys/ucontext.h>
    #include <signal.h>
    #include <errno.h>
    #include <sys/mman.h>

    // Snippet taken from OpenSSL 0.9.8
    static int
    detect_padlock(void)
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
        MCTX_EIP((ucontext_t*)uctxp) += 4;
    }

    // REP XSHA1 is crashed into the mprotect'ed page so we can
    // steal the state at *EDI before finalizing.
    static int
    padlock_xsha1_prepare(const unsigned char *input, SHA_CTX *output)
    {
        size_t page_size = getpagesize(), buffersize = 2 * page_size, hashed = 0;
        struct sigaction act, oldact;
        unsigned char *cnt, *inputbuffer;
        
        inputbuffer = mmap(0, buffersize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

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
    prepare_pmk_padlock(const unsigned char *essid_pre, int essidlen, const unsigned char *password, int passwdlen, struct pmk_ctr *ctr)
    {
        int i;
        unsigned char pad[64], essid[32+4];

        essidlen = essidlen > 32 ? 32 : essidlen;
        passwdlen = passwdlen > 64 ? 64 : passwdlen;

        memcpy(essid, essid_pre, essidlen);
        memset(essid + essidlen, 0, sizeof(essid) - essidlen);

        memcpy(pad, password, passwdlen);
        memset(pad + passwdlen, 0, sizeof(pad) - passwdlen);
        for (i = 0; i < 16; i++)
            ((unsigned int*)pad)[i] ^= 0x36363636;
        padlock_xsha1_prepare(pad, &ctr->ctx_ipad);
        for (i = 0; i < 16; i++)
            ((unsigned int*)pad)[i] ^= 0x6A6A6A6A;
        padlock_xsha1_prepare(pad, &ctr->ctx_opad);

        essid[essidlen + 4 - 1] = '\1';
        HMAC(EVP_sha1(), password, passwdlen, essid, essidlen + 4, (unsigned char*)ctr->e1, NULL);

        essid[essidlen + 4 - 1] = '\2';
        HMAC(EVP_sha1(), password, passwdlen, essid, essidlen + 4, (unsigned char*)ctr->e2, NULL);
    }

    static int
    finalize_pmk_padlock(struct pmk_ctr *ctr)
    {
        int i, j;
        unsigned int e1_buffer[5], e2_buffer[5];

        memcpy(e1_buffer, ctr->e1, 20);
        memcpy(e2_buffer, ctr->e2, 20);
        for (i = 0; i < 4096-1; i++)
        {
            padlock_xsha1_finalize(&ctr->ctx_ipad, (unsigned char*)e1_buffer);
            padlock_xsha1_finalize(&ctr->ctx_opad, (unsigned char*)e1_buffer);
            for (j = 0; j < 5; j++)
                ctr->e1[j] ^= e1_buffer[j];
            
            padlock_xsha1_finalize(&ctr->ctx_ipad, (unsigned char*)e2_buffer);
            padlock_xsha1_finalize(&ctr->ctx_opad, (unsigned char*)e2_buffer);
            for (j = 0; j < 3; j++)
                ctr->e2[j] ^= e2_buffer[j];
        }
        
        return 1;
    }

#endif // COMPILE_PADLOCK

#ifdef COMPILE_SSE2
    static int
    finalize_pmk_sse2(struct pmk_ctr *ctr)
    {
        int i, j, k;
        uint32_t ctx_ipad[4*5]      __attribute__ ((aligned (16)));
        uint32_t ctx_opad[4*5]      __attribute__ ((aligned (16)));
        uint32_t sha1_ctx[4*5+4*6]  __attribute__ ((aligned (16)));
        uint32_t e1_buffer[4*16]    __attribute__ ((aligned (16)));
        uint32_t e2_buffer[4*16]    __attribute__ ((aligned (16)));
        uint32_t wrkbuf[4*80]       __attribute__ ((aligned (16)));

        memset(e1_buffer, 0, sizeof(e1_buffer));
        memset(e2_buffer, 0, sizeof(e2_buffer));

        for (i = 0; i < 4; i++)
        {
            sha1_ctx[4*5 + 0*4 + i] = 0x5A827999; /* const_stage0 */
            sha1_ctx[4*5 + 1*4 + i] = 0x6ED9EBA1; /* const_stage1 */
            sha1_ctx[4*5 + 2*4 + i] = 0x8F1BBCDC; /* const_stage2 */
            sha1_ctx[4*5 + 3*4 + i] = 0xCA62C1D6; /* const_stage3 */
            sha1_ctx[4*5 + 4*4 + i] = 0xFF00FF00; /* const_ff00   */
            sha1_ctx[4*5 + 5*4 + i] = 0x00FF00FF; /* const_00ff   */
        }

        // Interleave four ipads, opads and first-round-PMKs to local buffers
        for (i = 0; i < 4; i++)
        {
            ctx_ipad[i+ 0] = ctr[i].ctx_ipad.h0;
            ctx_ipad[i+ 4] = ctr[i].ctx_ipad.h1;
            ctx_ipad[i+ 8] = ctr[i].ctx_ipad.h2;
            ctx_ipad[i+12] = ctr[i].ctx_ipad.h3;
            ctx_ipad[i+16] = ctr[i].ctx_ipad.h4;
     
            ctx_opad[i+ 0] = ctr[i].ctx_opad.h0;
            ctx_opad[i+ 4] = ctr[i].ctx_opad.h1;
            ctx_opad[i+ 8] = ctr[i].ctx_opad.h2;
            ctx_opad[i+12] = ctr[i].ctx_opad.h3;
            ctx_opad[i+16] = ctr[i].ctx_opad.h4;

            e1_buffer[20+i] = e2_buffer[20+i] = 0x80; // Terminator bit
            e1_buffer[60+i] = e2_buffer[60+i] = 0xA0020000; // size = (64+20)*8
            for (j = 0; j < 5; j++)
            {
                e1_buffer[j*4 + i] = ctr[i].e1[j];
                e2_buffer[j*4 + i] = ctr[i].e2[j];
            }
        }
        
        // Process through SSE2 and de-interleave back to ctr
        for (i = 0; i < 4096-1; i++)
        {
            memcpy(sha1_ctx, ctx_ipad, 4 * 5 * sizeof(uint32_t));
            sse2_sha1_update(sha1_ctx, e1_buffer, wrkbuf);
            sse2_sha1_finalize(sha1_ctx, e1_buffer);
            
            memcpy(sha1_ctx, ctx_opad, 4 * 5 * sizeof(uint32_t));
            sse2_sha1_update(sha1_ctx, e1_buffer, wrkbuf);
            sse2_sha1_finalize(sha1_ctx, e1_buffer);

            memcpy(sha1_ctx, ctx_ipad, 4 * 5 * sizeof(uint32_t));
            sse2_sha1_update(sha1_ctx, e2_buffer, wrkbuf);
            sse2_sha1_finalize(sha1_ctx, e2_buffer);
            
            memcpy(sha1_ctx, ctx_opad, 4 * 5 * sizeof(uint32_t));
            sse2_sha1_update(sha1_ctx, e2_buffer, wrkbuf);
            sse2_sha1_finalize(sha1_ctx, e2_buffer);
            
            for (j = 0; j < 4; j++)
            {
                for (k = 0; k < 5; k++)
                {
                    ctr[j].e1[k] ^= e1_buffer[k*4 + j];
                    ctr[j].e2[k] ^= e2_buffer[k*4 + j];
                }
            }
        }

        return 4;
    }
#endif // COMPILE_SSE2

static void
prepare_pmk_openssl(const unsigned char *essid_pre, int essidlen, const unsigned char *password, int passwdlen, struct pmk_ctr *ctr)
{
    int i;
    unsigned char pad[64], essid[32+4];

    essidlen = essidlen > 32 ? 32 : essidlen;
    passwdlen = passwdlen > 64 ? 64 : passwdlen;

    memcpy(essid, essid_pre, essidlen);
    memset(essid + essidlen, 0, sizeof(essid) - essidlen);
    
    memcpy(pad, password, passwdlen);
    memset(pad + passwdlen, 0, sizeof(pad) - passwdlen);
    for( i = 0; i < 16; i++ )
	    ((unsigned int*)pad)[i] ^= 0x36363636;
    SHA1_Init(&ctr->ctx_ipad);
    SHA1_Update(&ctr->ctx_ipad, pad, 64);
    for( i = 0; i < 16; i++ )
	    ((unsigned int*)pad)[i] ^= 0x6A6A6A6A;
    SHA1_Init(&ctr->ctx_opad);
    SHA1_Update(&ctr->ctx_opad, pad, 64);

    essid[essidlen + 4 - 1] = '\1';
    HMAC(EVP_sha1(), password, passwdlen, essid, essidlen + 4, (unsigned char*)ctr->e1, NULL);
    
    essid[essidlen + 4 - 1] = '\2';
    HMAC(EVP_sha1(), password, passwdlen, essid, essidlen + 4, (unsigned char*)ctr->e2, NULL);
}

static int
finalize_pmk_openssl(struct pmk_ctr *ctr)
{
    int i, j;
    SHA_CTX ctx;
    unsigned int e1_buffer[5], e2_buffer[5];

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

        for (j = 0; j < 5; j++)
            ctr->e1[j] ^= e1_buffer[j];
        
        memcpy(&ctx, &ctr->ctx_ipad, sizeof(ctx));
        SHA1_Update(&ctx, (unsigned char*)e2_buffer, 20);
        SHA1_Final((unsigned char*)e2_buffer, &ctx);
        
        memcpy(&ctx, &ctr->ctx_opad, sizeof(ctx));
        SHA1_Update(&ctx, (unsigned char*)e2_buffer, 20);
        SHA1_Final((unsigned char*)e2_buffer, &ctx);

        for (j = 0; j < 3; j++)
            ctr->e2[j] ^= e2_buffer[j]; 
    }
    
    return 1;
}

PyDoc_STRVAR(CPUDevice_solve__doc__, 
    "solve(essid, passwords) -> tuple\n\n"
    "Calculate PMKs from ESSID and iterable of strings.");

static PyObject *
CPUDevice_solve(PyObject *self, PyObject *args)
{
    unsigned char *essid, *passwd;
    PyObject *passwd_seq, *passwd_obj, *essid_obj, *result;
    int i, arraysize, essidlen, passwdlen;
    struct pmk_ctr *pmk_buffer, *t;

    if (!PyArg_ParseTuple(args, "OO", &essid_obj, &passwd_seq)) return NULL;
    passwd_seq = PyObject_GetIter(passwd_seq);
    if (!passwd_seq) return NULL;
    
    essid = (unsigned char*)PyString_AsString(essid_obj);
    essidlen = PyString_Size(essid_obj);
    if (essid == NULL || essidlen < 1 || essidlen > 32)
    {
        Py_DECREF(passwd_seq);
        PyErr_SetString(PyExc_ValueError, "ESSID must be a string between 1 and 32 bytes.");
        return NULL;
    }
    
    arraysize = 0;
    pmk_buffer = NULL;
    while ((passwd_obj=PyIter_Next(passwd_seq)))
    {
        if (arraysize % 100 == 0)
        {
            // Step-size must be aligned to four entries so finalize_pmk_sse2 has air to breath
            t = PyMem_Realloc(pmk_buffer, sizeof(struct pmk_ctr) * (arraysize+100));
            if (!t)
            {
                Py_DECREF(passwd_obj);
                Py_DECREF(passwd_seq);
                PyMem_Free(pmk_buffer);
                PyErr_NoMemory();
                return NULL;
            }
            pmk_buffer = t;
        }
        passwd = (unsigned char*)PyString_AsString(passwd_obj);
        passwdlen = PyString_Size(passwd_obj);
        if (passwd == NULL || passwdlen < 8 || passwdlen > 63)
        {
            Py_DECREF(passwd_obj);
            Py_DECREF(passwd_seq);
            PyMem_Free(pmk_buffer);
            PyErr_SetString(PyExc_ValueError, "All passwords must be strings between 8 and 63 characters");
            return NULL;
        }
        prepare_pmk(essid, essidlen, passwd, passwdlen, &pmk_buffer[arraysize]);
        Py_DECREF(passwd_obj);
        arraysize++;
    }
    Py_DECREF(passwd_seq);
    
    if (arraysize > 0)
    {
        Py_BEGIN_ALLOW_THREADS;
        i = 0;
        do
            i += finalize_pmk(&pmk_buffer[i]);
        while (i < arraysize);
        Py_END_ALLOW_THREADS;

        result = PyTuple_New(arraysize);
        for (i = 0; i < arraysize; i++)
            PyTuple_SetItem(result, i, Py_BuildValue("s#", pmk_buffer[i].e1, 32));
    } else {
        result = PyTuple_New(0);
    }

    PyMem_Free(pmk_buffer);

    return result;
}


/*
    ###########################################################################
    
    EAPOLCracker
    
    ###########################################################################
*/

#ifdef COMPILE_SSE2
    static unsigned char*
    fourwise_sha1hmac_prepare_sse2(unsigned char* msg, int msg_len)
    {
        int buffer_len, i, j, k;
        unsigned char *retval, *buffer, *prepared_msg;
                
        /* Align length to 56 bytes for for message, 1 for terminator, 8 for size */
        buffer_len = msg_len + (64 - ((msg_len + 1 + 8) % 64)) + 1 + 8;
        buffer = PyMem_Malloc(buffer_len);
        if (!buffer)
            return NULL;
        
        /* Terminate msg, total length = 64 bytes for IPAD + sizeof(msg) in bits */
        memset(buffer, 0, buffer_len);
        memcpy(buffer, msg, msg_len);
        buffer[msg_len] = 0x80;
        PUT_BE((64 + msg_len) * 8, buffer, buffer_len - 4);
        
        retval = PyMem_Malloc(buffer_len * 4 + 16);
        if (!retval)
        {
            PyMem_Free(buffer);
            return NULL;
        }        
        
        /* Interleave buffer four times for SSE2-processing */
        prepared_msg = retval + 16 - ((long)retval % 16);
        for (i = 0; i < buffer_len / 64; i++)
            for (j = 0; j < 16; j++)
                for (k = 0; k < 4; k++)
                    ((uint32_t*)prepared_msg)[(i * 64) + (j * 4) + k] = ((uint32_t*)buffer)[(i * 16) + j];
                
        PyMem_Free(buffer);
        return retval;
    
    }

    static inline void
    fourwise_sha1_init(fourwise_sha1_ctx* ctx)
    {
        int i;
        
        for (i = 0; i < 4; i++)
        {
            ctx->h0[i] = 0x67452301;      /* magic start value */
            ctx->h1[i] = 0xEFCDAB89;      /* magic start value */
            ctx->h2[i] = 0x98BADCFE;      /* magic start value */
            ctx->h3[i] = 0x10325476;      /* magic start value */
            ctx->h4[i] = 0xC3D2E1F0;      /* magic start value */
            ctx->cst[0][i] = 0x5A827999;  /* const_stage0 */
            ctx->cst[1][i] = 0x6ED9EBA1;  /* const_stage1 */
            ctx->cst[2][i] = 0x8F1BBCDC;  /* const_stage2 */
            ctx->cst[3][i] = 0xCA62C1D6;  /* const_stage3 */
            ctx->cst[4][i] = 0xFF00FF00;  /* const_ff00   */
            ctx->cst[5][i] = 0x00FF00FF;  /* const_00ff   */
        }
    }

    static void
    fourwise_sha1hmac_sse2(unsigned char* prepared_msg, int message_length, unsigned char* keys, int key_length, unsigned char* hmacs) 
    {
        int i, j;
        uint32_t buffer[16];
        uint32_t wrkbuf[4*80]        __attribute__ ((aligned (16)));
        uint32_t blockbuffer[16][4]  __attribute__ ((aligned (16)));
        uint32_t digests[4][5];
        fourwise_sha1_ctx ctx;
        
        key_length = key_length <= 64 ? key_length : 64;
        prepared_msg = prepared_msg + 16 - ((long)prepared_msg % 16);
        message_length = message_length + (64 - ((message_length + 1 + 8) % 64)) + 1 + 8;
        
        /* Step 1: Inner hash = IPAD ^ K // message */
        fourwise_sha1_init(&ctx);
        
        /* Process IPAD ^ K */
        for (i = 0; i < 4; i++)
        {
            memcpy(&buffer, &keys[key_length * i], key_length);
            memset(&((unsigned char*)buffer)[key_length], 0, sizeof(buffer) - key_length);
            for (j = 0; j < 16; j++)
                blockbuffer[j][i] = buffer[j] ^ 0x36363636;
        }
        sse2_sha1_update((uint32_t*)&ctx, (uint32_t*)blockbuffer, wrkbuf);
        
        for (i = 0; i < message_length / 64; i++)
            sse2_sha1_update((uint32_t*)&ctx, (uint32_t*)(prepared_msg + 64 * 4 * i), wrkbuf);

        /* First hash done */
        sse2_sha1_finalize((uint32_t*)&ctx, (uint32_t*)&blockbuffer);
        for (i = 0; i < 4; i++)
            for (j = 0; j < 5; j++)
                digests[i][j] = blockbuffer[j][i];
        
        /* Step 2: Outer hash = OPAD ^ K // inner hash */
        fourwise_sha1_init(&ctx);
        for (i = 0; i < 4; i++)
        {
            memcpy(&buffer, &keys[key_length * i], key_length);
            memset(&((unsigned char*)buffer)[key_length], 0, sizeof(buffer) - key_length);
            for (j = 0; j < 16; j++)
                blockbuffer[j][i] = buffer[j] ^ 0x5C5C5C5C;
        }
        sse2_sha1_update((uint32_t*)&ctx, (uint32_t*)blockbuffer, wrkbuf);

        memset(blockbuffer, 0, sizeof(blockbuffer));
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 5; j++)
                blockbuffer[j][i] = digests[i][j];
            blockbuffer[ 5][i] = 0x80;       /* Terminator bit */
            blockbuffer[15][i] = 0xA0020000; /* size = (64 + 20) * 8 */
        }
        sse2_sha1_update((uint32_t*)&ctx, (uint32_t*)blockbuffer, wrkbuf);

        /* Second hash == HMAC */
        sse2_sha1_finalize((uint32_t*)&ctx, (uint32_t*)&blockbuffer);
        for (i = 0; i < 4; i++)
            for (j = 0; j < 5; j++)
                ((uint32_t*)hmacs)[i * 5 + j] = blockbuffer[j][i];

    }
    
#endif // COMPILE_SSE2

static unsigned char*
fourwise_sha1hmac_prepare_openssl(unsigned char* msg, int msg_len)
{
    unsigned char* prep_msg;
    
    prep_msg = PyMem_Malloc(msg_len);
    if (!prep_msg)
        return NULL;
    
    memcpy(prep_msg, msg, msg_len);
    
    return prep_msg;
}

static void
fourwise_sha1hmac_openssl(unsigned char* message, int message_length, unsigned char* keys, int key_length, unsigned char* hmacs) 
{
    int i;
    
    for (i = 0; i < 4; i++)
        HMAC(EVP_sha1(), &keys[i * key_length], key_length, message, message_length, &hmacs[i * 20], NULL);
}

static int
EAPOLCracker_init(EAPOLCracker *self, PyObject *args, PyObject *kwds)
{
    char *keyscheme;
    unsigned char *pke, *keymic, *eapolframe;
    int pke_len, keymic_size, eapolframe_size;

    self->eapolframe = self->pke = NULL;
    if (!PyArg_ParseTuple(args, "ss#s#s#", &keyscheme, &pke, &pke_len, &keymic, &keymic_size, &eapolframe, &eapolframe_size))
        return -1;

    if (pke_len != 100)
    {
        PyErr_SetString(PyExc_ValueError, "PKE must be a string of exactly 100 bytes.");
        return -1;
    }
    self->pke = fourwise_sha1hmac_prepare(pke, 100);
    if (!self->pke)
    {
        PyErr_NoMemory();
        return -1;
    }
    
    if (keymic_size != 16)
    {
        PyErr_SetString(PyExc_ValueError, "KeyMIC must a string of 16 bytes.");
        return -1;
    }
    memcpy(self->keymic, keymic, 16);
    
    self->eapolframe_size = eapolframe_size;
    
    if (strcmp(keyscheme, "HMAC_MD5_RC4") == 0)
    {
        self->keyscheme = HMAC_MD5_RC4;
        self->eapolframe = PyMem_Malloc(eapolframe_size);
        if (!self->eapolframe)
        {
            PyErr_NoMemory();
            return -1;
        }
        memcpy(self->eapolframe, eapolframe, eapolframe_size);
    } else if (strcmp(keyscheme, "HMAC_SHA1_AES") == 0) {
        self->keyscheme = HMAC_SHA1_AES;
        self->eapolframe = fourwise_sha1hmac_prepare(eapolframe, eapolframe_size);
        if (!self->eapolframe)
        {
            PyErr_NoMemory();
            return -1;
        }
    } else {
        PyErr_SetString(PyExc_ValueError, "Invalid key-scheme.");
        return -1;
    }

    return 0;

}

static void
EAPOLCracker_dealloc(EAPOLCracker *self)
{
    if (self->pke)
        PyMem_Free(self->pke);
    if (self->eapolframe)
        PyMem_Free(self->eapolframe);
    self->ob_type->tp_free((PyObject*)self);
}

static int
EAPOLCracker_unpack(PyObject* result_seq, unsigned char **pmkbuffer_ptr)
{
    unsigned char *pmkbuffer, *t;
    int buffersize, itemcount;
    PyObject *result_iter, *result_obj, *pmk_obj;

    pmkbuffer = pmkbuffer_ptr[0] = NULL;
    buffersize = itemcount = 0;
    
    result_iter = PyObject_GetIter(result_seq);
    if (!result_iter)
    {
        PyErr_SetString(PyExc_ValueError, "Parameter must be a iterable of (password, PMK)-sequences.");
        return -1;
    }
    
    while ((result_obj = PyIter_Next(result_iter)))
    {
        if (buffersize <= itemcount)
        {
            /* Step-size must be aligned to four entries (SSE2-path) */
            buffersize += 50000;
            t = PyMem_Realloc(pmkbuffer, buffersize*32);
            if (!t)
            {
                PyErr_NoMemory();
                Py_DECREF(result_obj);
                goto out;
            }
            pmkbuffer = t;
        }

        pmk_obj = PySequence_GetItem(result_obj, 1);
        if (!pmk_obj)
        {
            PyErr_SetString(PyExc_ValueError, "Expected Pairwise Master Key as second item in a sequence-object.");
            Py_DECREF(result_obj);
            PyMem_Free(pmkbuffer);
            goto out;
        }
        t = (unsigned char*)PyString_AsString(pmk_obj);
        if (t == NULL || PyString_Size(pmk_obj) != 32)
        {
            PyErr_SetString(PyExc_ValueError, "All PMKs must be strings of 32 characters");
            Py_DECREF(result_obj);
            Py_DECREF(pmk_obj);
            PyMem_Free(pmkbuffer);
            goto out;
        }
        memcpy(pmkbuffer + itemcount*32, t, 32);
        itemcount += 1;
        Py_DECREF(pmk_obj);
        Py_DECREF(result_obj);
    }
    
    pmkbuffer_ptr[0] = pmkbuffer;

    out:
    Py_DECREF(result_iter);

    return itemcount * 32;
}


PyDoc_STRVAR(EAPOLCracker_solve__doc__, 
    "solve(object) -> solution or None\n\n"
    "Try to find the password that corresponds to this instance's EAPOL-session.\n");

static PyObject*
EAPOLCracker_solve(EAPOLCracker *self, PyObject *args)
{
    PyObject *result_seq, *pmkbuffer_obj, *solution_obj;
    unsigned char *pmkbuffer, *t, mics[4][20], eapol_mic_keys[4][16];
    Py_ssize_t buffersize;
    int i, j, solution_idx;
    PyBufferProcs *pb;

    pmkbuffer = NULL;

    if (!PyArg_ParseTuple(args, "O", &result_seq))
        return NULL;

    /* Try to get the PMKs through the object's buffer-protocol (faster) */
    if (PyObject_HasAttrString(result_seq, "getpmkbuffer"))
    {
        pmkbuffer_obj = PyObject_CallMethod(result_seq, "getpmkbuffer", NULL);
        if (pmkbuffer_obj)
        {
            if (!PyBuffer_Check(pmkbuffer_obj))
            {
                PyErr_SetString(PyExc_ValueError, "The object's .getpmkbuffer() must provide a buffer-object.");
                Py_DECREF(pmkbuffer_obj);
                return NULL;
            } else {
                pb = pmkbuffer_obj->ob_type->tp_as_buffer;
                buffersize = (*pb->bf_getreadbuffer)(pmkbuffer_obj, 0, (void**)&t);
                if (buffersize % 32 != 0)
                {
                    PyErr_SetString(PyExc_ValueError, "Object's buffer's length is not a multiple of 32.");
                    Py_DECREF(pmkbuffer_obj);
                    return NULL;
                }
                /* Align size to 4*32 for SSE2 */
                pmkbuffer = PyMem_Malloc(buffersize + 128 - (buffersize % 128));
                if (!pmkbuffer)
                {
                    PyErr_NoMemory();
                    Py_DECREF(pmkbuffer_obj);
                    return NULL;
                }
                memcpy(pmkbuffer, t, buffersize);
                Py_DECREF(pmkbuffer_obj);
            }
        } else {
            /* Pass the error from getpmkbuffer() */
            return NULL;
        }
    } else {
        /* Basic sequence-like objects must be unpacked */
        buffersize = EAPOLCracker_unpack(result_seq, &pmkbuffer);
        if (!pmkbuffer)
            return NULL;
    }

    solution_idx = -1;
    Py_BEGIN_ALLOW_THREADS;
    for (i = 0; i < buffersize / 32 && solution_idx == -1; i += 4)
    {
        fourwise_sha1hmac(self->pke, 100, &pmkbuffer[i*32], 32, (unsigned char*)&mics);
        for (j = 0; j < 4; j++)
            memcpy(eapol_mic_keys[j], mics[j], 16);
        if (self->keyscheme == HMAC_MD5_RC4)
            for (j = 0; j < 4; j++)
                HMAC(EVP_md5(), eapol_mic_keys[j], 16, self->eapolframe, self->eapolframe_size, mics[j], NULL);
        else
            fourwise_sha1hmac(self->eapolframe, self->eapolframe_size, (unsigned char*)&eapol_mic_keys, 16, (unsigned char*)&mics);
        for (j = 0; j < 4; j++)
            if (memcmp(&mics[j], self->keymic, 16) == 0)
                solution_idx = i + j;
    }
    Py_END_ALLOW_THREADS;

    PyMem_Free(pmkbuffer);

    if (solution_idx == -1)
    {
        solution_obj = Py_None;
        Py_INCREF(solution_obj);
    } else {
        solution_obj = PySequence_GetItem(result_seq, solution_idx);
    }
    
    return solution_obj;
}


/*
    ###########################################################################
    
    CowpattyResult
    
    ###########################################################################
*/

static void
CowpattyResult_dealloc(CowpattyResult* self)
{
    if (self->buffer)
        PyMem_Free(self->buffer);
    self->ob_type->tp_free((PyObject*)self);
}

static Py_ssize_t
CowpattyResult_bf_getreadbuffer(CowpattyResult* self, Py_ssize_t segment, void **ptrptr)
{
    if (segment != 0)
    {
        PyErr_SetString(PyExc_SystemError, "Invalid segment to CowpattyResult-buffer.");
        return -1;
    }
    ptrptr[0] = self->buffer;
    return self->itemcount * 32;
}

static Py_ssize_t
CowpattyResult_bf_getsegcount(CowpattyResult* self, Py_ssize_t *lenp)
{
    if (lenp)
        lenp[0] = self->itemcount * 32;
    return 1;
}

static Py_ssize_t
CowpattyResult_sq_length(CowpattyResult* self)
{
    return self->itemcount;
}

static PyObject*
CowpattyResult_sq_item(CowpattyResult* self, Py_ssize_t idx)
{
    PyObject *result;
    int entrylen, i, consumed;
    
    if (idx < 0 || idx > self->itemcount - 1)
    {
        PyErr_SetString(PyExc_IndexError, "Index out of bounds for CowpattyResult.");
        return NULL;
    }
    
    consumed = 0;
    for (i = 0; i < idx; i++)
        consumed += (int)self->buffer[self->itemcount * 32 + consumed];

    result = PyTuple_New(2);
    if (!result)
    {
        PyErr_NoMemory();
        return NULL;
    }
    
    entrylen = (int)self->buffer[self->itemcount * 32 + consumed];
    PyTuple_SetItem(result, 0, PyString_FromStringAndSize((char*)&self->buffer[self->itemcount * 32 + consumed + 1], entrylen - 1));
    PyTuple_SetItem(result, 1, PyString_FromStringAndSize((char*)&self->buffer[idx * 32], 32));

    return result;
}

static PyObject*
CowpattyResult_iter(CowpattyResult* self)
{
    Py_INCREF(self);
    return (PyObject*)self;
}

static PyObject*
CowpattyResult_iternext(CowpattyResult *self)
{
    PyObject *result;
    int entrylen;

    if (self->current_idx >= self->itemcount)
        return NULL;

    result = PyTuple_New(2);
    if (!result)
    {
        PyErr_NoMemory();
        return NULL;
    }
    
    entrylen = (int)self->current_ptr[0];
    PyTuple_SetItem(result, 0, PyString_FromStringAndSize((char*)self->current_ptr + 1, entrylen - 1));
    PyTuple_SetItem(result, 1, PyString_FromStringAndSize((char*)self->buffer + self->current_idx * 32, 32));
    
    self->current_ptr += entrylen;
    self->current_idx += 1;
    
    return result;
}

PyDoc_STRVAR(CowpattyResult_getpmkbuffer__doc__, 
    "getpmkbuffer() -> buffer-object\n\n"
    "Return a buffer-object to directly access the PMKs held by this object.");

static PyObject*
CowpattyResult_getpmkbuffer(PyObject *self, PyObject *args)
{
    return PyBuffer_FromObject(self, 0, Py_END_OF_BUFFER);
}

/*
    ###########################################################################
    
    CowpattyFile
    
    ###########################################################################
*/

PyDoc_STRVAR(CowpattyFile_gencowpentries__doc__, 
    "gencowpentries(iterable) -> string\n\n"
    "Generate a data-string in cowpatty-like format from a iterable of (password-PMK)-tuples.");

static PyObject *
CowpattyFile_gencowpentries(PyObject *self, PyObject *args)
{
    PyObject *result_seq, *result_obj, *passwd_obj, *pmk_obj, *result;
    char *passwd, *pmk;
    unsigned char *cowpbuffer, *t;
    unsigned int passwd_length, buffer_offset, buffersize;

    if (!PyArg_ParseTuple(args, "O", &result_seq))
        return NULL;

    result_seq = PyObject_GetIter(result_seq);
    if (!result_seq)
    {
        PyErr_NoMemory();
        return NULL;
    }
    
    cowpbuffer = NULL;
    passwd_obj = pmk_obj = NULL;
    buffer_offset = buffersize = 0;
    while ((result_obj = PyIter_Next(result_seq)))
    {
        if (buffersize - buffer_offset < 1+63+32)
        {
            buffersize += 1024*10;
            t = PyMem_Realloc(cowpbuffer, buffersize);
            if (!t)
            {
                PyErr_NoMemory();
                goto errout;
            }
            cowpbuffer = t;
        }
        passwd_obj = PySequence_GetItem(result_obj, 0);
        if (!passwd_obj)
        {
            PyErr_NoMemory();
            goto errout;
        }
        passwd = PyString_AsString(passwd_obj);
        passwd_length = PyString_Size(passwd_obj);
        if (passwd == NULL || passwd_length < 8 || passwd_length > 63)
        {
            PyErr_SetString(PyExc_ValueError, "All passwords must be strings between 8 and 63 characters");
            Py_DECREF(passwd_obj);
            goto errout;
        }
        pmk_obj = PySequence_GetItem(result_obj, 1);
        if (!pmk_obj)
        {
            PyErr_NoMemory();
            Py_DECREF(passwd_obj);
            goto errout;
        }
        pmk = PyString_AsString(pmk_obj);
        if (pmk == NULL || PyString_Size(pmk_obj) != 32)
        {
            PyErr_SetString(PyExc_ValueError, "All PMKs must be strings of 32 characters");
            Py_DECREF(passwd_obj);
            Py_DECREF(pmk_obj);
            goto errout;
        }
        
        cowpbuffer[buffer_offset + 0] = passwd_length + 32 + 1;
        memcpy(&cowpbuffer[buffer_offset + 1], passwd, passwd_length);
        memcpy(&cowpbuffer[buffer_offset + 1 + passwd_length], pmk, 32);
        
        Py_DECREF(passwd_obj);
        Py_DECREF(pmk_obj);
        Py_DECREF(result_obj);
        
        buffer_offset += passwd_length + 32 + 1;
    }
    Py_DECREF(result_seq);
    
    result = PyString_FromStringAndSize((char*)cowpbuffer, buffer_offset);

    PyMem_Free(cowpbuffer);

    return result;
    
    errout:
    Py_DECREF(result_obj);
    Py_DECREF(result_seq);
    PyMem_Free(cowpbuffer);
    return NULL;
}

PyDoc_STRVAR(CowpattyFile_unpackcowpentries__doc__, 
    "unpackcowpentries(string) -> (CowpattyResult, string)\n\n"
    "Unpack a data-string in cowpatty-like format and return a tuple with results and unfinished tail.");

static PyObject *
CowpattyFile_unpackcowpentries(PyObject *self, PyObject *args)
{
    CowpattyResult *iter;
    PyObject *result;
    int i, stringsize, consumed, entrylen, itemcount;
    char *string;

    if (!PyArg_ParseTuple(args, "s#", &string, &stringsize))
        return NULL;
        
    if (stringsize < 1+8+32 || string[0] > stringsize)
    {
        PyErr_SetString(PyExc_ValueError, "Input-string is too short.");
        return NULL;
    }

    itemcount = consumed = 0;
    do
    {
        entrylen = (int)string[consumed];
        if (entrylen < 1+8+32 || entrylen > 1+63+32)
        {
            PyErr_Format(PyExc_ValueError, "Entry of invalid size: %i", entrylen);
            return NULL;
        }
        if (consumed + entrylen > stringsize)
            break;
        consumed += entrylen;
        itemcount += 1;
    } while (consumed < stringsize);

    iter = (CowpattyResult*)PyObject_New(CowpattyResult, &CowpattyResult_type);
    if (!iter)
    {
        PyErr_NoMemory();
        return NULL;
    }
    iter->buffersize = consumed;
    iter->current_idx = 0;
    iter->itemcount = itemcount;
    
    iter->buffer = PyMem_Malloc(consumed);
    if (!iter->buffer)
    {
        Py_DECREF(iter);
        PyErr_NoMemory();
        return NULL;
    }
    iter->current_ptr = iter->buffer + (itemcount * 32);

    consumed = 0;
    for (i = 0; i < itemcount; i++)
    {
        entrylen = (int)string[consumed];
        memcpy(&iter->buffer[32 * i], &string[consumed + entrylen - 32], 32);
        iter->buffer[32 * itemcount + consumed - (32 * i)] = entrylen - 32;
        memcpy(&iter->buffer[32 * itemcount + consumed - (32 * i) + 1], &string[consumed + 1], entrylen - (32 + 1));
        consumed += entrylen;
    }
    
    result = PyTuple_New(2);
    if (!result)
    {
        PyErr_NoMemory();
        Py_DECREF(iter);
        return NULL;
    }
    PyTuple_SetItem(result, 0, (PyObject*)iter);
    PyTuple_SetItem(result, 1, PyString_FromStringAndSize(string + consumed, stringsize - consumed));
    
    return result;
}


/*
    ###########################################################################
    
    Module functions
    
    ###########################################################################
*/

PyDoc_STRVAR(cpyrit_getPlatform__doc__, 
    "getPlatform() -> string\n\n"
    "Determine CPU-type");

static PyObject *
cpyrit_getPlatform(PyObject *self, PyObject *args)
{
    Py_INCREF(PlatformString);
    return PlatformString;
}

PyDoc_STRVAR(cpyrit_grouper__doc__, 
    "grouper(string, groupsize) -> tuple\n\n"
    "Group a large string into a tuple of strings of equal size each");

static PyObject *
cpyrit_grouper(PyObject *self, PyObject *args)
{
    PyObject *result;
    int i, stringsize, groupsize;
    char *string;
    
    if (!PyArg_ParseTuple(args, "s#i", &string, &stringsize, &groupsize))
        return NULL;

    if (stringsize % groupsize != 0)
    {
        PyErr_SetString(PyExc_ValueError, "Invalid size of input string.");
        return NULL;
    }
    
    result = PyTuple_New(stringsize / groupsize);
    if (!result)
    {
        PyErr_NoMemory();
        return NULL;
    }
    for (i = 0; i < stringsize / groupsize; i++)
        PyTuple_SetItem(result, i, PyString_FromStringAndSize(&string[i * groupsize], groupsize));

    return result;
}


/*
    ###########################################################################
    
    Class definitions
    
    ###########################################################################
*/


static PyMethodDef CPUDevice_methods[] =
{
    {"solve", (PyCFunction)CPUDevice_solve, METH_VARARGS, CPUDevice_solve__doc__},
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

static PyMethodDef EAPOLCracker_methods[] =
{
    {"solve", (PyCFunction)EAPOLCracker_solve, METH_VARARGS, EAPOLCracker_solve__doc__},
    {NULL, NULL}
};

static PyTypeObject EAPOLCracker_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_cpu.EAPOLCracker",  /*tp_name*/
    sizeof(EAPOLCracker),       /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)EAPOLCracker_dealloc,   /*tp_dealloc*/
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
    EAPOLCracker_methods,       /*tp_methods*/
    0,                          /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)EAPOLCracker_init,/*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};

static PyMethodDef CowpattyResult_methods[] =
{
    {"getpmkbuffer", CowpattyResult_getpmkbuffer, METH_NOARGS, CowpattyResult_getpmkbuffer__doc__},
    {NULL, NULL}
};

static PyBufferProcs CowpattyResults_buffer_procs = {
    (readbufferproc)CowpattyResult_bf_getreadbuffer, /* bf_getreadbuffer */
    0,                                               /* bf_getwritebuffer */
    (segcountproc)CowpattyResult_bf_getsegcount,     /* bf_getsegcount */
    0                                                /* bf_getcharbuffer */
};

static PySequenceMethods CowpattyResult_seq_methods = {
    (lenfunc)CowpattyResult_sq_length,    /* sq_length */
    0,                                    /* sq_concat */
    0,                                    /* sq_repeat */
    (ssizeargfunc)CowpattyResult_sq_item, /* sq_item */
    0,                                    /* sq_ass_item */
    0,                                    /* sq_contains */
    0,                                    /* sq_inplace_concat */
    0                                     /* sq_inplace_repeat */
};

static PyTypeObject CowpattyResult_type = {
    PyObject_HEAD_INIT(NULL)
    0,                            /*ob_size*/
    "_cpyrit_cpu.CowpattyResult", /*tp_name*/
    sizeof(CowpattyResult),       /*tp_basicsize*/
    0,                            /*tp_itemsize*/
    (destructor)CowpattyResult_dealloc, /*tp_dealloc*/
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
    (getiterfunc)CowpattyResult_iter,      /*tp_iter*/
    (iternextfunc)CowpattyResult_iternext, /*tp_iternext*/
    CowpattyResult_methods,     /*tp_methods*/
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

static PyMethodDef CowpattyFile_methods[] =
{
    {"genCowpEntries", CowpattyFile_gencowpentries, METH_VARARGS, CowpattyFile_gencowpentries__doc__},
    {"unpackCowpEntries", CowpattyFile_unpackcowpentries, METH_VARARGS, CowpattyFile_unpackcowpentries__doc__},
    {NULL, NULL}
};

static PyTypeObject CowpattyFile_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_cpu.CowpattyFile", /*tp_name*/
    sizeof(CowpattyFile),       /*tp_basicsize*/
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
    CowpattyFile_methods,       /*tp_methods*/
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
    {"getPlatform", cpyrit_getPlatform, METH_NOARGS, cpyrit_getPlatform__doc__},
    {"grouper", cpyrit_grouper, METH_VARARGS, cpyrit_grouper__doc__},
    {NULL, NULL, 0, NULL}
};

static void pathconfig(void)
{
    #ifdef COMPILE_PADLOCK
        if (detect_padlock())
        {
            PlatformString = PyString_FromString("VIA Padlock");
            prepare_pmk = prepare_pmk_padlock;
            finalize_pmk = finalize_pmk_padlock;
            fourwise_sha1hmac_prepare = fourwise_sha1hmac_prepare_sse2;
            fourwise_sha1hmac = fourwise_sha1hmac_sse2;
            return;
        }
    #endif
    #ifdef COMPILE_SSE2
        if (detect_sse2())
        {
            PlatformString = PyString_FromString("SSE2");
            prepare_pmk = prepare_pmk_openssl;
            finalize_pmk = finalize_pmk_sse2;
            fourwise_sha1hmac_prepare = fourwise_sha1hmac_prepare_sse2;
            fourwise_sha1hmac = fourwise_sha1hmac_sse2;
            return;
        }
    #endif 

    PlatformString = PyString_FromString("x86");
    prepare_pmk = prepare_pmk_openssl;
    finalize_pmk = finalize_pmk_openssl;
    fourwise_sha1hmac_prepare = fourwise_sha1hmac_prepare_openssl;
    fourwise_sha1hmac = fourwise_sha1hmac_openssl;
}


/*
    ###########################################################################
    
    Module initialization
    
    ###########################################################################
*/

PyMODINIT_FUNC
init_cpyrit_cpu(void)
{
    PyObject *m;

    pathconfig();

    CPUDevice_type.tp_getattro = PyObject_GenericGetAttr;
    CPUDevice_type.tp_setattro = PyObject_GenericSetAttr;
    CPUDevice_type.tp_alloc  = PyType_GenericAlloc;
    CPUDevice_type.tp_new = PyType_GenericNew;
    CPUDevice_type.tp_free = _PyObject_Del;
    if (PyType_Ready(&CPUDevice_type) < 0)
	    return;

    EAPOLCracker_type.tp_getattro = PyObject_GenericGetAttr;
    EAPOLCracker_type.tp_setattro = PyObject_GenericSetAttr;
    EAPOLCracker_type.tp_alloc  = PyType_GenericAlloc;
    EAPOLCracker_type.tp_new = PyType_GenericNew;
    EAPOLCracker_type.tp_free = _PyObject_Del;
    if (PyType_Ready(&EAPOLCracker_type) < 0)
	    return;

    CowpattyFile_type.tp_getattro = PyObject_GenericGetAttr;
    CowpattyFile_type.tp_setattro = PyObject_GenericSetAttr;
    CowpattyFile_type.tp_alloc  = PyType_GenericAlloc;
    CowpattyFile_type.tp_new = PyType_GenericNew;
    CowpattyFile_type.tp_free = _PyObject_Del;
    if (PyType_Ready(&CowpattyFile_type) < 0)
	    return;
    
    CowpattyResult_type.tp_getattro = PyObject_GenericGetAttr;
    CowpattyResult_type.tp_setattro = PyObject_GenericSetAttr;
    CowpattyResult_type.tp_alloc  = PyType_GenericAlloc;
    CowpattyResult_type.tp_new = PyType_GenericNew;
    CowpattyResult_type.tp_free = _PyObject_Del;
    CowpattyResult_type.tp_as_sequence = &CowpattyResult_seq_methods;
    CowpattyResult_type.tp_as_buffer = &CowpattyResults_buffer_procs;
    if (PyType_Ready(&CowpattyResult_type) < 0)
	    return;

    m = Py_InitModule("_cpyrit_cpu", CPyritCPUMethods);

    Py_INCREF(&CPUDevice_type);
    PyModule_AddObject(m, "CPUDevice", (PyObject*)&CPUDevice_type);

    Py_INCREF(&EAPOLCracker_type);
    PyModule_AddObject(m, "EAPOLCracker", (PyObject*)&EAPOLCracker_type);

    Py_INCREF(&CowpattyFile_type);
    PyModule_AddObject(m, "CowpattyFile", (PyObject*)&CowpattyFile_type);

    Py_INCREF(&CowpattyResult_type);
    PyModule_AddObject(m, "CowpattyResult", (PyObject*)&CowpattyResult_type);

    PyModule_AddStringConstant(m, "VERSION", VERSION);
}

