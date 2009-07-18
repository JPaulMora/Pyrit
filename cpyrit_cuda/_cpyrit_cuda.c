/*
#
#    Copyright 2008, 2009, Lukas Lueg, lukas.lueg@gmail.com
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
#include <structmember.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "_cpyrit_cuda.h"

// Created by NVCC and setup.py
#include "_cpyrit_cudakernel.cubin.h"

static PyTypeObject CUDADevice_type;

typedef struct
{
    PyObject_HEAD
    int dev_idx;
    PyObject* dev_name;
    CUmodule mod;
    CUfunction kernel;
    CUcontext dev_ctx;
} CUDADevice;

int cudaDevCount;

static char*
getCUresultMsg(CUresult error)
{
    switch (error)
    {
        case CUDA_SUCCESS : return "CUDA_SUCCESS";
        case CUDA_ERROR_INVALID_VALUE : return "CUDA_ERROR_INVALID_VALUE";
        case CUDA_ERROR_OUT_OF_MEMORY : return "CUDA_ERROR_OUT_OF_MEMORY";
        case CUDA_ERROR_NOT_INITIALIZED : return "CUDA_ERROR_NOT_INITIALIZED";
        case CUDA_ERROR_DEINITIALIZED : return "CUDA_ERROR_DEINITIALIZED";
        case CUDA_ERROR_NO_DEVICE : return "CUDA_ERROR_NO_DEVICE";
        case CUDA_ERROR_INVALID_DEVICE : return "CUDA_ERROR_INVALID_DEVICE";
        case CUDA_ERROR_INVALID_IMAGE : return "CUDA_ERROR_INVALID_IMAGE";
        case CUDA_ERROR_INVALID_CONTEXT : return "CUDA_ERROR_INVALID_CONTEXT";
        case CUDA_ERROR_CONTEXT_ALREADY_CURRENT : return "CUDA_ERROR_CONTEXT_ALREADY_CURRENT";
        case CUDA_ERROR_MAP_FAILED : return "CUDA_ERROR_MAP_FAILED";
        case CUDA_ERROR_UNMAP_FAILED : return "CUDA_ERROR_UNMAP_FAILED";
        case CUDA_ERROR_ARRAY_IS_MAPPED : return "CUDA_ERROR_ARRAY_IS_MAPPED";
        case CUDA_ERROR_ALREADY_MAPPED : return "CUDA_ERROR_ALREADY_MAPPED";
        case CUDA_ERROR_NO_BINARY_FOR_GPU : return "CUDA_ERROR_NO_BINARY_FOR_GPU";
        case CUDA_ERROR_ALREADY_ACQUIRED : return "CUDA_ERROR_ALREADY_ACQUIRED";
        case CUDA_ERROR_NOT_MAPPED : return "CUDA_ERROR_NOT_MAPPED";
        case CUDA_ERROR_INVALID_SOURCE : return "CUDA_ERROR_INVALID SOURCE";
        case CUDA_ERROR_FILE_NOT_FOUND : return "CUDA_ERROR_FILE_NOT_FOUND";
        case CUDA_ERROR_INVALID_HANDLE : return "CASE_ERROR_INVALID_HANDLE";
        case CUDA_ERROR_NOT_FOUND : return "CUDA_ERROR_NOT_FOUND";
        case CUDA_ERROR_NOT_READY : return "CUDA_ERROR_NOT_READY";
        case CUDA_ERROR_LAUNCH_FAILED : return "CUDA_ERROR_LAUNCH_FAILED";
        case CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES : return "CUDA_ERROR_LAUNCH_OUT_OF_RESOUCES";
        case CUDA_ERROR_LAUNCH_TIMEOUT : return "CUDA_ERROR_LAUNCH_TIMEOUT";
        case CUDA_ERROR_LAUNCH_INCOMPATIBLE_TEXTURING : return "CUDA_ERROR_LAUNCH_INCOMPATIBLE_TEXTURING";
        case CUDA_ERROR_UNKNOWN : return "CUDA_ERROR_UNKNOWN";
        default : return "Unknown CUresult.";
    }
}

static int
cudadev_init(CUDADevice *self, PyObject *args, PyObject *kwds)
{
    int dev_idx;
    CUresult ret;
    char dev_name[64];

    if (!PyArg_ParseTuple(args, "i:CUDADevice", &dev_idx))
        return -1;

    if (dev_idx < 0 || dev_idx > cudaDevCount-1)
    {
        PyErr_SetString(PyExc_SystemError, "Invalid device number");
        return -1;
    }
    self->dev_idx = dev_idx;
    self->dev_name = NULL;
    self->mod = NULL;
    self->dev_ctx = NULL;
    
    CUSAFECALL(cuDeviceGetName(dev_name, sizeof(dev_name), self->dev_idx));
    self->dev_name = PyString_FromString(dev_name);
    if (!self->dev_name)
    {
        PyErr_NoMemory();
        return -1;
    }
    
    CUSAFECALL(cuCtxCreate(&self->dev_ctx, CU_CTX_SCHED_YIELD, self->dev_idx));
    
    CUSAFECALL(cuModuleLoadData(&self->mod, &__cudakernel_module));

    CUSAFECALL(cuModuleGetFunction(&self->kernel, self->mod, "cuda_pmk_kernel"));
    
    CUSAFECALL(cuFuncSetBlockShape(self->kernel, THREADS_PER_BLOCK, 1, 1));
    
    CUSAFECALL(cuCtxPopCurrent(NULL));

    return 0;
    
errout:
    PyErr_SetString(PyExc_SystemError, getCUresultMsg(ret));
    return -1;
    
}

static void
cudadev_dealloc(CUDADevice *self)
{
    if (self->mod)
        cuModuleUnload(self->mod);
    if (self->dev_ctx)
        cuCtxDestroy(self->dev_ctx);
    Py_XDECREF(self->dev_name);
    PyObject_Del(self);
}

static PyObject*
cpyrit_listDevices(PyObject* self, PyObject* args)
{
    int i;
    PyObject* result;
    char dev_name[64];
    
    if (!PyArg_ParseTuple(args, "")) return NULL;
    
    result = PyTuple_New(cudaDevCount);
    for (i = 0; i < cudaDevCount; i++)
    {
        cuDeviceGetName(dev_name, sizeof(dev_name), i);
        PyTuple_SetItem(result, i, Py_BuildValue("(s)", &dev_name));
    }

    return result;
}

static CUresult
calc_pmklist(CUDADevice *self, gpu_inbuffer *inbuffer, gpu_outbuffer* outbuffer, int size)
{
    CUdeviceptr g_inbuffer, g_outbuffer;
    CUresult ret;
    int buffersize;
    
    // Align size of memory allocation and operations to full threadblocks. Threadblocks should be aligned to warp-size.
    buffersize = (size / THREADS_PER_BLOCK + (size % THREADS_PER_BLOCK == 0 ? 0 : 1)) * THREADS_PER_BLOCK;
    g_inbuffer = 0;
    g_outbuffer = 0;
    
    CUSAFECALL(cuMemAlloc(&g_inbuffer, buffersize*sizeof(gpu_inbuffer)));
    
    CUSAFECALL(cuMemAlloc(&g_outbuffer, buffersize*sizeof(gpu_outbuffer)));
    
    CUSAFECALL(cuMemcpyHtoD(g_inbuffer, inbuffer, size*sizeof(gpu_inbuffer)));
    
    cuParamSeti(self->kernel, 0, g_inbuffer);
    cuParamSeti(self->kernel, sizeof(void*), g_outbuffer);
    cuParamSetSize(self->kernel, sizeof(void*)*2);
    CUSAFECALL(cuLaunchGrid(self->kernel, buffersize / THREADS_PER_BLOCK, 1));

    CUSAFECALL(cuMemcpyDtoH(outbuffer, g_outbuffer, size*sizeof(gpu_outbuffer)));
    
    cuMemFree(g_inbuffer);
    cuMemFree(g_outbuffer);

    return CUDA_SUCCESS;
    
errout:
    if (g_inbuffer != 0)
        cuMemFree(g_inbuffer);
    if (g_outbuffer != 0)
        cuMemFree(g_outbuffer);
    return ret;
}

static PyObject*
cpyrit_solve(CUDADevice *self, PyObject *args)
{
    char *essid_pre, essid[33+4], *passwd;
    unsigned char pad[64], temp[32];
    int i, arraysize, slen;
    PyObject *passwd_seq, *passwd_obj, *result;
    gpu_inbuffer *c_inbuffer, *t;
    gpu_outbuffer *c_outbuffer;
    SHA_CTX ctx_pad;

    if (!PyArg_ParseTuple(args, "sO", &essid_pre, &passwd_seq)) return NULL;
    passwd_seq = PyObject_GetIter(passwd_seq);
    if (!passwd_seq) return NULL;
    
    memset( essid, 0, sizeof(essid) );
    slen = strlen(essid_pre);
    slen = slen <= 32 ? slen : 32;
    memcpy(essid, essid_pre, slen);
    slen = strlen(essid)+4;

    arraysize = 0;
    c_inbuffer = NULL;
    c_outbuffer = NULL;    
    while ((passwd_obj = PyIter_Next(passwd_seq)))
    {
        if (arraysize % 1000 == 0)
        {
            t = PyMem_Realloc(c_inbuffer, sizeof(gpu_inbuffer)*(arraysize+1000));
            if (!t)
            {
                Py_DECREF(passwd_obj);
                Py_DECREF(passwd_seq);
                PyMem_Free(c_inbuffer);
                PyErr_NoMemory();
                return NULL;
            }
            c_inbuffer = t;
        }                
        passwd = PyString_AsString(passwd_obj);
        if (passwd == NULL || strlen(passwd) < 8 || strlen(passwd) > 63)
        {
            Py_DECREF(passwd_obj);
            Py_DECREF(passwd_seq);
            PyMem_Free(c_inbuffer);
            PyErr_SetString(PyExc_ValueError, "All items must be strings between 8 and 63 characters");
            return NULL;
        }
        
        strncpy((char*)pad, passwd, sizeof(pad));
        for (i = 0; i < 16; i++)
            ((unsigned int*)pad)[i] ^= 0x36363636;
        SHA1_Init(&ctx_pad);
        SHA1_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX(ctx_pad, c_inbuffer[arraysize].ctx_ipad);
        for (i = 0; i < 16; i++)
            ((unsigned int*)pad)[i] ^= 0x6A6A6A6A;
        SHA1_Init(&ctx_pad);
        SHA1_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX(ctx_pad, c_inbuffer[arraysize].ctx_opad);
        
        essid[slen - 1] = '\1';
        HMAC(EVP_sha1(), (unsigned char *)passwd, strlen(passwd), (unsigned char*)essid, slen, temp, NULL);
        GET_BE(c_inbuffer[arraysize].e1.h0, temp, 0);
        GET_BE(c_inbuffer[arraysize].e1.h1, temp, 4);
        GET_BE(c_inbuffer[arraysize].e1.h2, temp, 8);
        GET_BE(c_inbuffer[arraysize].e1.h3, temp, 12);
        GET_BE(c_inbuffer[arraysize].e1.h4, temp, 16);

        essid[slen - 1] = '\2';
        HMAC(EVP_sha1(), (unsigned char *)passwd, strlen(passwd), (unsigned char*)essid, slen, temp, NULL);
        GET_BE(c_inbuffer[arraysize].e2.h0, temp, 0);
        GET_BE(c_inbuffer[arraysize].e2.h1, temp, 4);
        GET_BE(c_inbuffer[arraysize].e2.h2, temp, 8);
        GET_BE(c_inbuffer[arraysize].e2.h3, temp, 12);
        GET_BE(c_inbuffer[arraysize].e2.h4, temp, 16);

        Py_DECREF(passwd_obj);
        arraysize++;
    }
    Py_DECREF(passwd_seq);
    
    if (arraysize == 0)
    {
        PyMem_Free(c_inbuffer);
        return PyTuple_New(0);
    }
    
    c_outbuffer = PyMem_New(gpu_outbuffer, arraysize);
    if (c_outbuffer == NULL)
    {
        PyMem_Free(c_inbuffer);
        return PyErr_NoMemory();
    }

    i = cuCtxPushCurrent(self->dev_ctx);
    if (i != CUDA_SUCCESS)
    {
        PyErr_SetString(PyExc_SystemError, getCUresultMsg(i));
        PyMem_Free(c_inbuffer);
        PyMem_Free(c_outbuffer);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS;
    i = calc_pmklist(self, c_inbuffer, c_outbuffer, arraysize);
    Py_END_ALLOW_THREADS;
    cuCtxPopCurrent(NULL);
    PyMem_Free(c_inbuffer);

    if (i != CUDA_SUCCESS)
    {
        PyMem_Free(c_outbuffer);
        PyErr_SetString(PyExc_SystemError, getCUresultMsg(i));
        return NULL;
    }

    result = PyTuple_New(arraysize);
    for (i = 0; i < arraysize; i++)
    {
        PUT_BE(c_outbuffer[i].pmk1.h0, temp, 0); PUT_BE(c_outbuffer[i].pmk1.h1, temp, 4);
        PUT_BE(c_outbuffer[i].pmk1.h2, temp, 8); PUT_BE(c_outbuffer[i].pmk1.h3, temp, 12); 
        PUT_BE(c_outbuffer[i].pmk1.h4, temp, 16);PUT_BE(c_outbuffer[i].pmk2.h0, temp, 20); 
        PUT_BE(c_outbuffer[i].pmk2.h1, temp, 24);PUT_BE(c_outbuffer[i].pmk2.h2, temp, 28); 
        PyTuple_SetItem(result, i, Py_BuildValue("s#", temp, 32));
    }
    
    PyMem_Free(c_outbuffer);

    return result;
}

static PyMemberDef CUDADevice_members[] =
{
    {"deviceName", T_OBJECT, offsetof(CUDADevice, dev_name), 0},
    {NULL}
};

static PyMethodDef CUDADevice_methods[] =
{
    {"solve", (PyCFunction)cpyrit_solve, METH_VARARGS, "Calculate PMKs from ESSID and iterable of strings."},
    {NULL, NULL}
};

static PyTypeObject CUDADevice_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_cuda.CUDADevice",  /*tp_name*/
    sizeof(CUDADevice),         /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)cudadev_dealloc,/*tp_dealloc*/
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
    CUDADevice_methods,         /*tp_methods*/
    CUDADevice_members,         /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)cudadev_init,     /*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};


static PyMethodDef CPyritCUDA_methods[] = {
    {"listDevices", cpyrit_listDevices, METH_VARARGS, "Returns a tuple of tuples, each describing a CUDA-capable device."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_cpyrit_cuda(void)
{
    PyObject *m;
    
    if (cuInit(0) != CUDA_SUCCESS || cuDeviceGetCount(&cudaDevCount) != CUDA_SUCCESS || cudaDevCount < 1)
    {
        PyErr_SetString(PyExc_ImportError, "CUDA seems to be unavailable or no device reported.");
        return;
    }
    
    CUDADevice_type.tp_getattro = PyObject_GenericGetAttr;
    CUDADevice_type.tp_setattro = PyObject_GenericSetAttr;
    CUDADevice_type.tp_alloc  = PyType_GenericAlloc;
    CUDADevice_type.tp_new = PyType_GenericNew;
    CUDADevice_type.tp_free = _PyObject_Del;  
    if (PyType_Ready(&CUDADevice_type) < 0)
	    return;

    m = Py_InitModule("_cpyrit_cuda", CPyritCUDA_methods);
    
    Py_INCREF(&CUDADevice_type);
    PyModule_AddObject(m, "CUDADevice", (PyObject*)&CUDADevice_type);
}

