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

#include <Python.h>
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
    char dev_name[64];
    CUmodule mod;
    CUfunction kernel;
    CUcontext dev_ctx;
} CUDADevice;

int cudaDevCount;

static int
cudadev_init(CUDADevice *self, PyObject *args, PyObject *kwds)
{
    int dev_idx;

	if (!PyArg_ParseTuple(args, "i:CUDADevice", &dev_idx))
		return -1;

    if (dev_idx < 0 || dev_idx > cudaDevCount-1)
    {
        PyErr_SetString(PyExc_SystemError, "Invalid device number");
        return -1;
    }
    self->dev_idx = dev_idx;
    
    if (cuDeviceGetName(self->dev_name, sizeof(self->dev_name), self->dev_idx) != CUDA_SUCCESS)
    {
        PyErr_SetString(PyExc_SystemError, "Failed to resolve device name.");
        return -1;
    }
    
    if (cuCtxCreate(&self->dev_ctx, CU_CTX_SCHED_YIELD, self->dev_idx) != CUDA_SUCCESS)
    {
        PyErr_SetString(PyExc_SystemError, "Failed to create device-context.");
        return -1;
    }
    
    if (cuModuleLoadData(&self->mod, &__cudakernel_module) != CUDA_SUCCESS)
    {
        PyErr_SetString(PyExc_SystemError, "Failed to load CUBIN-module.");
        return -1;
    }

    if (cuModuleGetFunction(&self->kernel, self->mod, "cuda_pmk_kernel") != CUDA_SUCCESS)
    {
        PyErr_SetString(PyExc_SystemError, "Failed to load kernel-function");
        return -1;    
    }
    
    if (cuFuncSetBlockShape(self->kernel, THREADS_PER_BLOCK, 1, 1) != CUDA_SUCCESS)
    {
        PyErr_SetString(PyExc_SystemError, "Failed to set block-shape");
        return -1;    
    }
    
    if (cuCtxPopCurrent(NULL) != CUDA_SUCCESS)
    {
        cuCtxDestroy(self->dev_ctx);
        PyErr_SetString(PyExc_SystemError, "Failed to detach from device-context after creation.");        
        return -1;
    }

    return 0;
}

static void
cudadev_dealloc(CUDADevice *self)
{
    cuModuleUnload(self->mod);
    cuCtxDestroy(self->dev_ctx);
    PyObject_Del(self);
}

PyObject* cpyrit_listDevices(PyObject* self, PyObject* args)
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

CUresult calc_pmklist(CUDADevice *self, gpu_inbuffer *inbuffer, gpu_outbuffer* outbuffer, int size)
{
    CUdeviceptr g_inbuffer, g_outbuffer;
    CUresult ret;
    int buffersize;
    
    // Align size of memory allocation and operations to full threadblocks. Threadblocks should be aligned to warp-size.
    buffersize = (size / THREADS_PER_BLOCK + (size % THREADS_PER_BLOCK == 0 ? 0 : 1)) * THREADS_PER_BLOCK;
    ret = cuMemAlloc(&g_inbuffer, buffersize*sizeof(gpu_inbuffer));
    if (ret != CUDA_SUCCESS)
        return ret;
    
    ret = cuMemAlloc(&g_outbuffer, buffersize*sizeof(gpu_outbuffer));
    if (ret != CUDA_SUCCESS)
    {
        cuMemFree(g_inbuffer);
        return ret;
    }
    
    ret = cuMemcpyHtoD(g_inbuffer, inbuffer, size*sizeof(gpu_inbuffer));
    if (ret != CUDA_SUCCESS)
    {
        cuMemFree(g_outbuffer);
        cuMemFree(g_inbuffer);
        return ret;
    }
    
    cuParamSeti(self->kernel, 0, g_inbuffer);
    cuParamSeti(self->kernel, sizeof(void*), g_outbuffer);
    cuParamSetSize(self->kernel, sizeof(void*)*2);
    ret = cuLaunchGrid(self->kernel, buffersize / THREADS_PER_BLOCK, 1);
    if (ret != CUDA_SUCCESS)
    {
        cuMemFree(g_inbuffer);
        cuMemFree(g_outbuffer);
        cuCtxPopCurrent(NULL);
        return ret;
    }

    cuMemFree(g_inbuffer);

    ret = cuMemcpyDtoH(outbuffer, g_outbuffer, size*sizeof(gpu_outbuffer));
    if (ret != CUDA_SUCCESS)
    {
        cuMemFree(g_outbuffer);
        cuCtxPopCurrent(NULL);
        return ret;
    }
    
    cuMemFree(g_outbuffer);

    return CUDA_SUCCESS;
}

PyObject *cpyrit_pmklist(CUDADevice *self, PyObject *args)
{
    char *essid_pre, *key, essid[33+4];
    unsigned char pad[64], temp[32];
    int i, j, numLines, slen, ret;
    PyObject *passwdList, *resultList;
    gpu_inbuffer* c_inbuffer;
    gpu_outbuffer* c_outbuffer;
    SHA_CTX ctx_pad;

    if (!PyArg_ParseTuple(args, "sO!", &essid_pre, &PyList_Type, &passwdList))
        return NULL;
    
    numLines = PyList_Size(passwdList);
    if (numLines <= 0)
        return PyTuple_New(0);

    c_inbuffer = (gpu_inbuffer *)malloc(numLines*sizeof(gpu_inbuffer));
    if (c_inbuffer == NULL)
        return PyErr_NoMemory();
    
    c_outbuffer = (gpu_outbuffer *)malloc(numLines*sizeof(gpu_outbuffer));
    if (c_outbuffer == NULL)
    {
        free(c_inbuffer);
        return PyErr_NoMemory();
    }

    memset( essid, 0, sizeof(essid) );
    slen = strlen(essid_pre);
    slen = slen <= 32 ? slen : 32;
    memcpy(essid, essid_pre, slen);
    slen = strlen(essid)+4;

    for (i = 0; i < numLines; i++)
    {
        key = PyString_AsString(PyList_GetItem(passwdList, i));

        strncpy((char*)pad, key, sizeof(pad));
        for (j = 0; j < 16; j++)
            ((unsigned int*)pad)[j] ^= 0x36363636;
        SHA1_Init(&ctx_pad);
        SHA1_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX(ctx_pad, c_inbuffer[i].ctx_ipad);

        for (j = 0; j < 16; j++)
            ((unsigned int*)pad)[j] ^= 0x6A6A6A6A;
        SHA1_Init(&ctx_pad);
        SHA1_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX(ctx_pad, c_inbuffer[i].ctx_opad);

        essid[slen - 1] = '\1';
        HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, temp, NULL);
        GET_BE(c_inbuffer[i].e1.h0, temp, 0); GET_BE(c_inbuffer[i].e1.h1, temp, 4);
        GET_BE(c_inbuffer[i].e1.h2, temp, 8); GET_BE(c_inbuffer[i].e1.h3, temp, 12);
        GET_BE(c_inbuffer[i].e1.h4, temp, 16);

        essid[slen - 1] = '\2';
        HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, temp, NULL);
        GET_BE(c_inbuffer[i].e2.h0, temp, 0); GET_BE(c_inbuffer[i].e2.h1, temp, 4);
        GET_BE(c_inbuffer[i].e2.h2, temp, 8); GET_BE(c_inbuffer[i].e2.h3, temp, 12);
        GET_BE(c_inbuffer[i].e2.h4, temp, 16);
    }
    
    if (cuCtxPushCurrent(self->dev_ctx) != CUDA_SUCCESS)
    {
        PyErr_SetString(PyExc_SystemError, "Failed to attach to device-context before launch.");
        free(c_inbuffer);
        free(c_outbuffer);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS;
    ret = calc_pmklist(self, c_inbuffer, c_outbuffer, numLines);
    Py_END_ALLOW_THREADS;
    
    cuCtxPopCurrent(NULL);
    free(c_inbuffer);
    if (ret != CUDA_SUCCESS)
    {
        free(c_outbuffer);
        PyErr_SetString(PyExc_SystemError, "Failed to launch CUDA-kernel.");
        return NULL;
    }

    resultList = PyTuple_New(numLines);
    for (i = 0; i < numLines; i++)
    {
        PUT_BE(c_outbuffer[i].pmk1.h0, temp, 0); PUT_BE(c_outbuffer[i].pmk1.h1, temp, 4);
        PUT_BE(c_outbuffer[i].pmk1.h2, temp, 8); PUT_BE(c_outbuffer[i].pmk1.h3, temp, 12); 
        PUT_BE(c_outbuffer[i].pmk1.h4, temp, 16);PUT_BE(c_outbuffer[i].pmk2.h0, temp, 20); 
        PUT_BE(c_outbuffer[i].pmk2.h1, temp, 24);PUT_BE(c_outbuffer[i].pmk2.h2, temp, 28); 
        PyTuple_SetItem(resultList, i, Py_BuildValue("s#", temp, 32));
    }
    
    free(c_outbuffer);

    return resultList;
}


static PyMethodDef CUDADevice_methods[] =
{
    {"calc_pmklist", (PyObject*)cpyrit_pmklist, METH_VARARGS, "Calculate PMKs from ESSID and list of strings."},
    {NULL, NULL}
};

static PyTypeObject CUDADevice_type = {
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"_cpyrit_cuda.CUDADevice",	/*tp_name*/
	sizeof(CUDADevice), /*tp_basicsize*/
	0,			/*tp_itemsize*/
	(destructor)cudadev_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,			/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    PyObject_GenericGetAttr,/*tp_getattro*/
    PyObject_GenericSetAttr,/*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,      /*tp_flags*/
    0,       /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    CUDADevice_methods,      /*tp_methods*/
    0,      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    (initproc)cudadev_init, /*tp_init*/
    PyType_GenericAlloc,    /*tp_alloc*/
    PyType_GenericNew,      /*tp_new*/
  	_PyObject_Del,          /*tp_free*/
    0,                      /*tp_is_gc*/
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

    if (PyType_Ready(&CUDADevice_type) < 0)
	    return;

    m = Py_InitModule("_cpyrit_cuda", CPyritCUDA_methods);
    
    Py_INCREF(&CUDADevice_type);
    PyModule_AddObject(m, "CUDADevice", (PyObject *)&CUDADevice_type);
}
