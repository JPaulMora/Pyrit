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
#include <structmember.h>
#include <CL/cl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <zlib.h>
#include "_cpyrit_opencl.h"

// Created by setup.py
#include "_cpyrit_oclkernel.cl.h"

static PyTypeObject OpenCLDevice_type;

typedef struct
{
    PyObject_HEAD
    int dev_idx;
    PyObject* dev_name;
    size_t lWorksize;
    cl_context dev_ctx;
    cl_program dev_prog;
    cl_kernel dev_kernel;
    cl_command_queue dev_queue;
} OpenCLDevice;

cl_uint OpenCLDevCount;
cl_device_id* OpenCLDevices;
unsigned char *oclkernel_program;

static char*
getCLresultMsg(cl_int error)
{
    switch (error)
    {
        // HC SVNT DRACONES
        case CL_SUCCESS: return "CL_SUCCESS";
        case CL_DEVICE_NOT_FOUND: return "CL_DEVICE_NOT_FOUND";
        case CL_DEVICE_NOT_AVAILABLE: return "CL_DEVICE_NOT_AVAILABLE";
        case CL_DEVICE_COMPILER_NOT_AVAILABLE: return "CL_DEVICE_COMPILER_NOT_AVAILABLE";
        case CL_MEM_OBJECT_ALLOCATION_FAILURE: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case CL_OUT_OF_RESOURCES: return "CL_OUT_OF_RESOURCES";
        case CL_OUT_OF_HOST_MEMORY: return "CL_OUT_OF_HOST_MEMORY";
        case CL_PROFILING_INFO_NOT_AVAILABLE: return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case CL_MEM_COPY_OVERLAP: return "CL_MEM_COPY_OVERLAP";
        case CL_IMAGE_FORMAT_MISMATCH: return "CL_IMAGE_FORMAT_MISMATCH";
        case CL_IMAGE_FORMAT_NOT_SUPPORTED: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case CL_BUILD_PROGRAM_FAILURE: return "CL_BUILD_PROGRAM_FAILURE";
        case CL_MAP_FAILURE: return "CL_MAP_FAILURE";
        case CL_INVALID_VALUE: return "CL_INVALID_VALUE";
        case CL_INVALID_DEVICE_TYPE: return "CL_INVALID_DEVICE_TYPE";
        case CL_INVALID_PLATFORM: return "CL_INVALID_PLATFORM";
        case CL_INVALID_DEVICE: return "CL_INVALID_DEVICE";
        case CL_INVALID_CONTEXT: return "CL_INVALID_CONTEXT";
        case CL_INVALID_QUEUE_PROPERTIES: return "CL_INVALID_QUEUE_PROPERTIES";
        case CL_INVALID_COMMAND_QUEUE: return "CL_INVALID_COMMAND_QUEUE";
        case CL_INVALID_HOST_PTR: return "CL_INVALID_HOST_PTR";
        case CL_INVALID_MEM_OBJECT: return "CL_INVALID_MEM_OBJECT";
        case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case CL_INVALID_IMAGE_SIZE: return "CL_INVALID_IMAGE_SIZE";
        case CL_INVALID_SAMPLER: return "CL_INVALID_SAMPLER";
        case CL_INVALID_BINARY: return "CL_INVALID_BINARY";
        case CL_INVALID_BUILD_OPTIONS: return "CL_INVALID_BUILD_OPTIONS";
        case CL_INVALID_PROGRAM: return "CL_INVALID_PROGRAM";
        case CL_INVALID_PROGRAM_EXECUTABLE: return "CL_INVALID_PROGRAM_EXECUTABLE";
        case CL_INVALID_KERNEL_NAME: return "CL_INVALID_KERNEL_NAME";
        case CL_INVALID_KERNEL_DEFINITION: return "CL_INVALID_KERNEL_DEFINITION";
        case CL_INVALID_KERNEL: return "CL_INVALID_KERNEL";
        case CL_INVALID_ARG_INDEX: return "CL_INVALID_ARG_INDEX";
        case CL_INVALID_ARG_VALUE: return "CL_INVALID_ARG_VALUE";
        case CL_INVALID_ARG_SIZE: return "CL_INVALID_ARG_SIZE";
        case CL_INVALID_KERNEL_ARGS: return "CL_INVALID_KERNEL_ARGS";
        case CL_INVALID_WORK_DIMENSION: return "CL_INVALID_WORK_DIMENSION";
        case CL_INVALID_WORK_GROUP_SIZE: return "CL_INVALID_WORK_GROUP_SIZE";
        case CL_INVALID_WORK_ITEM_SIZE: return "CL_INVALID_WORK_ITEM_SIZE";
        case CL_INVALID_GLOBAL_OFFSET: return "CL_INVALID_GLOBAL_OFFSET";
        case CL_INVALID_EVENT_WAIT_LIST: return "CL_INVALID_EVENT_WAIT_LIST";
        case CL_INVALID_EVENT: return "CL_INVALID_EVENT";
        case CL_INVALID_OPERATION: return "CL_INVALID_OPERATION";
        case CL_INVALID_GL_OBJECT: return "CL_INVALID_GL_OBJECT";
        case CL_INVALID_BUFFER_SIZE: return "CL_INVALID_BUFFER_SIZE";
        case CL_INVALID_MIP_LEVEL: return "CL_INVALID_MIP_LEVEL";
        default : return "Unknown CLresult";
    }
}

static int
opencldev_init(OpenCLDevice *self, PyObject *args, PyObject *kwds)
{
    int dev_idx;
    char dev_name[64];
    cl_int errcode;

    if (!PyArg_ParseTuple(args, "i:OpenCLDevice", &dev_idx))
        return -1;

    if (dev_idx < 0 || dev_idx > OpenCLDevCount-1)
    {
        PyErr_Format(PyExc_ValueError, "Device-number must be between 0 and %i", OpenCLDevCount-1);
        return -1;
    }
    self->dev_idx = dev_idx;
    self->dev_name = NULL;
    self->dev_ctx = NULL;
    self->dev_prog = NULL;
    self->dev_kernel = NULL;
    self->dev_queue = NULL;
    self->lWorksize = WORKGROUP_SIZE; // make this depend on the device?

    errcode = clGetDeviceInfo(OpenCLDevices[dev_idx], CL_DEVICE_NAME, sizeof(dev_name), &dev_name, NULL);
    if (errcode != CL_SUCCESS)
    {
        PyErr_Format(PyExc_SystemError, "Failed to get device-name (%s)", getCLresultMsg(errcode));
        return -1;
    }
    self->dev_name = PyString_FromString(dev_name);
    if (!self->dev_name)
    {
        PyErr_NoMemory();
        return -1;
    }
    
    self->dev_ctx = clCreateContext(NULL, 1, &OpenCLDevices[dev_idx], NULL, NULL, &errcode);
    if (errcode != CL_SUCCESS)
    {
        PyErr_Format(PyExc_SystemError, "Failed to create device-context (%s)", getCLresultMsg(errcode));
        return -1;
    }
    
    self->dev_queue = clCreateCommandQueue(self->dev_ctx, OpenCLDevices[dev_idx], 0, &errcode);
    if (errcode != CL_SUCCESS)
    {
        PyErr_Format(PyExc_SystemError, "Failed to create command-queue (%s)", getCLresultMsg(errcode));
        return -1;
    }
    
    self->dev_prog = clCreateProgramWithSource(self->dev_ctx, 1, (void*)&oclkernel_program, &oclkernel_size, &errcode);
    if (errcode != CL_SUCCESS)
    {
        PyErr_Format(PyExc_SystemError, "Failed to load kernel-source (%s)", getCLresultMsg(errcode));
        return -1;
    }
    
    errcode = clBuildProgram(self->dev_prog, 0, NULL, NULL, NULL, NULL);
    if (errcode != CL_SUCCESS)
    {
        char log[1024];
        clGetProgramBuildInfo(self->dev_prog, OpenCLDevices[dev_idx], CL_PROGRAM_BUILD_LOG, sizeof(log), log, NULL);
        PyErr_Format(PyExc_SystemError, "Failed to compile kernel-source (%s):\n%s", getCLresultMsg(errcode), log);
        return -1;
    }
    
    self->dev_kernel = clCreateKernel(self->dev_prog, "opencl_pmk_kernel", &errcode);
    if (errcode != CL_SUCCESS)
    {
        PyErr_Format(PyExc_SystemError, "Failed to create kernel (%s)", getCLresultMsg(errcode));
        return -1;
    }

    return 0;
        
}

static void
opencldev_dealloc(OpenCLDevice *self)
{
    if (self->dev_queue)
        clReleaseCommandQueue(self->dev_queue);
    if (self->dev_kernel)
        clReleaseKernel(self->dev_kernel);
    if (self->dev_prog)
        clReleaseProgram(self->dev_prog);
    if (self->dev_ctx)
        clReleaseContext(self->dev_ctx);
    Py_XDECREF(self->dev_name);
    PyObject_Del(self);
}

static PyObject*
cpyrit_listDevices(PyObject* self, PyObject* args)
{
    int i;
    PyObject* result;
    char dev_name[64];
    char vendor_name[128];
    
    if (!PyArg_ParseTuple(args, "")) return NULL;
    
    result = PyTuple_New(OpenCLDevCount);
    for (i = 0; i < OpenCLDevCount; i++)
    {
        clGetDeviceInfo(OpenCLDevices[i], CL_DEVICE_NAME, sizeof(dev_name), &dev_name, NULL);
        clGetDeviceInfo(OpenCLDevices[i], CL_DEVICE_VENDOR, sizeof(vendor_name), &vendor_name, NULL);
        PyTuple_SetItem(result, i, Py_BuildValue("(s, s)", &dev_name, &vendor_name));
    }

    return result;
}

static cl_int
calc_pmklist(OpenCLDevice *self, gpu_inbuffer *inbuffer, gpu_outbuffer* outbuffer, int size)
{
    cl_mem g_inbuffer, g_outbuffer;
    cl_int errcode;
    size_t gWorksize[1], lWorksize[1], buffersize;
    
    buffersize = (size / self->lWorksize + (size % self->lWorksize == 0 ? 0 : 1)) * self->lWorksize;

    g_inbuffer = NULL;
    g_outbuffer = NULL;
    gWorksize[0] = buffersize;
    lWorksize[0] = self->lWorksize;
    
    g_inbuffer = clCreateBuffer(self->dev_ctx, CL_MEM_READ_ONLY, buffersize*sizeof(gpu_inbuffer), NULL, &errcode);
    if (errcode != CL_SUCCESS)
        goto out;
    errcode = clEnqueueWriteBuffer(self->dev_queue, g_inbuffer, CL_FALSE, 0, size*sizeof(gpu_inbuffer), inbuffer, 0, NULL, NULL);
    if (errcode != CL_SUCCESS)
        goto out;
    
    g_outbuffer = clCreateBuffer(self->dev_ctx, CL_MEM_WRITE_ONLY, buffersize*sizeof(gpu_outbuffer), NULL, &errcode);
    if (errcode != CL_SUCCESS)
        goto out;
    
    errcode = clSetKernelArg(self->dev_kernel, 0, sizeof(cl_mem), &g_inbuffer);
    if (errcode != CL_SUCCESS)
        goto out;
    errcode = clSetKernelArg(self->dev_kernel, 1, sizeof(cl_mem), &g_outbuffer);
    if (errcode != CL_SUCCESS)
        goto out;
    errcode = clEnqueueNDRangeKernel(self->dev_queue, self->dev_kernel, 1, NULL, gWorksize, lWorksize, 0, NULL, NULL);
    if (errcode != CL_SUCCESS)
        goto out;

    errcode = clEnqueueReadBuffer(self->dev_queue, g_outbuffer, CL_FALSE, 0, size*sizeof(gpu_outbuffer), outbuffer, 0, NULL, NULL);
    
out:
    clFinish(self->dev_queue);
    if (g_inbuffer != NULL)
        clReleaseMemObject(g_inbuffer);
    if (g_outbuffer != NULL)
        clReleaseMemObject(g_outbuffer);
    
    return errcode;
}

PyObject*
cpyrit_solve(OpenCLDevice *self, PyObject *args)
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
            t = PyMem_Resize(c_inbuffer, gpu_inbuffer, arraysize+1000);
            if (!t)
            {
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
        PyErr_NoMemory();
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS;
    i = calc_pmklist(self, c_inbuffer, c_outbuffer, arraysize);
    Py_END_ALLOW_THREADS;    
    PyMem_Free(c_inbuffer);
    
    if (i != CL_SUCCESS)
    {
        PyMem_Free(c_outbuffer);
        PyErr_Format(PyExc_SystemError, "Failed to execute kernel (%s)", getCLresultMsg(i));
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

static PyMemberDef OpenCLDevice_members[] =
{
    {"deviceName", T_OBJECT, offsetof(OpenCLDevice, dev_name), 0},
    {NULL}
};

static PyMethodDef OpenCLDevice_methods[] =
{
    {"solve", (PyCFunction)cpyrit_solve, METH_VARARGS, "Calculate PMKs from ESSID and list of strings."},
    {NULL, NULL}
};

static PyTypeObject OpenCLDevice_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_cuda.OpenCLDevice",/*tp_name*/
    sizeof(OpenCLDevice),       /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)opencldev_dealloc,/*tp_dealloc*/
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
    OpenCLDevice_methods,       /*tp_methods*/
    OpenCLDevice_members,       /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)opencldev_init,   /*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};


static PyMethodDef CPyritOpenCL_methods[] = {
    {"listDevices", cpyrit_listDevices, METH_VARARGS, "Returns a tuple of tuples, each describing a OpenCL-capable device."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_cpyrit_opencl(void)
{
    z_stream zst;

    if (clGetDeviceIDs(NULL, CL_DEVICE_TYPE_GPU, 0, NULL, &OpenCLDevCount) != CL_SUCCESS || OpenCLDevCount < 1)
    {
        PyErr_SetString(PyExc_ImportError, "Could not enumerate available OpenCL-devices or no devices reported.");
        return;
    }
    
    OpenCLDevices = PyMem_New(cl_device_id, OpenCLDevCount);
    if (clGetDeviceIDs(NULL, CL_DEVICE_TYPE_GPU, OpenCLDevCount, OpenCLDevices, NULL) != CL_SUCCESS)
    {
        PyMem_Free(OpenCLDevices);
        PyErr_SetString(PyExc_ImportError, "Failed to get Device-IDs");
        return;
    }
    
    oclkernel_program = PyMem_Malloc(oclkernel_size);
    if (!oclkernel_program)
    {
        PyMem_Free(OpenCLDevices);
        PyErr_NoMemory();
        return;
    }
    zst.zalloc = Z_NULL;
    zst.zfree = Z_NULL;
    zst.opaque = Z_NULL;
    zst.avail_in = sizeof(oclkernel_packedprogram);
    zst.next_in = oclkernel_packedprogram;
    if (inflateInit(&zst) != Z_OK)
    {
        PyMem_Free(OpenCLDevices);
        PyMem_Free(oclkernel_program);
        PyErr_SetString(PyExc_IOError, "Failed to initialize zlib.");
        return;
    }
    zst.avail_out = oclkernel_size;
    zst.next_out = oclkernel_program;   
    if (inflate(&zst, Z_FINISH) != Z_STREAM_END)
    {
        inflateEnd(&zst);
        PyMem_Free(OpenCLDevices);
        PyMem_Free(oclkernel_program);    
        PyErr_SetString(PyExc_IOError, "Failed to decompress OpenCL-kernel.");
        return;
    }
    inflateEnd(&zst);

    OpenCLDevice_type.tp_getattro = PyObject_GenericGetAttr;
    OpenCLDevice_type.tp_setattro = PyObject_GenericSetAttr;
    OpenCLDevice_type.tp_alloc  = PyType_GenericAlloc;
    OpenCLDevice_type.tp_new = PyType_GenericNew;
    OpenCLDevice_type.tp_free = _PyObject_Del;      
    if (PyType_Ready(&OpenCLDevice_type) < 0)
    {
        PyMem_Free(OpenCLDevices);
        PyMem_Free(oclkernel_program);
	    return;
    }

    Py_INCREF(&OpenCLDevice_type);
    PyModule_AddObject(Py_InitModule("_cpyrit_opencl", CPyritOpenCL_methods), "OpenCLDevice", (PyObject *)&OpenCLDevice_type);
}

