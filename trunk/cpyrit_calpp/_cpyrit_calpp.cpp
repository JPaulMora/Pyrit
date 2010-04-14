/*
#
#    Copyright 2008, 2009, 2010 Artur Kornacki, Lukas Lueg, lukas.lueg@gmail.com
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
#include <cal/cal.hpp>
#include <iostream>
#include <boost/cstdint.hpp>
#include "_cpyrit_calpp.h"

std::string calpp_create_pmk_kernel( cal::Device& device );

extern "C" typedef struct
{
    PyObject_HEAD
    int dev_idx;
    PyObject* dev_name;
    cal::Context* dev_context;
    cal::Program* dev_prog;
    cal::Kernel* dev_kernel;
    cal::CommandQueue* dev_queue;
    int dev_maxheight;
} CALDevice;

static int calDevCount;
static cal::Context calContext;

static const char* device_name[10] = {"ATI RV600", "ATI RV610", "ATI RV630",
                                      "ATI RV670", "ATI RV7XX", "ATI RV770",
                                      "ATI RV710", "ATI RV730", "ATI CYPRESS",
                                      "ATI JUNIPER"};

static const char*
getDeviceName( int target )
{
    if(target >= 0 && target < 10)
        return device_name[target];

    return "ATI";
}

static int
caldev_init( CALDevice *self, PyObject *args, PyObject *kwds )
{
    int dev_idx;

    self->dev_name = NULL;
    self->dev_context = NULL;
    self->dev_prog = NULL;
    self->dev_kernel = NULL;
    self->dev_queue = NULL;

    if (!PyArg_ParseTuple(args, "i:CALDevice", &dev_idx))
        return -1;

    if (dev_idx < 0 || dev_idx > calDevCount-1)
    {
        PyErr_SetString(PyExc_SystemError, "Invalid device number");
        return -1;
    }

    try {
        cal::Device device;
        std::string source;

        device = calContext.getInfo<CAL_CONTEXT_DEVICES>()[dev_idx];

        self->dev_context = new cal::Context(device);

        source = calpp_create_pmk_kernel(device);

        //std::cout << source;

        self->dev_idx  = dev_idx;
        self->dev_name = PyString_FromString(getDeviceName(device.getInfo<CAL_DEVICE_TARGET>()));

        try {
            self->dev_prog = new cal::Program(*self->dev_context, source.c_str(), source.length() );
            self->dev_prog->build(self->dev_context->getInfo<CAL_CONTEXT_DEVICES>());
            //self->dev_prog->disassemble(std::cout);
        } catch( cal::Error& e ) {
            PyErr_SetString(PyExc_SystemError, "CAL++ kernel compilation error");
            return -1;
        }

        self->dev_kernel = new cal::Kernel(*self->dev_prog, "main");
        self->dev_kernel->setArgBind(0, "i0");
        self->dev_kernel->setArgBind(1, "i1");
        self->dev_kernel->setArgBind(2, "i2");
        self->dev_kernel->setArgBind(3, "i3");
        self->dev_kernel->setArgBind(4, "i4");
        self->dev_kernel->setArgBind(5, "o0");
        self->dev_kernel->setArgBind(6, "o1");

        self->dev_queue = new cal::CommandQueue(*self->dev_context,device);

        self->dev_maxheight = device.getInfo<CAL_DEVICE_MAXRESOURCE2DHEIGHT>();

    } catch( cal::Error& e ) {
        PyErr_SetString(PyExc_SystemError, e.what());
        return -1;
    }

    return 0;
}

static void
caldev_dealloc(CALDevice *self)
{
    if(self->dev_queue)
        delete self->dev_queue;
    if(self->dev_kernel)
        delete self->dev_kernel;
    if(self->dev_prog)
        delete self->dev_prog;
    if(self->dev_context)
        delete self->dev_context;

    Py_XDECREF(self->dev_name);
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject*
cpyrit_listDevices(PyObject* self, PyObject* args)
{
    int i;
    PyObject* result;
    std::vector<cal::Device> devices;

    devices = calContext.getInfo<CAL_CONTEXT_DEVICES>();

    result = PyTuple_New(calDevCount);
    for (i = 0; i < calDevCount; i++)
        PyTuple_SetItem(result, i, Py_BuildValue("(s)", getDeviceName(devices[i].getInfo<CAL_DEVICE_TARGET>())));

    return result;
}

static void
copy_gpu_inbuffer(CALDevice* self, const gpu_inbuffer* inbuffer, 
                  cal::Image2D& g0, cal::Image2D& g1, cal::Image2D& g2,
                  cal::Image2D& g3, cal::Image2D& g4, int size)
{
    CALuint pitch;
    uint32_t *p0, *p1, *p2, *p3, *p4;
    int i;

    p0 = (uint32_t*)self->dev_queue->mapMemObject(g0,pitch);
    p1 = (uint32_t*)self->dev_queue->mapMemObject(g1,pitch);
    p2 = (uint32_t*)self->dev_queue->mapMemObject(g2,pitch);
    p3 = (uint32_t*)self->dev_queue->mapMemObject(g3,pitch);
    p4 = (uint32_t*)self->dev_queue->mapMemObject(g4,pitch);

    for(i = 0; i < size; i++)
    {
        std::memcpy(p0, &inbuffer[i].ctx_ipad.h0, 4*4);
        std::memcpy(p1, &inbuffer[i].ctx_ipad.h4, 4*4);
        std::memcpy(p2, &inbuffer[i].ctx_opad.h3, 4*4);
        std::memcpy(p3, &inbuffer[i].e1.h2, 4*4);
        std::memcpy(p4, &inbuffer[i].e2.h1, 4*4);

        p0 += 4; p1 += 4;
        p2 += 4; p3 += 4;
        p4 += 4;
    }

    self->dev_queue->unmapMemObject(g0);
    self->dev_queue->unmapMemObject(g1);
    self->dev_queue->unmapMemObject(g2);
    self->dev_queue->unmapMemObject(g3);
    self->dev_queue->unmapMemObject(g4);
}

static void
copy_gpu_outbuffer(CALDevice* self, gpu_outbuffer* outbuffer,
                   cal::Image2D& g0, cal::Image2D& g1, int size)
{
    CALuint pitch;
    uint32_t *p0, *p1;
    int i;

    p0 = (uint32_t*)self->dev_queue->mapMemObject(g0, pitch);
    p1 = (uint32_t*)self->dev_queue->mapMemObject(g1, pitch);

    for(i = 0; i < size; i++)
    {
        std::memcpy(&outbuffer[i].pmk1.h0, p0, 4*4);
        std::memcpy(&outbuffer[i].pmk1.h4, p1, 4*4);

        p0 += 4; p1 += 4;
    }

    self->dev_queue->unmapMemObject(g0);
    self->dev_queue->unmapMemObject(g1);
}


static void
calc_pmklist(CALDevice *self, gpu_inbuffer *inbuffer, gpu_outbuffer* outbuffer, int size)
{
    cal::Image2D g_inbuffer0, g_inbuffer1, g_inbuffer2, g_inbuffer3, g_inbuffer4;
    cal::Image2D g_outbuffer0, g_outbuffer1, g_outbuffer2;
    int w, h;

    h = (size + CALPP_BLOCK_WIDTH - 1) / CALPP_BLOCK_WIDTH;
    w = CALPP_BLOCK_WIDTH * ((h + self->dev_maxheight - 1) / self->dev_maxheight);
    h = (size + w - 1) / w;

    // allocate gpu memory
    g_inbuffer0 = cal::Image2D(*self->dev_context, w, h, CAL_FORMAT_UINT_4, 0);
    g_inbuffer1 = cal::Image2D(*self->dev_context, w, h, CAL_FORMAT_UINT_4, 0);
    g_inbuffer2 = cal::Image2D(*self->dev_context, w, h, CAL_FORMAT_UINT_4, 0);
    g_inbuffer3 = cal::Image2D(*self->dev_context, w, h, CAL_FORMAT_UINT_4, 0);
    g_inbuffer4 = cal::Image2D(*self->dev_context, w, h, CAL_FORMAT_UINT_4, 0);
    g_outbuffer0 = cal::Image2D(*self->dev_context, w, h, CAL_FORMAT_UINT_4, 0);
    g_outbuffer1 = cal::Image2D(*self->dev_context, w, h, CAL_FORMAT_UINT_4, 0);

    copy_gpu_inbuffer(self, inbuffer, g_inbuffer0, g_inbuffer1, g_inbuffer2, g_inbuffer3, g_inbuffer4, size);

    // run kernel
    cal::NDRange rect(w,h);
    cal::Event event;

    self->dev_kernel->setArg(0, g_inbuffer0);
    self->dev_kernel->setArg(1, g_inbuffer1);
    self->dev_kernel->setArg(2, g_inbuffer2);
    self->dev_kernel->setArg(3, g_inbuffer3);
    self->dev_kernel->setArg(4, g_inbuffer4);
    self->dev_kernel->setArg(5, g_outbuffer0);
    self->dev_kernel->setArg(6, g_outbuffer1);

    self->dev_queue->enqueueNDRangeKernel(*self->dev_kernel, rect, &event);
    self->dev_queue->waitForEvent(event);

    copy_gpu_outbuffer(self, outbuffer, g_outbuffer0, g_outbuffer1, size);
}

static PyObject*
cpyrit_solve(CALDevice *self, PyObject *args)
{
    unsigned char essid[32+4], *passwd, pad[64], temp[32];
    int i, arraysize, essidlen, passwdlen;
    PyObject *essid_obj, *passwd_seq, *passwd_obj, *result;
    gpu_inbuffer *c_inbuffer, *t;
    gpu_outbuffer *c_outbuffer;
    SHA_CTX ctx_pad;

    if (!PyArg_ParseTuple(args, "OO", &essid_obj, &passwd_seq))
        return NULL;

    passwd_seq = PyObject_GetIter(passwd_seq);
    if (!passwd_seq)
        return NULL;

    essidlen = PyString_Size(essid_obj);
    if (essidlen < 1 || essidlen > 32)
    {
        Py_DECREF(passwd_seq);
        PyErr_SetString(PyExc_ValueError, "The ESSID must be a string between 1 and 32 characters");
        return NULL;
    }
    memcpy(essid, PyString_AsString(essid_obj), essidlen);
    memset(essid + essidlen, 0, sizeof(essid) - essidlen);

    arraysize = 0;
    c_inbuffer = NULL;
    c_outbuffer = NULL;    
    while ((passwd_obj = PyIter_Next(passwd_seq)))
    {
        if (arraysize % 1000 == 0)
        {
            t = (gpu_inbuffer*) PyMem_Realloc(c_inbuffer, sizeof(gpu_inbuffer)*(arraysize+1000));
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
        passwd = (unsigned char*)PyString_AsString(passwd_obj);
        passwdlen = PyString_Size(passwd_obj);
        if (passwd == NULL || passwdlen < 8 || passwdlen > 63)
        {
            Py_DECREF(passwd_obj);
            Py_DECREF(passwd_seq);
            PyMem_Free(c_inbuffer);
            PyErr_SetString(PyExc_ValueError, "All passwords must be strings between 8 and 63 characters");
            return NULL;
        }
        
        memcpy(pad, passwd, passwdlen);
        memset(pad + passwdlen, 0, sizeof(pad) - passwdlen);
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
        
        essid[essidlen + 4 - 1] = '\1';
        HMAC(EVP_sha1(), passwd, passwdlen, essid, essidlen + 4, temp, NULL);
        GET_BE(c_inbuffer[arraysize].e1.h0, temp, 0);
        GET_BE(c_inbuffer[arraysize].e1.h1, temp, 4);
        GET_BE(c_inbuffer[arraysize].e1.h2, temp, 8);
        GET_BE(c_inbuffer[arraysize].e1.h3, temp, 12);
        GET_BE(c_inbuffer[arraysize].e1.h4, temp, 16);

        essid[essidlen + 4 - 1] = '\2';
        HMAC(EVP_sha1(), passwd, passwdlen, essid, essidlen + 4, temp, NULL);
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
    if (!c_outbuffer)
    {
        PyMem_Free(c_inbuffer);
        return PyErr_NoMemory();
    }

    Py_BEGIN_ALLOW_THREADS;
    calc_pmklist(self, c_inbuffer, c_outbuffer, arraysize);
    Py_END_ALLOW_THREADS;
    PyMem_Free(c_inbuffer);

    result = PyTuple_New(arraysize);
    for (i = 0; i < arraysize; i++)
    {
        PUT_BE(c_outbuffer[i].pmk1.h0, temp, 0); PUT_BE(c_outbuffer[i].pmk1.h1, temp, 4);
        PUT_BE(c_outbuffer[i].pmk1.h2, temp, 8); PUT_BE(c_outbuffer[i].pmk1.h3, temp, 12); 
        PUT_BE(c_outbuffer[i].pmk1.h4, temp, 16);PUT_BE(c_outbuffer[i].pmk2.h0, temp, 20); 
        PUT_BE(c_outbuffer[i].pmk2.h1, temp, 24);PUT_BE(c_outbuffer[i].pmk2.h2, temp, 28); 
        PyTuple_SetItem(result, i, PyString_FromStringAndSize((char*)temp, 32));
    }

    PyMem_Free(c_outbuffer);

    return result;
}

static PyMemberDef CALDevice_members[] =
{
    {(char*)"deviceName", T_OBJECT, offsetof(CALDevice, dev_name), 0},
    {NULL}
};

static PyMethodDef CALDevice_methods[] =
{
    {"solve", (PyCFunction)cpyrit_solve, METH_VARARGS, "Calculate PMKs from ESSID and iterable of strings."},
    {NULL, NULL}
};

static PyTypeObject CALDevice_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_calpp.CALDevice",  /*tp_name*/
    sizeof(CALDevice),          /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)caldev_dealloc, /*tp_dealloc*/
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
    CALDevice_methods,          /*tp_methods*/
    CALDevice_members,          /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)caldev_init,      /*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};

static PyMethodDef CPyritCAL_methods[] = {
    {"listDevices", cpyrit_listDevices, METH_NOARGS, "Returns a tuple of tuples, each describing a CAL++ capable device."},
    {NULL, NULL, 0, NULL}
};

extern "C" PyMODINIT_FUNC init_cpyrit_calpp(void)
{
    PyObject *m;

    cal::Init();

    calContext = cal::Context(CAL_DEVICE_TYPE_GPU);
    calDevCount = calContext.getInfo<CAL_CONTEXT_DEVICES>().size();

    CALDevice_type.tp_getattro = PyObject_GenericGetAttr;
    CALDevice_type.tp_setattro = PyObject_GenericSetAttr;
    CALDevice_type.tp_alloc  = PyType_GenericAlloc;
    CALDevice_type.tp_new = PyType_GenericNew;
    CALDevice_type.tp_free = _PyObject_Del;
    if (PyType_Ready(&CALDevice_type) < 0)
        return;

    m = Py_InitModule("_cpyrit_calpp", CPyritCAL_methods);

    Py_INCREF(&CALDevice_type);
    PyModule_AddObject(m, "CALDevice", (PyObject*)&CALDevice_type);
    PyModule_AddStringConstant(m, "VERSION", VERSION);
}

