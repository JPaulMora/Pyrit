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

#include "_cpyrit_cuda.h"

int cudaDevCount;
cudaDevContext *cudaDevices;

//Will be compiled by nvcc and linked in
int calc_pmklist(gpu_inbuffer *inbuffer, gpu_outbuffer *outbuffer, int buffersize);

PyObject* cpyrit_listDevices(PyObject* self, PyObject* args)
{
    int i;
    PyObject* result;
    if (!PyArg_ParseTuple(args, "")) return NULL;
    
    result = PyTuple_New(cudaDevCount);
    for (i = 0; i < cudaDevCount; i++)
    {
        PyTuple_SetItem(result, i, Py_BuildValue("(siiii)", &cudaDevices[i].properties.name,
                                                cudaDevices[i].properties.totalGlobalMem, cudaDevices[i].properties.regsPerBlock, 
                                                cudaDevices[i].properties.clockRate, cudaDevices[i].properties.multiProcessorCount));
    }

    return result;
}

// Sets CUDA-device for the current thread.
PyObject* cpyrit_setDevice(PyObject* self, PyObject* args)
{
    int cudaDev, cudaDev_new;
    if (!PyArg_ParseTuple(args, "i", &cudaDev_new)) return NULL;

    if (cudaDev_new < 0 || cudaDev_new > cudaDevCount-1)
    {
        PyErr_SetString(PyExc_SystemError, "Invalid device number");
        return NULL;
    }

    if (cudaSetDevice(cudaDev_new) != cudaSuccess)
    {
        if (cudaGetDevice(&cudaDev) != cudaSuccess)
        {
            PyErr_SetString(PyExc_SystemError, "Failed to get/set new device.");
            return NULL;
        }
        if (cudaDev_new != cudaDev)
        {
            PyErr_SetString(PyExc_SystemError, "Failed to set new device.");
            return NULL;
        }
    }

    return Py_BuildValue("i", cudaDev_new);
}

PyObject *cpyrit_pmklist(PyObject *self, PyObject *args)
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

    Py_BEGIN_ALLOW_THREADS;
    ret = calc_pmklist(c_inbuffer, c_outbuffer, numLines);
    Py_END_ALLOW_THREADS;
    
    free(c_inbuffer);

    if (ret != cudaSuccess)
    {
        PyErr_SetString(PyExc_IOError, cudaGetErrorString(ret));
        free(c_outbuffer);
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

static PyMethodDef CPyritCUDAMethods[] = {
    {"calc_pmklist", cpyrit_pmklist, METH_VARARGS, "Calculate PMKs from ESSID and list of strings"},
    {"setDevice", cpyrit_setDevice, METH_VARARGS, "Binds the current thread to the given device. Can only be called once per thread."},
    {"listDevices", cpyrit_listDevices, METH_VARARGS, "Returns a tuple to tuples, each describing a CUDA-capable device."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_cpyrit_cuda(void)
{
    int ret, i;

    ret = cudaGetDeviceCount(&cudaDevCount);
    if (ret != cudaSuccess || cudaDevCount < 1)
    {
        PyErr_SetString(PyExc_ImportError, "CUDA seems to be unavailable or no device reported.");
        return;
    }
    
    cudaDevices = malloc(cudaDevCount * (sizeof(cudaDevContext)));
    for (i = 0; i < cudaDevCount; i++)
    {
        cudaGetDeviceProperties(&cudaDevices[i].properties, i);
        cudaDevices[i].device = i;
    }
    
    ret = cudaGetLastError();
    if (ret != cudaSuccess)
    {
        PyErr_SetString(PyExc_ImportError, cudaGetErrorString(ret));
        return;
    }

    (void) Py_InitModule("_cpyrit_cuda", CPyritCUDAMethods);
}

int
main(int argc, char *argv[])
{
    Py_Initialize();

    init_cpyrit_cuda();

    return -1;
}
