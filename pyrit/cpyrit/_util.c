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

/*
def _genCowpEntries(self, res):
    return ''.join(map(''.join, [(chr(len(passwd) + 32 + 1), passwd, pmk) for passwd, pmk in res]))
*/
static PyObject *
util_gencowpentries(PyObject *self, PyObject *args)
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
                goto errout;
            cowpbuffer = t;
        }
        passwd_obj = PySequence_GetItem(result_obj, 0);
        if (!passwd_obj)
            goto errout;
        passwd = PyString_AsString(passwd_obj);
        passwd_length = PyString_Size(passwd_obj);
        if (passwd == NULL || passwd_length < 8 || passwd_length > 63)
        {
            PyErr_SetString(PyExc_ValueError, "All passwords must be strings between 8 and 63 characters");
            goto errout;
        }
        pmk_obj = PySequence_GetItem(result_obj, 1);
        if (!pmk_obj)
            goto errout;
        pmk = PyString_AsString(pmk_obj);
        if (pmk == NULL || PyString_Size(pmk_obj) != 32)
        {
            PyErr_SetString(PyExc_ValueError, "All PMKs must be strings of 32 characters");
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
    Py_XDECREF(passwd_obj);
    Py_XDECREF(pmk_obj);
    PyMem_Free(cowpbuffer);
    return NULL;
}

static PyMethodDef UtilMethods[] = {
    {"genCowpEntries", util_gencowpentries, METH_VARARGS, "Generate a data-string in cowpatty-like format from a iterable of password:PMK tuples."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_util(void)
{
    PyModule_AddStringConstant(Py_InitModule("_util", UtilMethods), "VERSION", VERSION);
}

