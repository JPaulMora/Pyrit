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
#include <stdint.h>
#include <openssl/hmac.h>

#define HMAC_MD5_RC4 0
#define HMAC_SHA1_AES 1


typedef struct
{
    PyObject_HEAD
    char keyscheme;
    unsigned char pke[100];
    unsigned char keymic[16];
    size_t eapolframe_size;
    unsigned char *eapolframe;
} EAPOLCracker;

static int
eapolcracker_init(EAPOLCracker *self, PyObject *args, PyObject *kwds)
{
    char *keyscheme;
    unsigned char *pke, *keymic, *eapolframe;
    int pke_len, keymic_size, eapolframe_size;

    self->eapolframe = NULL;
    if (!PyArg_ParseTuple(args, "ss#s#s#", &keyscheme, &pke, &pke_len, &keymic, &keymic_size, &eapolframe, &eapolframe_size))
        return -1;

    if (pke_len != 100)
    {
        PyErr_SetString(PyExc_ValueError, "PKE must be a string of exactly 100 bytes.");
        return -1;
    }
    memcpy(self->pke, pke, 100);
    
    if (keymic_size != 16)
    {
        PyErr_SetString(PyExc_ValueError, "KeyMIC must a string of 16 bytes.");
        return -1;
    }
    memcpy(self->keymic, keymic, 16);
    
    self->eapolframe_size = eapolframe_size;
    self->eapolframe = PyMem_Malloc(self->eapolframe_size);
    if (!self->eapolframe)
    {
        PyErr_NoMemory();
        return -1;
    }
    memcpy(self->eapolframe, eapolframe, self->eapolframe_size);
    
    if (strcmp(keyscheme, "HMAC_MD5_RC4") == 0) {
        self->keyscheme = HMAC_MD5_RC4;
    } else if (strcmp(keyscheme, "HMAC_SHA1_AES") == 0) {
        self->keyscheme = HMAC_SHA1_AES;
    } else {
        PyErr_SetString(PyExc_ValueError, "Invalid key-scheme.");
        return -1;
    }

    return 0;

}

static void
eapolcracker_dealloc(EAPOLCracker *self)
{
    if (self->eapolframe)
        PyMem_Free(self->eapolframe);
    PyObject_Del(self);
}


static PyObject *
eapolcracker_solve(EAPOLCracker *self, PyObject *args)
{
    PyObject *result_seq, *result_obj, **passwd_objbuffer, **t_obj, \
             *passwd_obj, *pmk_obj, *solution_obj;
    char *pmk;
    unsigned char *pmk_buffer, *t, mic_key[20], eapol_mic[20];
    Py_ssize_t buffersize;
    long i, itemcount;

    if (!PyArg_ParseTuple(args, "O", &result_seq))
        return NULL;

    result_seq = PyObject_GetIter(result_seq);
    if (!result_seq)
    {
        PyErr_NoMemory();
        return NULL;
    }
    
    pmk_buffer = NULL;
    passwd_objbuffer = NULL;
    passwd_obj = pmk_obj = solution_obj = NULL;
    itemcount = 0;
    buffersize = 0;
    while ((result_obj = PyIter_Next(result_seq)))
    {
        if (buffersize <= itemcount)
        {
            buffersize += 50000;
            t = PyMem_Realloc(pmk_buffer, buffersize*32);
            if (!t)
                goto out;
            pmk_buffer = t;
            t_obj = PyMem_Realloc(passwd_objbuffer, buffersize*sizeof(PyObject*));
            if (!t_obj)
                goto out;
            passwd_objbuffer = t_obj;
        }
        
        passwd_obj = PySequence_GetItem(result_obj, 0);
        if (!passwd_obj)
            goto out;
        passwd_objbuffer[itemcount] = passwd_obj;
        
        pmk_obj = PySequence_GetItem(result_obj, 1);
        if (!pmk_obj)
            goto out;
        pmk = PyString_AsString(pmk_obj);
        if (pmk == NULL || PyString_Size(pmk_obj) != 32)
        {
            PyErr_SetString(PyExc_ValueError, "All PMKs must be strings of 32 characters");
            Py_DECREF(pmk_obj);
            goto out;
        }
        memcpy(pmk_buffer + itemcount*32, pmk, 32);
        Py_DECREF(pmk_obj);
        
        itemcount += 1;
    }
    
    if (itemcount > 0)
    {
        Py_BEGIN_ALLOW_THREADS;
        for (i = 0; i < itemcount; i++)
        {
            HMAC(EVP_sha1(), &pmk_buffer[i*32], 32, self->pke, 100, mic_key, NULL);
            if (self->keyscheme == HMAC_MD5_RC4)
                HMAC(EVP_md5(), mic_key, 16, self->eapolframe, self->eapolframe_size, eapol_mic, NULL);
            else
                HMAC(EVP_sha1(), mic_key, 16, self->eapolframe, self->eapolframe_size, eapol_mic, NULL);
            if (memcmp(eapol_mic, self->keymic, 16) == 0)
            {
                solution_obj = passwd_objbuffer[i];
                break;
            }
        }
        Py_END_ALLOW_THREADS;
    }
    if (!solution_obj)
    {
        solution_obj = Py_None;
        Py_INCREF(solution_obj);
    }
    
    out:
    Py_DECREF(result_seq);
    if (pmk_buffer)
        PyMem_Free(pmk_buffer);
    if (itemcount > 0)
    {
        for (i = 0; i < itemcount; i++)
            Py_DECREF(passwd_objbuffer[i]);
        PyMem_Free(passwd_objbuffer);
    }
    return solution_obj;
}


static PyMethodDef EAPOLCracker_methods[] =
{
    {"solve", (PyCFunction)eapolcracker_solve, METH_VARARGS, "Try to find the password that corresponds to this instance's EAPOL-session from a iterable of (passwords,PMK)-tuples."},
    {NULL, NULL}
};

static PyTypeObject EAPOLCracker_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_pckttools.EAPOLCracker", /*tp_name*/
    sizeof(EAPOLCracker),       /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)eapolcracker_dealloc,   /*tp_dealloc*/
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
    (initproc)eapolcracker_init,/*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};

PyMODINIT_FUNC
init_cpyrit_pckttools(void)
{
    PyObject *m;

    EAPOLCracker_type.tp_getattro = PyObject_GenericGetAttr;
    EAPOLCracker_type.tp_setattro = PyObject_GenericSetAttr;
    EAPOLCracker_type.tp_alloc  = PyType_GenericAlloc;
    EAPOLCracker_type.tp_new = PyType_GenericNew;
    EAPOLCracker_type.tp_free = _PyObject_Del;  
    if (PyType_Ready(&EAPOLCracker_type) < 0)
	    return;
    
    m = Py_InitModule("_cpyrit_pckttools", NULL);

    Py_INCREF(&EAPOLCracker_type);
    PyModule_AddObject(m, "EAPOLCracker", (PyObject*)&EAPOLCracker_type);
}

