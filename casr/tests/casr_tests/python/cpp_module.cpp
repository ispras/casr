#define PY_SSIZE_T_CLEAN
#include <Python.h>

static PyObject *
df(PyObject *self, PyObject *args) {
    int* a = (int*)malloc(sizeof(int));
    free(a);
    free(a);
    return PyLong_FromLong(0);
}

static PyMethodDef Methods[] = {
    {"df", df, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef cpp_module = {
    PyModuleDef_HEAD_INIT,
    "cpp_module",
    NULL,
    -1,
    Methods
};

PyMODINIT_FUNC
PyInit_cpp_module(void) {
    return PyModule_Create(&cpp_module);
}
