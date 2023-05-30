#include "AspectExtend.h"
#include "Initializer/Initializer.h"
#include <iostream> // FIXME: remove

PyObject *api_extend_aspect(PyObject *self, PyObject *const *args,
                            Py_ssize_t nargs) {
    if (nargs != 2 or !args) {
        // TODO: any other more sane error handling?
        return nullptr;
    }

    PyObject *candidate_text = args[0];
    auto len_candidate_text = PyByteArray_Size(candidate_text);
    PyObject *to_add = args[1];
    // TODO: Check if this works with bytes and bytearrays or we have to convert
    // bytes to a new bytearray!
    auto method_name = PyUnicode_FromString("extend");
    PyObject_CallMethodOneArg(candidate_text, method_name, to_add);
    Py_DecRef(method_name);  // TODO: check if right
    auto ctx_map = initializer->get_tainting_map();
    if (not ctx_map or ctx_map->empty()) {
        Py_RETURN_NONE;
    }

    const auto &to_candidate = get_tainted_object(candidate_text, ctx_map);
    auto to_result = initializer->allocate_tainted_object(to_candidate);
    const auto &to_toadd = get_tainted_object(to_add, ctx_map);
    if (to_toadd) {
        to_result->add_ranges_shifted(to_toadd, (long) len_candidate_text);
    }
    set_tainted_object(candidate_text, to_result, ctx_map);
    Py_RETURN_NONE;
}
