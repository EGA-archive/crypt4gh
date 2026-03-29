#include <Python.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>

static char module_name[] = "sodium";

#define NONCE_LEN   12
#define CIPHER_DIFF 28

static PyObject*
crypt4gh_chacha20poly1305_encrypt(PyObject* self, PyObject* args)
{
    PyObject *ciphersegment_obj, *segment_obj, *key_obj;
    uint8_t *ciphersegment, *segment, *key;
    Py_ssize_t ciphersegment_len, segment_len; //, key_len;
    unsigned long long clen;
    PyObject* ret;
    Py_buffer ciphersegment_view, segment_view, key_view;

    memset(&ciphersegment_view, 0, sizeof(ciphersegment_view));
    memset(&segment_view, 0, sizeof(segment_view));
    memset(&key_view, 0, sizeof(key_view));

    if (!PyArg_ParseTuple(args, "OOO",
			  &ciphersegment_obj,
			  &segment_obj,
			  &key_obj)) {
      PyErr_SetString(PyExc_TypeError, "All arguments must be buffer objects");
      return NULL;
    }

    ret = NULL;

    if (PyObject_GetBuffer(ciphersegment_obj, &ciphersegment_view, PyBUF_WRITABLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "ciphersegment must be writable");
      goto bailout;
    }

    if (PyObject_GetBuffer(segment_obj, &segment_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "segment buffer must be readable");
      goto bailout;
    }

    if (PyObject_GetBuffer(key_obj, &key_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "key buffer must be readable");
      goto bailout;
    }

    ciphersegment = (uint8_t *)ciphersegment_view.buf;
    ciphersegment_len = ciphersegment_view.len;
    segment = (uint8_t *)segment_view.buf;
    segment_len = segment_view.len;
    key = (uint8_t *)key_view.buf;
    //key_len = key_view.len;

    if (ciphersegment_len < segment_len + CIPHER_DIFF) {
      PyErr_SetString(PyExc_AssertionError, "Invalid buffer sizes");
      goto bailout;
    }

    randombytes_buf(ciphersegment, NONCE_LEN);

    if(crypto_aead_chacha20poly1305_ietf_encrypt(ciphersegment + NONCE_LEN, &clen,
						 segment, segment_len,
						 NULL, 0, NULL,
						 ciphersegment, key) != 0){
      PyErr_SetString(PyExc_ValueError, "Segment encryption failed");
      goto bailout;
    }

    ret = PyLong_FromUnsignedLongLong(clen + NONCE_LEN);
    /* fallthrough */

bailout:
    PyBuffer_Release(&ciphersegment_view);
    PyBuffer_Release(&segment_view);
    PyBuffer_Release(&key_view);
    return ret;
}

static PyObject*
crypt4gh_chacha20poly1305_decrypt(PyObject* self, PyObject* args)
{
    PyObject *ciphersegment_obj, *segment_obj, *key_obj;
    uint8_t *ciphersegment, *segment, *key;
    Py_ssize_t ciphersegment_len, segment_len; //, key_len;
    unsigned long long slen;
    PyObject* ret;
    Py_buffer ciphersegment_view, segment_view, key_view;

    memset(&ciphersegment_view, 0, sizeof(ciphersegment_view));
    memset(&segment_view, 0, sizeof(segment_view));
    memset(&key_view, 0, sizeof(key_view));

    if (!PyArg_ParseTuple(args, "OOO",
			  &segment_obj,
			  &ciphersegment_obj,
			  &key_obj)) {
      PyErr_SetString(PyExc_TypeError, "All arguments must be buffer objects");
      return NULL;
    }

    ret = NULL;

    if (PyObject_GetBuffer(segment_obj, &segment_view, PyBUF_WRITABLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "segment must be writable");
      goto bailout;
    }

    if (PyObject_GetBuffer(ciphersegment_obj, &ciphersegment_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "ciphersegment buffer must be readable");
      goto bailout;
    }

    if (PyObject_GetBuffer(key_obj, &key_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "key buffer must be readable");
      goto bailout;
    }

    ciphersegment = (uint8_t *)ciphersegment_view.buf;
    ciphersegment_len = ciphersegment_view.len;
    segment = (uint8_t *)segment_view.buf;
    segment_len = segment_view.len;
    key = (uint8_t *)key_view.buf;
    //key_len = key_view.len;

    if (segment_len < ciphersegment_len - CIPHER_DIFF) {
      PyErr_SetString(PyExc_AssertionError, "Invalid buffer sizes");
      goto bailout;
    }

    if(crypto_aead_chacha20poly1305_ietf_decrypt(segment, &slen,
						 NULL,
						 ciphersegment + NONCE_LEN, ciphersegment_len - NONCE_LEN,
						 NULL, 0, ciphersegment /* nonce */, key) != 0){
      PyErr_SetString(PyExc_ValueError, "Ciphersegment decryption failed");
      goto bailout;
    }

    ret = PyLong_FromUnsignedLongLong(slen);
    /* fallthrough */

bailout:
    PyBuffer_Release(&ciphersegment_view);
    PyBuffer_Release(&segment_view);
    PyBuffer_Release(&key_view);
    return ret;
}


static PyObject*
crypt4gh_kx_server(PyObject* self, PyObject* args)
{
    PyObject *server_public_key_obj, *server_secret_key_obj, *client_public_key_obj;
    Py_ssize_t server_public_key_len, server_secret_key_len, client_public_key_len;
    uint8_t *server_public_key, *server_secret_key, *client_public_key;
    Py_buffer server_public_key_view, server_secret_key_view, client_public_key_view;

    PyObject* ret = NULL;
    unsigned char shared_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char ignored[crypto_kx_SESSIONKEYBYTES];

    memset(&server_public_key_view, 0, sizeof(server_public_key_view));
    memset(&server_secret_key_view, 0, sizeof(server_secret_key_view));
    memset(&client_public_key_view, 0, sizeof(client_public_key_view));
    memset(shared_key, 0, crypto_kx_SESSIONKEYBYTES);

    if (!PyArg_ParseTuple(args, "OOO",
			  &server_public_key_obj,
			  &server_secret_key_obj,
			  &client_public_key_obj)) {
      PyErr_SetString(PyExc_TypeError, "All arguments must be buffer objects");
      return NULL;
    }

    if (PyObject_GetBuffer(server_public_key_obj, &server_public_key_view, PyBUF_SIMPLE) != 0 ||
	PyObject_GetBuffer(server_secret_key_obj, &server_secret_key_view, PyBUF_SIMPLE) != 0 ||
	PyObject_GetBuffer(client_public_key_obj, &client_public_key_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "buffers must be readable");
      goto bailout;
    }

    server_public_key = (uint8_t *)server_public_key_view.buf;
    server_public_key_len = server_public_key_view.len;
    server_secret_key = (uint8_t *)server_secret_key_view.buf;
    server_secret_key_len = server_secret_key_view.len;
    client_public_key = (uint8_t *)client_public_key_view.buf;
    client_public_key_len = client_public_key_view.len;

    if (server_public_key_len != crypto_kx_PUBLICKEYBYTES ||
	server_secret_key_len != crypto_kx_SECRETKEYBYTES ||
	client_public_key_len != crypto_kx_PUBLICKEYBYTES) {
      PyErr_SetString(PyExc_AssertionError, "Wrong key sizes");
      goto bailout;
    }

    if(crypto_kx_server_session_keys(ignored, shared_key,
				     server_public_key,
				     server_secret_key,
				     client_public_key) != 0){
      PyErr_SetString(PyExc_ValueError, "Server session key generation failed.");
    }

    ret = PyBytes_FromStringAndSize((const char*)shared_key, crypto_kx_SESSIONKEYBYTES);

bailout:
    PyBuffer_Release(&server_public_key_view);
    PyBuffer_Release(&server_secret_key_view);
    PyBuffer_Release(&client_public_key_view);
    return ret;
}

static PyObject*
crypt4gh_kx_client(PyObject* self, PyObject* args)
{
    PyObject *server_public_key_obj, *client_secret_key_obj, *client_public_key_obj;
    Py_ssize_t server_public_key_len, client_secret_key_len, client_public_key_len;

    uint8_t *server_public_key, *client_secret_key, *client_public_key;
    Py_buffer server_public_key_view, client_secret_key_view, client_public_key_view;

    PyObject* ret = NULL;
    unsigned char shared_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char ignored[crypto_kx_SESSIONKEYBYTES];

    memset(&client_public_key_view, 0, sizeof(client_public_key_view));
    memset(&client_secret_key_view, 0, sizeof(client_secret_key_view));
    memset(&server_public_key_view, 0, sizeof(server_public_key_view));
    memset(shared_key, 0, crypto_kx_SESSIONKEYBYTES);

    if (!PyArg_ParseTuple(args, "OOO",
			  &client_public_key_obj,
			  &client_secret_key_obj,
			  &server_public_key_obj)) {
      PyErr_SetString(PyExc_TypeError, "All arguments must be buffer objects");
      Py_RETURN_NONE;
    }

    if (PyObject_GetBuffer(client_public_key_obj, &client_public_key_view, PyBUF_SIMPLE) != 0 ||
	PyObject_GetBuffer(client_secret_key_obj, &client_secret_key_view, PyBUF_SIMPLE) != 0 ||
	PyObject_GetBuffer(server_public_key_obj, &server_public_key_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "buffers must be readable");
      goto bailout;
    }

    client_public_key = (uint8_t *)client_public_key_view.buf;
    client_public_key_len = client_public_key_view.len;
    client_secret_key = (uint8_t *)client_secret_key_view.buf;
    client_secret_key_len = client_secret_key_view.len;
    server_public_key = (uint8_t *)server_public_key_view.buf;
    server_public_key_len = server_public_key_view.len;

    if (client_public_key_len != crypto_kx_PUBLICKEYBYTES ||
	client_secret_key_len != crypto_kx_SECRETKEYBYTES ||
	server_public_key_len != crypto_kx_PUBLICKEYBYTES) {
      PyErr_SetString(PyExc_AssertionError, "Wrong key sizes");
      goto bailout;
    }

    if(crypto_kx_client_session_keys(shared_key, ignored,
				     client_public_key,
				     client_secret_key,
				     server_public_key) != 0){
      PyErr_SetString(PyExc_ValueError, "Client session key generation failed.");
    }

    ret = PyBytes_FromStringAndSize((const char*)shared_key, crypto_kx_SESSIONKEYBYTES);

bailout:
    PyBuffer_Release(&client_public_key_view);
    PyBuffer_Release(&client_secret_key_view);
    PyBuffer_Release(&server_public_key_view);
    return ret;
}

static PyObject*
crypt4gh_derive_pk(PyObject* self, PyObject* args)
{
    PyObject *n_obj;
    Py_buffer n_view;

    PyObject* ret = NULL;

    unsigned char q[crypto_scalarmult_BYTES];

    memset(&n_view, 0, sizeof(n_view));
    memset(&q, 0, sizeof(q));

    if (!PyArg_ParseTuple(args, "O", &n_obj)) {
      PyErr_SetString(PyExc_TypeError, "n must be a buffer object");
      return NULL;
    }

    if (PyObject_GetBuffer(n_obj, &n_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "n must be readable");
      goto bailout;
    }

    if (n_view.len != crypto_scalarmult_SCALARBYTES) {
      PyErr_SetString(PyExc_AssertionError, "wrong input size");
      goto bailout;
    }

    if(crypto_scalarmult_base(q, (unsigned char*)n_view.buf) != 0)
      PyErr_SetString(PyExc_RuntimeError, "can't derive public key from private key.");
    else
      ret = PyBytes_FromStringAndSize((const char*)q, crypto_scalarmult_BYTES);

bailout:
    PyBuffer_Release(&n_view);
    return ret;
}

static PyObject*
crypt4gh_sign_ed25519_pk_to_curve25519(PyObject* self, PyObject* args)
{
    PyObject *ed25519_pk_obj;
    Py_ssize_t ed25519_pk_len;
    uint8_t *ed25519_pk;
    Py_buffer ed25519_pk_view;

    PyObject* ret = NULL;
    unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES];

    memset(&ed25519_pk_view, 0, sizeof(ed25519_pk_view));
    memset(x25519_pk, 0, crypto_scalarmult_curve25519_BYTES);

    if (!PyArg_ParseTuple(args, "O",
			  &ed25519_pk_obj)) {
      PyErr_SetString(PyExc_TypeError, "ed25519 public key must be buffer objects");
      return NULL;
    }

    if (PyObject_GetBuffer(ed25519_pk_obj, &ed25519_pk_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "ed25519 public key must be readable");
      goto bailout;
    }

    ed25519_pk = (uint8_t *)ed25519_pk_view.buf;
    ed25519_pk_len = ed25519_pk_view.len;

    if (ed25519_pk_len != crypto_sign_ed25519_PUBLICKEYBYTES) {
      PyErr_SetString(PyExc_ValueError, "Invalid ed25519 public key size");
      goto bailout;
    }

    if(crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk) != 0)
      PyErr_SetString(PyExc_RuntimeError, "Can't convert ed25519 public key to curve25519.");
    else
      ret = PyBytes_FromStringAndSize((const char*)x25519_pk, crypto_scalarmult_curve25519_BYTES);

bailout:
    PyBuffer_Release(&ed25519_pk_view);
    return ret;
}

static PyObject*
crypt4gh_sign_ed25519_sk_to_curve25519(PyObject* self, PyObject* args)
{
    PyObject *ed25519_skpk_obj;
    Py_ssize_t ed25519_skpk_len;
    uint8_t *ed25519_skpk;
    Py_buffer ed25519_skpk_view;

    PyObject* ret = NULL;
    unsigned char x25519_sk[crypto_scalarmult_curve25519_BYTES];

    memset(&ed25519_skpk_view, 0, sizeof(ed25519_skpk_view));
    memset(x25519_sk, 0, crypto_scalarmult_curve25519_BYTES);

    if (!PyArg_ParseTuple(args, "O",
			  &ed25519_skpk_obj)) {
      PyErr_SetString(PyExc_TypeError, "ed25519 secret key must be buffer objects");
      return NULL;
    }

    if (PyObject_GetBuffer(ed25519_skpk_obj, &ed25519_skpk_view, PyBUF_SIMPLE) != 0) {
      PyErr_SetString(PyExc_BufferError, "ed25519 secret key must be readable");
      goto bailout;
    }

    ed25519_skpk = (uint8_t *)ed25519_skpk_view.buf;
    ed25519_skpk_len = ed25519_skpk_view.len;

    if (ed25519_skpk_len != crypto_sign_ed25519_SECRETKEYBYTES) {
      PyErr_SetString(PyExc_ValueError, "Invalid ed25519 secret key size");
      goto bailout;
    }

    if(crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_skpk) != 0)
      PyErr_SetString(PyExc_RuntimeError, "Can't convert ed25519 secret key to curve25519.");
    else
      ret = PyBytes_FromStringAndSize((const char*)x25519_sk, crypto_scalarmult_curve25519_BYTES);

bailout:
    PyBuffer_Release(&ed25519_skpk_view);
    return ret;
}

// Method definitions
static PyMethodDef methods[] = {
    {"chacha20poly1305_encrypt",
     crypt4gh_chacha20poly1305_encrypt,
     METH_VARARGS, "Encrypt data using ChaCha20-Poly1305"},
    {"chacha20poly1305_decrypt",
     crypt4gh_chacha20poly1305_decrypt,
     METH_VARARGS, "Decrypt data using ChaCha20-Poly1305"},
    {"kx_server",
     crypt4gh_kx_server,
     METH_VARARGS, "Generate shared key for the server."},
    {"kx_client",
     crypt4gh_kx_client,
     METH_VARARGS, "Generate shared key for the client."},
    {"derive_pk",
     crypt4gh_derive_pk,
     METH_VARARGS, "Generate shared key for the client."},
    {"sign_ed25519_pk_to_curve25519",
     crypt4gh_sign_ed25519_pk_to_curve25519,
     METH_VARARGS, "Converts a public Ed25519 key to a public Curve25519 key."},
    {"sign_ed25519_sk_to_curve25519",
     crypt4gh_sign_ed25519_sk_to_curve25519,
     METH_VARARGS, "Converts a secret Ed25519 key to a secret Curve25519 key."},

    {NULL, NULL, 0, NULL}
};


// Module definition
static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    module_name,
    NULL,
    -1,
    methods
};

// Module initialization
PyMODINIT_FUNC PyInit_sodium(void) {
    if (sodium_init() == -1) {
      return NULL;
    }
    return PyModule_Create(&module);
}
