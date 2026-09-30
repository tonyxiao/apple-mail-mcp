/* Native process boundary for Apple Mail FDA. Never exec a generic interpreter. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>
#include "runtime.h"

/* Trusted fixed bootstrap: service files are parsed as data, never sourced. */
static const char bootstrap[] =
"import os, shlex, stat\n"
"from urllib.parse import urlsplit\n"
"allowed = {'APPLE_MAIL_MCP_NAME', 'APPLE_MAIL_MCP_ORIGIN', 'APPLE_MAIL_MCP_HUB_ORIGIN', 'APPLE_MAIL_MCP_TOKEN_FILE', 'APPLE_MAIL_MCP_HOST', 'APPLE_MAIL_MCP_PORT', 'EMAIL_MCP_STATE_DIR', 'EMAIL_MCP_MAIL_DIR', 'EMAIL_MCP_READ_ONLY'}\n"
"def absolute(value):\n"
"    if not value or not os.path.isabs(value) or any(ord(c) < 32 for c in value):\n"
"        raise ValueError('helper configuration requires an absolute path')\n"
"    return value\n"
"explicit = os.environ.get('APPLE_MAIL_MCP_ENV_FILE')\n"
"path = absolute(explicit) if explicit else os.path.join(absolute(os.environ.get('HOME', '')), '.homebrew/services/apple-mail-mcp.env')\n"
"try:\n"
"    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n"
"except FileNotFoundError:\n"
"    if explicit: raise ValueError('helper configuration file is missing')\n"
"else:\n"
"    with os.fdopen(fd, 'r', encoding='utf-8') as stream:\n"
"        info = os.fstat(stream.fileno())\n"
"        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):\n"
"            raise ValueError('helper configuration must be owned by this user and private')\n"
"        content = stream.read(65537)\n"
"        if len(content) > 65536: raise ValueError('helper configuration is too large')\n"
"        seen = set()\n"
"        for line in content.splitlines():\n"
"            words = shlex.split(line, comments=True)\n"
"            if not words: continue\n"
"            if len(words) != 1 or '=' not in words[0]: raise ValueError('invalid helper configuration assignment')\n"
"            key, value = words[0].split('=', 1)\n"
"            if key not in allowed or key in seen: raise ValueError('unknown or duplicate helper configuration key')\n"
"            seen.add(key)\n"
"            os.environ[key] = value\n"
"for key in ('EMAIL_MCP_STATE_DIR', 'EMAIL_MCP_MAIL_DIR'):\n"
"    if key in os.environ: absolute(os.environ[key])\n"
"def origin(value):\n"
"    p = urlsplit(value)\n"
"    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.path or p.query or p.fragment or '*' in value or any(ord(c) < 33 for c in value):\n"
"        raise ValueError('helper origins must be exact HTTPS origins')\n"
"    return value\n"
"def http_args():\n"
"    name = os.environ.get('APPLE_MAIL_MCP_NAME', '')\n"
"    if name not in ('apple-mail-tx-m5', 'apple-mail-cs-mini'): raise ValueError('helper backend name must identify tx-m5 or cs-mini')\n"
"    if os.environ.get('APPLE_MAIL_MCP_HOST', '127.0.0.1') != '127.0.0.1' or os.environ.get('APPLE_MAIL_MCP_PORT', '58435') != '58435':\n"
"        raise ValueError('helper HTTP bind address and port are fixed')\n"
"    return ['http', '--host', '127.0.0.1', '--port', '58435', '--token-file', absolute(os.environ.get('APPLE_MAIL_MCP_TOKEN_FILE', '')), '--name', name, '--allowed-origin', origin(os.environ.get('APPLE_MAIL_MCP_ORIGIN', '')), '--allowed-origin', origin(os.environ.get('APPLE_MAIL_MCP_HUB_ORIGIN', 'https://mcphub.meteor-ruffe.ts.net'))]\n";

static int append_path(PyConfig *config, const char *path) {
    wchar_t *wide = Py_DecodeLocale(path, NULL);
    if (wide == NULL) return -1;
    PyStatus status = PyWideStringList_Append(&config->module_search_paths, wide);
    PyMem_RawFree(wide);
    return PyStatus_Exception(status) ? -1 : 0;
}

static int append_arg(PyObject *list, const char *value) {
    PyObject *arg = PyUnicode_DecodeFSDefault(value);
    if (arg == NULL) return -1;
    int result = PyList_Append(list, arg);
    Py_DECREF(arg);
    return result;
}

int main(int argc, char **argv) {
    enum { HTTP, FTS, STDIO, SQL } mode = HTTP;
    if (argc == 2 && strcmp(argv[1], "--fts") == 0) mode = FTS;
    else if (argc == 2 && strcmp(argv[1], "--stdio") == 0) mode = STDIO;
    else if (argc >= 3 && strcmp(argv[1], "--sql") == 0 &&
             (strcmp(argv[2], "query") == 0 || strcmp(argv[2], "schema") == 0)) mode = SQL;
    else if (argc != 1) {
        fputs("usage: apple-mayo-mcp [--fts | --stdio | --sql query/schema ...]\n", stderr);
        return 2;
    }
    char invoked_path[PATH_MAX], binary_path[PATH_MAX];
    uint32_t path_size = sizeof(invoked_path);
    if (_NSGetExecutablePath(invoked_path, &path_size) != 0 ||
        realpath(invoked_path, binary_path) == NULL) {
        fputs("helper native executable path cannot be resolved\n", stderr);
        return 2;
    }
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.use_environment = 0;
    config.site_import = 0;
    config.user_site_directory = 0;
    config.safe_path = 1;
    config.parse_argv = 0;
    config.install_signal_handlers = 1;
    config.write_bytecode = 0;
    config.module_search_paths_set = 1;
    PyStatus status = PyConfig_SetBytesString(&config, &config.home, HELPER_PYTHON_HOME);
    if (!PyStatus_Exception(status)) status = PyConfig_SetBytesString(&config, &config.program_name, binary_path);
    if (!PyStatus_Exception(status)) status = PyConfig_SetBytesString(&config, &config.executable, binary_path);
    if (PyStatus_Exception(status) || append_path(&config, HELPER_STDLIB) < 0 ||
        append_path(&config, HELPER_DYNLOAD) < 0 || append_path(&config, HELPER_SITE_PACKAGES) < 0) {
        PyConfig_Clear(&config);
        fputs("helper runtime configuration failed\n", stderr);
        return 2;
    }
    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        fputs("helper embedded runtime initialization failed\n", stderr);
        return 2;
    }
    PyObject *globals = PyDict_New();
    PyObject *configured = globals ? PyRun_String(bootstrap, Py_file_input, globals, globals) : NULL;
    PyObject *args = NULL, *module = NULL, *function = NULL, *result = NULL;
    int exit_code = 2;
    if (configured == NULL) goto finish;
    Py_DECREF(configured);
    if (mode == HTTP) {
        PyObject *make_args = PyDict_GetItemString(globals, "http_args");
        args = PyObject_CallNoArgs(make_args);
    } else {
        args = PyList_New(0);
        if (args == NULL) goto finish;
        if (mode == FTS) {
            const char *fixed[] = {"fts", "--sync", "--limit", "2000"};
            for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
                if (append_arg(args, fixed[i]) < 0) goto finish;
        } else if (mode == STDIO) {
            if (append_arg(args, "serve") < 0) goto finish;
        } else {
            if (append_arg(args, "sql") < 0) goto finish;
            for (int i = 2; i < argc; i++) if (append_arg(args, argv[i]) < 0) goto finish;
        }
    }
    if (args == NULL) goto finish;
    module = PyImport_ImportModule("email_mcp.cli");
    if (module == NULL) goto finish;
    function = PyObject_GetAttrString(module, "main");
    if (function == NULL) goto finish;
    result = PyObject_CallOneArg(function, args);
    if (result != NULL) exit_code = (int)PyLong_AsLong(result);
finish:
    if (PyErr_Occurred()) {
        /* CLI argparse SystemExit is rendered by Python without a traceback. */
        PyErr_Print();
        exit_code = 2;
    }
    Py_XDECREF(result);
    Py_XDECREF(function);
    Py_XDECREF(module);
    Py_XDECREF(args);
    Py_XDECREF(globals);
    if (Py_FinalizeEx() < 0 && exit_code == 0) exit_code = 120;
    return exit_code;
}
