/*
 * Samba 4.x VFS module for database-backed virtual filesystem
 * Communicates with Python DB VFS service via JSON over Unix socket
 */
#undef TRACIM_DEBUG
// Set in smb.conf "log level = 3 vfs:10"
#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/sys_rw.h"
#include "smbd/fd_handle.h"
#include <jansson.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

extern NTSTATUS smb_register_vfs(int version, const char *name, const struct vfs_fn_pointers *fns);

#ifdef __cplusplus
extern "C" {
#endif
        #include <errno.h>
	#include <stdio.h>
	#include <stdarg.h> // for variable number of arguments in functions
#ifdef __cplusplus
}
#endif

#ifdef TRACIM_DEBUG
	#define LOG_DEBUG1(...) fprintf(stdout,__VA_ARGS__)
	#define LOG_DEBUG2(...) fprintf(stdout,__VA_ARGS__)

	#define WHERESTR  "[file %s, line %d]: "
	#define DEBUGPRINT(...)  DEBUG2(WHERESTR _fmt, __FILE__, __LINE__, __VA_ARGS__)
#else
	#define LOG_DEBUG_(msg)
	#define LOG_DEBUG1(...)
	#define LOG_DEBUG2(...)   
#endif

#define LOG_ERR 1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_DEBUG 4
#define LOG_TRACE 5

#ifdef MAIN_FILE
int log_level;
#else
extern int log_level;
#endif

#ifndef SMB_VFS_INTERFACE_VERSION
#error "SMB_VFS_INTERFACE_VERSION not defined"
#endif

#define DB_VFS_SOCKET_PATH "/srv/tracim/samba_vfs_tracim_service.sock"
#define MAX_RESPONSE_SIZE 65536
#define MAX_REQUEST_SIZE 32768

/* VFS module data structure */
struct tracim_data {
    int socket_fd;
    bool connected;
    char *socket_path;
    char *connection_string;
	char *user;
};

/* Helper function to get module data */
static struct tracim_data *get_tracim_data(vfs_handle_struct *handle)
{
	LOG_DEBUG1("Tracim: get_tracim_data().\n");
    struct tracim_data *data;
    
    SMB_VFS_HANDLE_GET_DATA(handle, data, struct tracim_data, return NULL);
	if(!data) {
		LOG_DEBUG1("Tracim: tracim_openat() - No tracim data found.\n");
		return NULL;
	}
    return data;
}

/* Connect to Unix socket */
static int connect_to_service(struct tracim_data *data)
{
	LOG_DEBUG1("Tracim: connect_to_service().\n");
    struct sockaddr_un addr;
    int ret;
    
    if (data->connected && data->socket_fd >= 0) {
        return 0; /* Already connected */
    }
    
    /* Close existing socket if any */
    if (data->socket_fd >= 0) {
        close(data->socket_fd);
    }
    
    data->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (data->socket_fd < 0) {
        DEBUG(0, ("tracim: Failed to create socket: %s\n", strerror(errno)));
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, data->socket_path, sizeof(addr.sun_path) - 1);
    
    ret = connect(data->socket_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        DEBUG(0, ("tracim: Failed to connect to %s: %s\n", 
                  data->socket_path, strerror(errno)));
        close(data->socket_fd);
        data->socket_fd = -1;
        data->connected = false;
        return -1;
    }
    
    data->connected = true;
    DEBUG(5, ("tracim: Connected to service at %s\n", data->socket_path));
    return 0;
}

/* Send JSON request and receive response */
static json_t *send_request(struct tracim_data *data, json_t *request)
{
	LOG_DEBUG1("Tracim: send_request().\n");
    char *request_str;
    char response_buf[MAX_RESPONSE_SIZE];
    ssize_t bytes_sent, bytes_received;
    json_t *response = NULL;
    json_error_t error;
    
    if (connect_to_service(data) < 0) {
        return NULL;
    }
    
    request_str = json_dumps(request, JSON_COMPACT);
    if (!request_str) {
        DEBUG(0, ("tracim: Failed to serialize JSON request\n"));
        return NULL;
    }
    
    /* Send request */
    bytes_sent = send(data->socket_fd, request_str, strlen(request_str), 0);
    if (bytes_sent < 0) {
        DEBUG(0, ("tracim: Failed to send request: %s\n", strerror(errno)));
        data->connected = false;
        free(request_str);
        return NULL;
    }
    
    /* Send newline delimiter */
    send(data->socket_fd, "\n", 1, 0);
    free(request_str);
    
    /* Receive response */
    bytes_received = recv(data->socket_fd, response_buf, sizeof(response_buf) - 1, 0);
    if (bytes_received < 0) {
        DEBUG(0, ("tracim: Failed to receive response: %s\n", strerror(errno)));
        data->connected = false;
        return NULL;
    }
    
    response_buf[bytes_received] = '\0';
    
    /* Parse JSON response */
    response = json_loads(response_buf, 0, &error);
    if (!response) {
        DEBUG(0, ("tracim: Failed to parse JSON response: %s\n", error.text));
        return NULL;
    }
    
    return response;
}

/* VFS operations */

static int tracim_connect(vfs_handle_struct *handle, const char *service, const char *user)
{
	LOG_DEBUG1("Tracim: tracim_connect().\n");
    DEBUG(0, ("tracim: tracim_connect(%s)\n", user));
    struct tracim_data *data;
    const char *socket_path;
    
    data = talloc_zero(handle, struct tracim_data);
    if (!data) {
        DEBUG(0, ("tracim: Failed to allocate memory\n"));
        return -1;
    }
    data->user = talloc_strdup(data->user, user);
    const char *connection_string = lp_parm_const_string(SNUM(handle->conn), "tracim", "connection_string", NULL);
    if (connection_string) {
        data->connection_string = talloc_strdup(data, connection_string);
        DEBUG(0, ("tracim: Using connection string: %s\n", data->connection_string));
    } else {
        DEBUG(0, ("tracim: No connection string specified in config\n"));
        data->connection_string = NULL;
    }

    /* Get socket path from config, default to DB_VFS_SOCKET_PATH */
    socket_path = lp_parm_const_string(SNUM(handle->conn), "tracim", "socket_path", DB_VFS_SOCKET_PATH);
    data->socket_path = talloc_strdup(data, socket_path);
    data->socket_fd = -1;
    data->connected = false;
    
    SMB_VFS_HANDLE_SET_DATA(handle, data, NULL, struct tracim_data, return -1);
    
    DEBUG(0, ("tracim: Connected to service %s, socket: %s\n", service, socket_path));
    return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void tracim_disconnect(vfs_handle_struct *handle)
{
	LOG_DEBUG1("Tracim: tracim_disconnect().\n");
    struct tracim_data *data = get_tracim_data(handle);
    
    if (data && data->socket_fd >= 0) {
        close(data->socket_fd);
        data->socket_fd = -1;
        data->connected = false;
    }
    
    SMB_VFS_NEXT_DISCONNECT(handle);
}

static int tracim_openat(vfs_handle_struct *handle,
                         const struct files_struct *dirfsp,
                         const struct smb_filename *smb_fname,
                         files_struct *fsp,
                         const struct vfs_open_how *how)
{
    struct tracim_data *data = get_tracim_data(handle);
    DEBUG(0, ("Tracim: tracim_openat(%s).\n", data->user));
    json_t *request, *response, *success_obj, *fd_obj;
    int result = -1;

    if (!data) {
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "op", json_string("open"));
    json_object_set_new(request, "path", json_string(smb_fname->base_name));
    json_object_set_new(request, "flags", json_integer(how->flags));
    json_object_set_new(request, "mode", json_integer(how->mode));
    
    /* Send request */
    response = send_request(data, request);
    json_decref(request);
    
    if (!response) {
        DEBUG(3, ("tracim: Failed to get response for open, falling back to next VFS\n"));
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
    
    /* Parse response */
    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
        fd_obj = json_object_get(response, "fd");
        if (fd_obj && json_is_integer(fd_obj)) {
            result = json_integer_value(fd_obj);
            DEBUG(5, ("tracim: Successfully opened %s, fd=%d\n", smb_fname->base_name, result));
        }
    } else {
        DEBUG(3, ("tracim: Open failed for %s, falling back to next VFS\n", smb_fname->base_name));
        json_decref(response);
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
    
    json_decref(response);
    return result >= 0 ? result : SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
}

static int tracim_close(vfs_handle_struct *handle, files_struct *fsp)
{
	DEBUG(0, ("Tracim: tracim_close().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    json_t *request, *response, *success_obj;
    int result = 0;
    
    if (!data) {
        return SMB_VFS_NEXT_CLOSE(handle, fsp);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "op", json_string("close"));
    json_object_set_new(request, "fd", json_integer(fsp_get_io_fd(fsp)));
    
    /* Send request */
    response = send_request(data, request);
    json_decref(request);
    
    if (response) {
        success_obj = json_object_get(response, "success");
        if (success_obj) {
            result = json_is_true(success_obj) ? 0 : -1;
        }
        json_decref(response);
    }
    
    return SMB_VFS_NEXT_CLOSE(handle, fsp);
}

static ssize_t tracim_pread(vfs_handle_struct *handle, files_struct *fsp, 
                            void *data_buf, size_t n, off_t offset)
{
	DEBUG(0, ("Tracim: tracim_pread().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    json_t *request, *response, *success_obj, *data_obj;
    ssize_t result = -1;
    const char *encoded_data;
    
    if (!data) {
        return SMB_VFS_NEXT_PREAD(handle, fsp, data_buf, n, offset);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "op", json_string("read"));
    json_object_set_new(request, "fd", json_integer(fsp_get_io_fd(fsp)));
    json_object_set_new(request, "size", json_integer(n));
    json_object_set_new(request, "offset", json_integer(offset));
    
    /* Send request */
    response = send_request(data, request);
    json_decref(request);
    
    if (!response) {
        return SMB_VFS_NEXT_PREAD(handle, fsp, data_buf, n, offset);
    }
    
    /* Parse response */
    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
        data_obj = json_object_get(response, "data");
        if (data_obj && json_is_string(data_obj)) {
            encoded_data = json_string_value(data_obj);
            if (encoded_data) {
                /* Decode base64 data */
                size_t decoded_len = strlen(encoded_data) * 3 / 4; /* Rough estimate */
                if (decoded_len <= n) {
                    /* Simple base64 decode - in production use proper base64 library */
                    memcpy(data_buf, encoded_data, strlen(encoded_data));
                    result = strlen(encoded_data);
                }
            }
        }
    }
    
    json_decref(response);
    return result >= 0 ? result : SMB_VFS_NEXT_PREAD(handle, fsp, data_buf, n, offset);
}

static ssize_t tracim_pwrite(vfs_handle_struct *handle, files_struct *fsp,
                             const void *data_buf, size_t n, off_t offset)
{
	DEBUG(0, ("Tracim: tracim_pwrite().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    json_t *request, *response, *success_obj, *bytes_obj;
    ssize_t result = -1;
    char *encoded_data;
    
    if (!data) {
        return SMB_VFS_NEXT_PWRITE(handle, fsp, data_buf, n, offset);
    }
    
    /* Encode data as base64 - simplified version */
    encoded_data = talloc_array(NULL, char, n * 2); /* Rough size */
    if (!encoded_data) {
        return SMB_VFS_NEXT_PWRITE(handle, fsp, data_buf, n, offset);
    }
    
    /* Simple encoding - in production use proper base64 library */
    memcpy(encoded_data, data_buf, n);
    encoded_data[n] = '\0';
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "op", json_string("write"));
    json_object_set_new(request, "fd", json_integer(fsp_get_io_fd(fsp)));
    json_object_set_new(request, "data", json_string(encoded_data));
    json_object_set_new(request, "offset", json_integer(offset));
    
    /* Send request */
    response = send_request(data, request);
    json_decref(request);
    talloc_free(encoded_data);
    
    if (!response) {
        return SMB_VFS_NEXT_PWRITE(handle, fsp, data_buf, n, offset);
    }
    
    /* Parse response */
    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
        bytes_obj = json_object_get(response, "bytes_written");
        if (bytes_obj && json_is_integer(bytes_obj)) {
            result = json_integer_value(bytes_obj);
        }
    }
    
    json_decref(response);
    return result >= 0 ? result : SMB_VFS_NEXT_PWRITE(handle, fsp, data_buf, n, offset);
}

static int tracim_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    struct tracim_data *data = get_tracim_data(handle);
	DEBUG(0, ("Tracim: tracim_stat(%s, %s).\n", data->user, smb_fname->base_name));
    json_t *request, *response, *success_obj, *stat_obj;
    int result = -1;
    
    if (!data) {
        return SMB_VFS_NEXT_STAT(handle, smb_fname);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "op", json_string("stat"));
    json_object_set_new(request, "user", json_string(data->user));
    json_object_set_new(request, "path", json_string(smb_fname->base_name));
    
    /* Send request */
    response = send_request(data, request);
    json_decref(request);
    
    if (!response) {
        return SMB_VFS_NEXT_STAT(handle, smb_fname);
    }
    
    /* Parse response */
    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
        stat_obj = json_object_get(response, "stat");
        if (stat_obj && json_is_object(stat_obj)) {
            json_t *size_obj, *mode_obj, *mtime_obj;
            
            /* Parse stat information */
            size_obj = json_object_get(stat_obj, "size");
            if (size_obj && json_is_integer(size_obj)) {
                smb_fname->st.st_ex_size = json_integer_value(size_obj);
            }
            mode_obj = json_object_get(stat_obj, "mode");
            if (mode_obj && json_is_integer(mode_obj)) {
                smb_fname->st.st_ex_mode = json_integer_value(mode_obj);
            }
            mtime_obj = json_object_get(stat_obj, "mtime");
            if (mtime_obj && json_is_integer(mtime_obj)) {
                smb_fname->st.st_ex_mtime.tv_sec = json_integer_value(mtime_obj);
            }
            
            result = 0;
        }
    }
    
    json_decref(response);
    return result >= 0 ? result : SMB_VFS_NEXT_STAT(handle, smb_fname);
}

static int tracim_unlinkat(vfs_handle_struct *handle,
                           struct files_struct *dirfsp,
                           const struct smb_filename *smb_fname,
                           int flags)
{
	DEBUG(0, ("Tracim: tracim_unlinkat().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    json_t *request, *response, *success_obj;
    int result = -1;
    
    if (!data) {
        return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "op", json_string("unlink"));
    json_object_set_new(request, "path", json_string(smb_fname->base_name));
    json_object_set_new(request, "flags", json_integer(flags));
    
    /* Send request */
    response = send_request(data, request);
    json_decref(request);
    
    if (!response) {
        return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
    }
    
    /* Parse response */
    success_obj = json_object_get(response, "success");
    if (success_obj) {
        result = json_is_true(success_obj) ? 0 : -1;
    }
    
    json_decref(response);
    return result >= 0 ? result : SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
}

/* VFS operations structure for Samba 4.x */
static struct vfs_fn_pointers tracim_functions = {
    .connect_fn = tracim_connect,
    .disconnect_fn = tracim_disconnect,
    .openat_fn = tracim_openat,
    .close_fn = tracim_close,
    .pread_fn = tracim_pread,
    .pwrite_fn = tracim_pwrite,
    .stat_fn = tracim_stat,
    .unlinkat_fn = tracim_unlinkat,
};

NTSTATUS vfs_tracim_init(TALLOC_CTX *ctx)
{
	DEBUG(0, ("tracim: vfs_tracim_init()\n"));
	NTSTATUS (*real_smb_register_vfs)(int, const char *, const struct vfs_fn_pointers *);
	real_smb_register_vfs = dlsym(RTLD_DEFAULT, "smb_register_vfs");
    if (!real_smb_register_vfs) {
        DEBUG(0, ("Could not find smb_register_vfs in main process\n"));
        return NT_STATUS_UNSUCCESSFUL;
    }

	NTSTATUS status = real_smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "tracim", &tracim_functions);
    if (!NT_STATUS_IS_OK(status)) {
        DEBUG(0, ("tracim: Failed to register VFS module: %s\n", nt_errstr(status)));
    } else {
        DEBUG(0, ("tracim: VFS module registered successfully\n"));
    }
	return status;
}