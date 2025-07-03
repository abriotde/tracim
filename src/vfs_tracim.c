/*
 * Samba 4.x VFS module for database-backed virtual filesystem
 * Communicates with Python DB VFS service via JSON over Unix socket
 */

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

#define DB_VFS_SOCKET_PATH "/var/run/db_vfs.sock"
#define MAX_RESPONSE_SIZE 65536
#define MAX_REQUEST_SIZE 32768

/* VFS module data structure */
struct db_vfs_data {
    int socket_fd;
    bool connected;
    char *socket_path;
};

/* Helper function to get module data */
static struct db_vfs_data *get_db_vfs_data(vfs_handle_struct *handle)
{
    struct db_vfs_data *data;
    
    SMB_VFS_HANDLE_GET_DATA(handle, data, struct db_vfs_data, return NULL);
    return data;
}

/* Connect to Unix socket */
static int connect_to_service(struct db_vfs_data *data)
{
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
        DEBUG(0, ("db_vfs: Failed to create socket: %s\n", strerror(errno)));
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, data->socket_path, sizeof(addr.sun_path) - 1);
    
    ret = connect(data->socket_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        DEBUG(0, ("db_vfs: Failed to connect to %s: %s\n", 
                  data->socket_path, strerror(errno)));
        close(data->socket_fd);
        data->socket_fd = -1;
        data->connected = false;
        return -1;
    }
    
    data->connected = true;
    DEBUG(5, ("db_vfs: Connected to service at %s\n", data->socket_path));
    return 0;
}

/* Send JSON request and receive response */
static json_t *send_request(struct db_vfs_data *data, json_t *request)
{
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
        DEBUG(0, ("db_vfs: Failed to serialize JSON request\n"));
        return NULL;
    }
    
    /* Send request */
    bytes_sent = send(data->socket_fd, request_str, strlen(request_str), 0);
    if (bytes_sent < 0) {
        DEBUG(0, ("db_vfs: Failed to send request: %s\n", strerror(errno)));
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
        DEBUG(0, ("db_vfs: Failed to receive response: %s\n", strerror(errno)));
        data->connected = false;
        return NULL;
    }
    
    response_buf[bytes_received] = '\0';
    
    /* Parse JSON response */
    response = json_loads(response_buf, 0, &error);
    if (!response) {
        DEBUG(0, ("db_vfs: Failed to parse JSON response: %s\n", error.text));
        return NULL;
    }
    
    return response;
}

/* VFS operations */

static int db_vfs_connect(vfs_handle_struct *handle, const char *service, const char *user)
{
    struct db_vfs_data *data;
    const char *socket_path;
    
    data = talloc_zero(handle, struct db_vfs_data);
    if (!data) {
        DEBUG(0, ("db_vfs: Failed to allocate memory\n"));
        return -1;
    }
    
    /* Get socket path from config, default to DB_VFS_SOCKET_PATH */
    socket_path = lp_parm_const_string(SNUM(handle->conn), "db_vfs", "socket_path", DB_VFS_SOCKET_PATH);
    data->socket_path = talloc_strdup(data, socket_path);
    data->socket_fd = -1;
    data->connected = false;
    
    SMB_VFS_HANDLE_SET_DATA(handle, data, NULL, struct db_vfs_data, return -1);
    
    DEBUG(5, ("db_vfs: Connected to service %s, socket: %s\n", service, socket_path));
    return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void db_vfs_disconnect(vfs_handle_struct *handle)
{
    struct db_vfs_data *data = get_db_vfs_data(handle);
    
    if (data && data->socket_fd >= 0) {
        close(data->socket_fd);
        data->socket_fd = -1;
        data->connected = false;
    }
    
    SMB_VFS_NEXT_DISCONNECT(handle);
}

static int db_vfs_openat(vfs_handle_struct *handle,
                         const struct files_struct *dirfsp,
                         const struct smb_filename *smb_fname,
                         files_struct *fsp,
                         const struct vfs_open_how *how)
{
    struct db_vfs_data *data = get_db_vfs_data(handle);
    json_t *request, *response, *success_obj, *fd_obj;
    int result = -1;

    if (!data) {
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "operation", json_string("open"));
    json_object_set_new(request, "path", json_string(smb_fname->base_name));
    json_object_set_new(request, "flags", json_integer(how->flags));
    json_object_set_new(request, "mode", json_integer(how->mode));
    
    /* Send request */
    response = send_request(data, request);
    json_decref(request);
    
    if (!response) {
        DEBUG(3, ("db_vfs: Failed to get response for open, falling back to next VFS\n"));
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
    
    /* Parse response */
    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
        fd_obj = json_object_get(response, "fd");
        if (fd_obj && json_is_integer(fd_obj)) {
            result = json_integer_value(fd_obj);
            DEBUG(5, ("db_vfs: Successfully opened %s, fd=%d\n", smb_fname->base_name, result));
        }
    } else {
        DEBUG(3, ("db_vfs: Open failed for %s, falling back to next VFS\n", smb_fname->base_name));
        json_decref(response);
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
    
    json_decref(response);
    return result >= 0 ? result : SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
}

static int db_vfs_close(vfs_handle_struct *handle, files_struct *fsp)
{
    struct db_vfs_data *data = get_db_vfs_data(handle);
    json_t *request, *response, *success_obj;
    int result = 0;
    
    if (!data) {
        return SMB_VFS_NEXT_CLOSE(handle, fsp);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "operation", json_string("close"));
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

static ssize_t db_vfs_pread(vfs_handle_struct *handle, files_struct *fsp, 
                            void *data_buf, size_t n, off_t offset)
{
    struct db_vfs_data *data = get_db_vfs_data(handle);
    json_t *request, *response, *success_obj, *data_obj;
    ssize_t result = -1;
    const char *encoded_data;
    
    if (!data) {
        return SMB_VFS_NEXT_PREAD(handle, fsp, data_buf, n, offset);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "operation", json_string("read"));
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

static ssize_t db_vfs_pwrite(vfs_handle_struct *handle, files_struct *fsp,
                             const void *data_buf, size_t n, off_t offset)
{
    struct db_vfs_data *data = get_db_vfs_data(handle);
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
    json_object_set_new(request, "operation", json_string("write"));
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

static int db_vfs_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    struct db_vfs_data *data = get_db_vfs_data(handle);
    json_t *request, *response, *success_obj, *stat_obj;
    int result = -1;
    
    if (!data) {
        return SMB_VFS_NEXT_STAT(handle, smb_fname);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "operation", json_string("stat"));
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

static int db_vfs_unlinkat(vfs_handle_struct *handle,
                           struct files_struct *dirfsp,
                           const struct smb_filename *smb_fname,
                           int flags)
{
    struct db_vfs_data *data = get_db_vfs_data(handle);
    json_t *request, *response, *success_obj;
    int result = -1;
    
    if (!data) {
        return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
    }
    
    /* Create JSON request */
    request = json_object();
    json_object_set_new(request, "operation", json_string("unlink"));
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
static struct vfs_fn_pointers db_vfs_functions = {
    .connect_fn = db_vfs_connect,
    .disconnect_fn = db_vfs_disconnect,
    .openat_fn = db_vfs_openat,
    .close_fn = db_vfs_close,
    .pread_fn = db_vfs_pread,
    .pwrite_fn = db_vfs_pwrite,
    .stat_fn = db_vfs_stat,
    .unlinkat_fn = db_vfs_unlinkat,
};

NTSTATUS vfs_db_vfs_init(TALLOC_CTX *ctx)
{
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "db_vfs", &db_vfs_functions);
}