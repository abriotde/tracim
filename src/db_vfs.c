#include "include/includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "lib/util/tevent_unix.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <json-c/json.h>
#include <errno.h>
#include <unistd.h>

#define SOCKET_PATH "/var/run/db_vfs.sock"
#define BUFFER_SIZE 4096

/* Module state structure */
struct db_vfs_data {
    int socket_fd;
    struct connection_struct *conn;
};

/* Forward declarations */
static int db_vfs_connect(vfs_handle_struct *handle, const char *service, const char *user);
static void db_vfs_disconnect(vfs_handle_struct *handle);
static int db_vfs_open(vfs_handle_struct *handle, struct smb_filename *smb_fname, files_struct *fsp, int flags, mode_t mode);
static int db_vfs_close(vfs_handle_struct *handle, files_struct *fsp);
static ssize_t db_vfs_read(vfs_handle_struct *handle, files_struct *fsp, void *data, size_t n);
static ssize_t db_vfs_write(vfs_handle_struct *handle, files_struct *fsp, const void *data, size_t n);

/* Socket communication functions */
static int connect_to_service(void);
static json_object *send_json_request(int socket_fd, json_object *request);
static void disconnect_from_service(int socket_fd);

/* Helper function to connect to the Python service */
static int connect_to_service(void) {
    int sock_fd;
    struct sockaddr_un addr;
    
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        DEBUG(0, ("db_vfs: Failed to create socket: %s\n", strerror(errno)));
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        DEBUG(0, ("db_vfs: Failed to connect to service: %s\n", strerror(errno)));
        close(sock_fd);
        return -1;
    }
    
    return sock_fd;
}

/* Helper function to send JSON request and receive response */
static json_object *send_json_request(int socket_fd, json_object *request) {
    const char *request_str;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_sent, bytes_received;
    json_object *response = NULL;
    
    if (!request) {
        DEBUG(0, ("db_vfs: Invalid request object\n"));
        return NULL;
    }
    
    request_str = json_object_to_json_string(request);
    if (!request_str) {
        DEBUG(0, ("db_vfs: Failed to serialize JSON request\n"));
        return NULL;
    }
    
    /* Send request */
    bytes_sent = send(socket_fd, request_str, strlen(request_str), 0);
    if (bytes_sent == -1) {
        DEBUG(0, ("db_vfs: Failed to send request: %s\n", strerror(errno)));
        return NULL;
    }
    
    /* Receive response */
    bytes_received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received == -1) {
        DEBUG(0, ("db_vfs: Failed to receive response: %s\n", strerror(errno)));
        return NULL;
    }
    
    buffer[bytes_received] = '\0';
    
    /* Parse JSON response */
    response = json_tokener_parse(buffer);
    if (!response) {
        DEBUG(0, ("db_vfs: Failed to parse JSON response\n"));
        return NULL;
    }
    
    return response;
}

/* Helper function to disconnect from service */
static void disconnect_from_service(int socket_fd) {
    if (socket_fd != -1) {
        close(socket_fd);
    }
}

/* VFS connect function */
static int db_vfs_connect(vfs_handle_struct *handle, const char *service, const char *user) {
    struct db_vfs_data *data;
    int ret;
    
    /* Call the next VFS module first */
    ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
    if (ret != 0) {
        return ret;
    }
    
    /* Allocate our private data */
    data = talloc_zero(handle, struct db_vfs_data);
    if (!data) {
        DEBUG(0, ("db_vfs: Failed to allocate memory for private data\n"));
        SMB_VFS_NEXT_DISCONNECT(handle);
        return -1;
    }
    
    /* Initialize socket connection */
    data->socket_fd = connect_to_service();
    if (data->socket_fd == -1) {
        DEBUG(0, ("db_vfs: Failed to connect to database service\n"));
        talloc_free(data);
        SMB_VFS_NEXT_DISCONNECT(handle);
        return -1;
    }
    
    data->conn = handle->conn;
    SMB_VFS_HANDLE_SET_DATA(handle, data, NULL, struct db_vfs_data, return -1);
    
    DEBUG(1, ("db_vfs: Connected to database service\n"));
    return 0;
}

/* VFS disconnect function */
static void db_vfs_disconnect(vfs_handle_struct *handle) {
    struct db_vfs_data *data = NULL;
    
    SMB_VFS_HANDLE_GET_DATA(handle, data, struct db_vfs_data, return);
    
    if (data) {
        disconnect_from_service(data->socket_fd);
        talloc_free(data);
    }
    
    SMB_VFS_NEXT_DISCONNECT(handle);
}

/* VFS open function */
static int db_vfs_open(vfs_handle_struct *handle, struct smb_filename *smb_fname, 
                      files_struct *fsp, int flags, mode_t mode) {
    struct db_vfs_data *data = NULL;
    json_object *request, *response;
    json_object *action, *path, *flags_obj, *mode_obj;
    json_object *success, *error_msg;
    int ret;
    
    SMB_VFS_HANDLE_GET_DATA(handle, data, struct db_vfs_data, return -1);
    
    /* Create JSON request */
    request = json_object_new_object();
    action = json_object_new_string("open");
    path = json_object_new_string(smb_fname->base_name);
    flags_obj = json_object_new_int(flags);
    mode_obj = json_object_new_int(mode);
    
    json_object_object_add(request, "action", action);
    json_object_object_add(request, "path", path);
    json_object_object_add(request, "flags", flags_obj);
    json_object_object_add(request, "mode", mode_obj);
    
    /* Send request to service */
    response = send_json_request(data->socket_fd, request);
    json_object_put(request);
    
    if (!response) {
        DEBUG(0, ("db_vfs: Failed to get response for open operation\n"));
        return -1;
    }
    
    /* Parse response */
    if (!json_object_object_get_ex(response, "success", &success)) {
        DEBUG(0, ("db_vfs: Invalid response format\n"));
        json_object_put(response);
        return -1;
    }
    
    if (!json_object_get_boolean(success)) {
        if (json_object_object_get_ex(response, "error", &error_msg)) {
            DEBUG(0, ("db_vfs: Open failed: %s\n", json_object_get_string(error_msg)));
        }
        json_object_put(response);
        return -1;
    }
    
    json_object_put(response);
    
    /* Call the next VFS module */
    ret = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
    
    DEBUG(2, ("db_vfs: Opened file %s\n", smb_fname->base_name));
    return ret;
}

/* VFS close function */
static int db_vfs_close(vfs_handle_struct *handle, files_struct *fsp) {
    struct db_vfs_data *data = NULL;
    json_object *request, *response;
    json_object *action, *path;
    json_object *success, *error_msg;
    int ret;
    
    SMB_VFS_HANDLE_GET_DATA(handle, data, struct db_vfs_data, return -1);
    
    /* Create JSON request */
    request = json_object_new_object();
    action = json_object_new_string("close");
    path = json_object_new_string(fsp->fsp_name->base_name);
    
    json_object_object_add(request, "action", action);
    json_object_object_add(request, "path", path);
    
    /* Send request to service */
    response = send_json_request(data->socket_fd, request);
    json_object_put(request);
    
    if (!response) {
        DEBUG(0, ("db_vfs: Failed to get response for close operation\n"));
        return -1;
    }
    
    /* Parse response */
    if (!json_object_object_get_ex(response, "success", &success)) {
        DEBUG(0, ("db_vfs: Invalid response format\n"));
        json_object_put(response);
        return -1;
    }
    
    if (!json_object_get_boolean(success)) {
        if (json_object_object_get_ex(response, "error", &error_msg)) {
            DEBUG(0, ("db_vfs: Close failed: %s\n", json_object_get_string(error_msg)));
        }
        json_object_put(response);
        return -1;
    }
    
    json_object_put(response);
    
    /* Call the next VFS module */
    ret = SMB_VFS_NEXT_CLOSE(handle, fsp);
    
    DEBUG(2, ("db_vfs: Closed file %s\n", fsp->fsp_name->base_name));
    return ret;
}

/* VFS read function */
static ssize_t db_vfs_read(vfs_handle_struct *handle, files_struct *fsp, void *data, size_t n) {
    struct db_vfs_data *vfs_data = NULL;
    json_object *request, *response;
    json_object *action, *path, *size_obj;
    json_object *success, *error_msg;
    ssize_t ret;
    
    SMB_VFS_HANDLE_GET_DATA(handle, vfs_data, struct db_vfs_data, return -1);
    
    /* Create JSON request */
    request = json_object_new_object();
    action = json_object_new_string("read");
    path = json_object_new_string(fsp->fsp_name->base_name);
    size_obj = json_object_new_int64(n);
    
    json_object_object_add(request, "action", action);
    json_object_object_add(request, "path", path);
    json_object_object_add(request, "size", size_obj);
    
    /* Send request to service */
    response = send_json_request(vfs_data->socket_fd, request);
    json_object_put(request);
    
    if (!response) {
        DEBUG(0, ("db_vfs: Failed to get response for read operation\n"));
        return -1;
    }
    
    /* Parse response */
    if (!json_object_object_get_ex(response, "success", &success)) {
        DEBUG(0, ("db_vfs: Invalid response format\n"));
        json_object_put(response);
        return -1;
    }
    
    if (!json_object_get_boolean(success)) {
        if (json_object_object_get_ex(response, "error", &error_msg)) {
            DEBUG(0, ("db_vfs: Read failed: %s\n", json_object_get_string(error_msg)));
        }
        json_object_put(response);
        return -1;
    }
    
    json_object_put(response);
    
    /* Call the next VFS module */
    ret = SMB_VFS_NEXT_READ(handle, fsp, data, n);
    
    DEBUG(3, ("db_vfs: Read %zd bytes from file %s\n", ret, fsp->fsp_name->base_name));
    return ret;
}

/* VFS write function */
static ssize_t db_vfs_write(vfs_handle_struct *handle, files_struct *fsp, const void *data, size_t n) {
    struct db_vfs_data *vfs_data = NULL;
    json_object *request, *response;
    json_object *action, *path, *size_obj;
    json_object *success, *error_msg;
    ssize_t ret;
    
    SMB_VFS_HANDLE_GET_DATA(handle, vfs_data, struct db_vfs_data, return -1);
    
    /* Create JSON request */
    request = json_object_new_object();
    action = json_object_new_string("write");
    path = json_object_new_string(fsp->fsp_name->base_name);
    size_obj = json_object_new_int64(n);
    
    json_object_object_add(request, "action", action);
    json_object_object_add(request, "path", path);
    json_object_object_add(request, "size", size_obj);
    
    /* Send request to service */
    response = send_json_request(vfs_data->socket_fd, request);
    json_object_put(request);
    
    if (!response) {
        DEBUG(0, ("db_vfs: Failed to get response for write operation\n"));
        return -1;
    }
    
    /* Parse response */
    if (!json_object_object_get_ex(response, "success", &success)) {
        DEBUG(0, ("db_vfs: Invalid response format\n"));
        json_object_put(response);
        return -1;
    }
    
    if (!json_object_get_boolean(success)) {
        if (json_object_object_get_ex(response, "error", &error_msg)) {
            DEBUG(0, ("db_vfs: Write failed: %s\n", json_object_get_string(error_msg)));
        }
        json_object_put(response);
        return -1;
    }
    
    json_object_put(response);
    
    /* Call the next VFS module */
    ret = SMB_VFS_NEXT_WRITE(handle, fsp, data, n);
    
    DEBUG(3, ("db_vfs: Wrote %zd bytes to file %s\n", ret, fsp->fsp_name->base_name));
    return ret;
}

/* VFS operations structure */
static struct vfs_fn_pointers db_vfs_ops = {
    .connect_fn = db_vfs_connect,
    .disconnect_fn = db_vfs_disconnect,
    .open_fn = db_vfs_open,
    .close_fn = db_vfs_close,
    .read_fn = db_vfs_read,
    .write_fn = db_vfs_write,
};

/* Module initialization */
NTSTATUS vfs_db_vfs_init(TALLOC_CTX *ctx)
{
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "db_vfs", &db_vfs_ops);
}