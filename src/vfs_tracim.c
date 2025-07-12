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
#include <dirent.h>

extern NTSTATUS smb_register_vfs(int version, const char *name, const struct vfs_fn_pointers *fns);

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
	DEBUG(0 ,("Tracim: get_tracim_data().\n"));
    struct tracim_data *data;
    
    SMB_VFS_HANDLE_GET_DATA(handle, data, struct tracim_data, return NULL);
	if(!data) {
		DEBUG(0, ("Tracim: get_tracim_data() - No tracim data found.\n"));
		return NULL;
	}
    return data;
}
/**
 * @brief Connect to Unix socket.
 * 
 * @param data 
 * @return int : 0 = ok, -1 = error
 */
static int connect_to_service(struct tracim_data *data)
{
	DEBUG(0, ("Tracim: connect_to_service().\n"));
    struct sockaddr_un addr;
    int ret;
    
    if (data->connected && data->socket_fd >= 0) {
        return 0; /* Already connected */
    }
    
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
        DEBUG(0, ("tracim: Failed to connect to %s: %s\n", data->socket_path, strerror(errno)));
        close(data->socket_fd);
        data->socket_fd = -1;
        data->connected = false;
        return -1;
    }
    
    data->connected = true;
    DEBUG(5, ("tracim: Connected to service at %s\n", data->socket_path));
    return 0;
}

/**
 * @brief Send JSON request and receive response
 * 
 * @param data 
 * @param request 
 * @return * json_t* 
 */
static json_t *send_request(struct tracim_data *data, json_t *request)
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
        DEBUG(0, ("tracim: Failed to serialize JSON request\n"));
        return NULL;
    }
    bytes_received = recv(data->socket_fd, response_buf, sizeof(response_buf) - 1, MSG_DONTWAIT);
	if (bytes_received>0) {
        DEBUG(0, ("tracim: Empty the buffer of '%s'\n", response_buf));
	}
    
    /* Send request */
	DEBUG(0, ("tracim: Sending request: %s\n", request_str));
	flock(data->socket_fd, LOCK_EX);
	ssize_t tosend = strlen(request_str);
    bytes_sent = send(data->socket_fd, request_str, tosend, 0);
	flock(data->socket_fd, LOCK_UN);
    free(request_str);
    if (bytes_sent < tosend) {
        DEBUG(0, ("tracim: Failed to send request: sended %ld bytes while %ld bytes to send : %s\n",
			bytes_sent, tosend, strerror(errno)));
        data->connected = false;
        return NULL;
    }
    send(data->socket_fd, "\n", 1, 0);
    /* Receive response */
	// flock(data->socket_fd, LOCK_EX);
    bytes_received = recv(data->socket_fd, response_buf, sizeof(response_buf) - 1, 0); // flag=MSG_WAITALL?;
	// flock(data->socket_fd, LOCK_UN);
    if (bytes_received < 0) {
        DEBUG(0, ("tracim: Failed to receive response: %s\n", strerror(errno)));
        data->connected = false;
        return NULL;
    }
    response_buf[bytes_received] = '\0';
    DEBUG(0, ("tracim: Received response: %s\n", response_buf));

    /* Parse JSON response */
    response = json_loads(response_buf, 0, &error);
    if (!response) {
        DEBUG(0, ("tracim: Failed to parse JSON response: %s\n", error.text));
        return NULL;
    }
    
    return response;
}

/**
 * @brief 
 * 
 * @param handle 
 * @param service 
 * @param user 
 * @return int 
 */
static int tracim_connect(vfs_handle_struct *handle, const char *service, const char *user)
{
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
    return 0; // SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void tracim_disconnect(vfs_handle_struct *handle)
{
	DEBUG(0, ("Tracim: tracim_disconnect().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    
    if (data && data->socket_fd >= 0) {
        close(data->socket_fd);
        data->socket_fd = -1;
        data->connected = false;
    }
    
    // SMB_VFS_NEXT_DISCONNECT(handle);
}

/**
 * @brief Open a file in the Tracim VFS.
 *
 * @param handle 
 * @param dirfsp 
 * @param smb_fname 
 * @param fsp 
 * @param how 
 * @return int : the file descriptor (fd) if > 0
 */
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
        DEBUG(0, ("tracim_openat: Failed to get VFS tracim data\n"));
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }

    request = json_object();
    json_object_set_new(request, "op", json_string("open"));
    json_object_set_new(request, "path", json_string(smb_fname->base_name));
    json_object_set_new(request, "flags", json_integer(how->flags));
    json_object_set_new(request, "mode", json_integer(how->mode));
    json_object_set_new(request, "user", json_string(data->user));
    response = send_request(data, request);
    json_decref(request);
    if (!response) {
        DEBUG(0, ("tracim_openat: Failed to get response for open, falling back to next VFS\n"));
        return result; // SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }

    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
        fd_obj = json_object_get(response, "handle");
        if (fd_obj && json_is_integer(fd_obj)) {
            result = json_integer_value(fd_obj);
            DEBUG(0, ("tracim_openat: Successfully opened %s, fd=%d\n", smb_fname->base_name, result));
        } else {
            DEBUG(0, ("tracim_openat: No fd..."));
		}
    } else {
        DEBUG(0, ("tracim_openat: Open failed for %s, falling back to next VFS\n", smb_fname->base_name));
    }
    json_decref(response);
	// DEBUG(0, ("Tracim: tracim_openat() : file is : %s, %ld, %d, %ld.\n", smb_fname->base_name, smb_fname->st.st_ex_size, smb_fname->st.st_ex_mode, smb_fname->st.st_ex_mtime.tv_sec));
	// result = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
	// DEBUG(0, ("Tracim: tracim_openat() : file SMB_VFS_NEXT_OPENAT : %s, %ld, %d, %ld : %d.\n", smb_fname->base_name, smb_fname->st.st_ex_size, smb_fname->st.st_ex_mode, smb_fname->st.st_ex_mtime.tv_sec, result));
    return result; // >= 0 ? result : 
}

static int tracim_close(vfs_handle_struct *handle, files_struct *fsp)
{
	DEBUG(0, ("Tracim: tracim_close().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    json_t *request, *response, *success_obj;
    int result = -1;
    
    if (!data) {
        return result; // SMB_VFS_NEXT_CLOSE(handle, fsp);
    }
    
    request = json_object();
    json_object_set_new(request, "op", json_string("close"));
    json_object_set_new(request, "handle", json_integer(fsp_get_io_fd(fsp)));
    response = send_request(data, request);
    json_decref(request);
    if (response) {
        success_obj = json_object_get(response, "success");
        if (success_obj && json_is_true(success_obj)) {
            result = 0;
        } else {
			result = -1;
        	success_obj = json_object_get(response, "error");
			DEBUG(10, ("Tracim: tracim_close() failed: %s\n", json_string_value(success_obj)));
		}
        json_decref(response);
    }
	result = SMB_VFS_NEXT_CLOSE(handle, fsp);
	DEBUG(0, ("Tracim: tracim_close() : %d.\n", result));
    return result; // result; // >= 0 ? result : SMB_VFS_NEXT_CLOSE(handle, fsp);
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
    
    request = json_object();
    json_object_set_new(request, "op", json_string("read"));
    json_object_set_new(request, "fd", json_integer(fsp_get_io_fd(fsp)));
    json_object_set_new(request, "size", json_integer(n));
    json_object_set_new(request, "offset", json_integer(offset));
    response = send_request(data, request);
    json_decref(request);
    if (!response) {
        return SMB_VFS_NEXT_PREAD(handle, fsp, data_buf, n, offset);
    }
    
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
        return result; // SMB_VFS_NEXT_PWRITE(handle, fsp, data_buf, n, offset);
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
    return result; // >= 0 ? result : SMB_VFS_NEXT_PWRITE(handle, fsp, data_buf, n, offset);
}

int tracim_stat_sub(json_t *request, vfs_handle_struct *handle, SMB_STRUCT_STAT *sbuf) {
    json_t *response, *json_obj, *stat_obj;
    struct tracim_data *data = get_tracim_data(handle);
    int result = -1;
    if (!data) {
		DEBUG(0, ("Tracim: tracim_stat() : fail get data.\n"));
    	json_decref(request);
        return result; // SMB_VFS_NEXT_STAT(handle, smb_fname);
    }
	DEBUG(0, ("Tracim: tracim_stat_sub(%s).\n", data->user));
    json_object_set_new(request, "op", json_string("stat"));
    json_object_set_new(request, "user", json_string(data->user));
    response = send_request(data, request);
    json_decref(request);
    if (!response) {
		DEBUG(0, ("Tracim: tracim_stat() : fail get response.\n"));
        return result; // SMB_VFS_NEXT_STAT(handle, smb_fname);
    }
    
    json_obj = json_object_get(response, "success");
    if (json_obj && json_is_true(json_obj)) {
		bool is_dir = false;
		DEBUG(0, ("Tracim: tracim_stat() : file was, %ld, %d, %ld.\n", 
			sbuf->st_ex_size, sbuf->st_ex_mode, sbuf->st_ex_mtime.tv_sec));
		json_obj = json_object_get(response, "size");
		if (json_obj && json_is_integer(json_obj)) {
			sbuf->st_ex_size = json_integer_value(json_obj);
		}
		json_obj = json_object_get(response, "is_dir");
		if (json_obj && json_is_true(json_obj)) {
			is_dir = true;
		}
		json_obj = json_object_get(response, "mode");
		if (json_obj && json_is_integer(json_obj)) {
			unsigned long int mode = json_integer_value(json_obj);
			if (is_dir) {
				mode |= S_IFDIR;
			} else {
				mode |= S_IFREG;
			}
			sbuf->st_ex_mode = mode;
		}
		json_obj = json_object_get(response, "mtime");
		if (json_obj && json_is_integer(json_obj)) {
			unsigned long int mtime = json_integer_value(json_obj);
			sbuf->st_ex_mtime.tv_sec = mtime;
			sbuf->st_ex_atime.tv_sec = mtime;
			sbuf->st_ex_ctime.tv_sec = mtime;
		}
		DEBUG(0, ("Tracim: tracim_stat() : file is: %ld, %d, %ld.\n",
			sbuf->st_ex_size, sbuf->st_ex_mode, sbuf->st_ex_mtime.tv_sec));
        result = 0;
		DEBUG(0, ("Tracim: tracim_stat() : Ok.\n"));
    } else {
		errno = ENOENT; // File not found
		result = 1;
		json_obj = json_object_get(response, "error");
		DEBUG(0, ("Tracim: tracim_stat() : fail get response : %s.\n", json_string_value(json_obj)));
	}
    json_decref(response);
    // result = SMB_VFS_NEXT_STAT(handle, smb_fname);
	// DEBUG(0, ("Tracim: tracim_stat() : file SMB_VFS_NEXT_STAT : %ld, %d, %ld.\n", sbuf->st_ex_size, sbuf->st_ex_mode, sbuf->st_ex_mtime.tv_sec));
	DEBUG(0, ("Tracim: tracim_stat() : %d.\n", result));
}

/**
 * @brief Get metadata via an open file descriptor
 * 
 * @param handle 
 * @param fsp 
 * @param sbuf 
 * @return int 
 */
static int tracim_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf) {
	int fd = fsp_get_io_fd(fsp);
    DEBUG(0, ("Tracim: tracim_fstat(%d)\n", fd));
    json_t *request = json_object();
    json_object_set_new(request, "handle", json_integer(fd));
	return tracim_stat_sub(request, handle, sbuf);
}
/**
 * @brief Get metadata by pathname
 * 
 * @param handle 
 * @param smb_fname 
 * @return int 
 */
static int tracim_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	DEBUG(0, ("Tracim: tracim_stat(%s).\n", smb_fname->base_name));
    json_t *request;
    request = json_object();
    json_object_set_new(request, "path", json_string(smb_fname->base_name));
	return tracim_stat_sub(request, handle, &smb_fname->st);
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

/* Structure to hold our custom DIR state */
struct tracim_dir {
    DIR *real_dir;
    int static_index;
};

/* Helper function to create a custom DIR wrapper */
static DIR *create_static_dir(void) {
    struct tracim_dir *custom_dir;

    custom_dir = talloc_zero(NULL, struct tracim_dir);
    if (!custom_dir) {
        errno = ENOMEM;
        return NULL;
    }
    
    custom_dir->real_dir = NULL;
    custom_dir->static_index = 0;

    return (DIR *)custom_dir;
}
/**
 * @brief Call API to open a directory in the Tracim VFS. There is no file list.
 * 
 * @param handle 
 * @param fsp 
 * @param mask 
 * @param attr 
 * @return DIR* : It's a integer as a "file descriptor".
 */
static DIR *tracim_opendir(vfs_handle_struct *handle,
                                    files_struct *fsp,
                                    const char *mask,
                                    uint32_t attr)
{
	DEBUG(0, ("Tracim: tracim_opendir(%s).\n", fsp->fsp_name->base_name));
    DIR *result = NULL;
    json_t *request, *response, *success_obj, *json_obj;
    struct tracim_data *data = get_tracim_data(handle);
    
    request = json_object();
    json_object_set_new(request, "op", json_string("opendir"));
    json_object_set_new(request, "path", json_string(fsp->fsp_name->base_name));
    json_object_set_new(request, "attr", json_integer(attr));

    response = send_request(data, request);
    json_decref(request);
    success_obj = json_object_get(response, "success");
	if(success_obj) {
		if (json_is_true(success_obj)) {
			json_obj = json_object_get(response, "handle");
			int i = json_integer_value(json_obj);
			DEBUG(10, ("Tracim: tracim_opendir successfull for fd=%d\n", i));
			result = (DIR *)i;
		} else {
			json_obj = json_object_get(response, "error");
			DEBUG(10, ("Tracim: tracim_opendir failed: %s\n", json_string_value(json_obj)));
		}
	} else {
		DEBUG(10, ("Tracim: tracim_opendir failed\n"));
	}
    json_decref(response);

    /* result = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
    if (result == NULL) {
        DEBUG(1, ("vfs_example_fdopendir: SMB_VFS_NEXT_FDOPENDIR failed: %s\n",
                  strerror(errno)));
        return NULL;
    }*/

    DEBUG(10, ("Tracim: tracim_opendir ended for %s\n", fsp_str_dbg(fsp)));
    
    return result;
}
/**
 * @brief Call on a DIR* to list all the files into the directory. At each call, give next entry.
 * 
 * @param handle 
 * @param dirfsp 
 * @param dirp 
 * @return struct dirent* : directory entry one by one.
 */
static struct dirent *tracim_readdir(vfs_handle_struct *handle,
                                          struct files_struct *dirfsp,
                                          DIR *dirp)
{
	DEBUG(0, ("Tracim: tracim_readdir().\n"));
	struct dirent * result = NULL;
	struct tracim_data *data = get_tracim_data(handle);
	json_t *request, *response, *success_obj, *entry_obj;
	size_t i;

    request = json_object();
    json_object_set_new(request, "op", json_string("readdir"));
    json_object_set_new(request, "handle", json_integer((int)dirp));
    json_object_set_new(request, "user", json_string(data->user));
    response = send_request(data, request);
    json_decref(request);
	if (!response) {
		DEBUG(3, ("tracim: Failed to get response for readdir, falling back to next VFS\n"));
		return SMB_VFS_NEXT_READDIR(handle, dirfsp, dirp);
	}
    success_obj = json_object_get(response, "success");
	if (!success_obj) {
		if (json_is_true(success_obj)) {
			result = talloc(talloc_tos(), struct dirent);
			if (!result) {
				errno = ENOMEM;
				return NULL;
			}
			entry_obj = json_object_get(response, "name");
			strncpy(result->d_name, json_string_value(entry_obj), sizeof(result->d_name) - 1);
			result->d_name[sizeof(result->d_name) - 1] = '\0';
			entry_obj = json_object_get(response, "ino");
			result->d_ino = json_integer_value(entry_obj);
			entry_obj = json_object_get(response, "type");
			result->d_type = (unsigned char)json_integer_value(entry_obj);
		} else {
			entry_obj = json_object_get(response, "error");
			DEBUG(10, ("Tracim: tracim_readdir failed: %s\n", json_string_value(entry_obj)));
		}
	} else {
		DEBUG(10, ("Tracim: tracim_readdir failed\n"));
	}
    json_decref(response);

	DEBUG(10, ("tracim_readdir: '%s'\n", result->d_name));

	// result = SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);

    return result;
}

/* Custom closedir function to clean up our custom structure */
static int tracim_closedir(vfs_handle_struct *handle,
                                DIR *dirp)
{
    struct vfs_example_dir *custom_dir = (struct vfs_example_dir *)dirp;
    int result = 0;

    DEBUG(0, ("Tracim: tracim_closedir called\n"));
	
    return result;
}
/**
 * @brief Get metadata relative to a directory handle
 * 
 * @param handle 
 * @param dirfsp 
 * @param smb_fname 
 * @param sbuf 
 * @param flags 
 * @return int 
 */
int tracim_fstatat(
		struct vfs_handle_struct *handle, const struct files_struct *dirfsp,
		const struct smb_filename *smb_fname, SMB_STRUCT_STAT *sbuf, int flags) {
    DEBUG(0, ("Tracim: tracim_fstatat()\n"));

}

/* VFS operations structure for Samba 4.x : Not ok before */
static struct vfs_fn_pointers tracim_functions = {
    .connect_fn = tracim_connect,
    .disconnect_fn = tracim_disconnect,
    .openat_fn = tracim_openat,
    .close_fn = tracim_close,
    .pread_fn = tracim_pread,

	// .fstat_fn = tracim_fstat,
	// .fstatat_fn = tracim_fstatat,

    // .pwrite_fn = tracim_pwrite,
    .unlinkat_fn = tracim_unlinkat,
	.stat_fn = tracim_stat,
    .fdopendir_fn = tracim_opendir,
    .readdir_fn = tracim_readdir,
    .closedir_fn = tracim_closedir
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