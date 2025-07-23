/*
 * Samba 4.x VFS module for database-backed virtual filesystem
 * Communicates with Python DB VFS service via JSON over Unix socket
 */
#undef TRACIM_DEBUG
// Set in smb.conf "log level = 3 vfs:10"
#include "includes.h"
#include "smbd/globals.h"
#include "smbd/smbd.h"
#include "auth.h"
#include "smb.h"
#include "system/filesys.h"
#include "security.h"
#include "fake_file.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/sys_rw.h"
#include "../librpc/gen_ndr/ioctl.h" // For create_file_unixpath()
#include "librpc/gen_ndr/ndr_xattr.h"
#include "smbd/fd_handle.h"
#include <jansson.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <dirent.h>
#include <sys/eventfd.h>


#ifndef SMB_VFS_INTERFACE_VERSION
#error "SMB_VFS_INTERFACE_VERSION not defined"
#endif

#define DB_VFS_SOCKET_PATH "/srv/tracim/samba_vfs_tracim_service.sock"
#define MAX_RESPONSE_SIZE 65536
#define MAX_REQUEST_SIZE 32768

extern NTSTATUS smb_register_vfs(int version, const char *name, const struct vfs_fn_pointers *fns);
extern int fsp_get_pathref_fd(const struct files_struct *fsp);
extern int fsp_get_io_fd(const struct files_struct *fsp);
extern NTSTATUS open_fake_file(struct smb_request *req, connection_struct *conn,
				uint64_t current_vuid,
				enum FAKE_FILE_TYPE fake_file_type,
				const struct smb_filename *smb_fname,
				uint32_t access_mask,
				files_struct **result);
extern enum ndr_err_code ndr_push_nbt_name(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct nbt_name *r);
char *BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const char *in, const unsigned long in_len, char *out) {
	int in_index = 0;
	int out_index = 0;
	while (in_index < in_len) {
		// process group of 24 bit
		// first 6-bit
		out[out_index++] = BASE64[ (in[in_index] & 0xFC) >> 2 ];
		if ((in_index + 1) == in_len) {
			// padding case n.1
			// Remaining bits to process are the right-most 2 bit of on the
			// last byte of input. we also need to add two bytes of padding
			out[out_index++] = BASE64[ ((in[in_index] & 0x3) << 4) ];
			out[out_index++] = '=';
			out[out_index++] = '=';
			break;
		}
		// second 6-bit
		out[out_index++] = BASE64[ ((in[in_index] & 0x3) << 4) | ((in[in_index+1] & 0xF0) >> 4) ];
		if ((in_index + 2) == in_len) {
			// padding case n.2
			//
			// Remaining bits to process are the right most 4 bit on the
			// last byte of input. We also need to add a single byte of
			// padding.
			out[out_index++] = BASE64[ ((in[in_index + 1] & 0xF) << 2) ];
			out[out_index++] = '=';
			break;
		}
		// third 6-bit
		out[out_index++] = BASE64[ ((in[in_index + 1] & 0xF) << 2) | ((in[in_index + 2] & 0xC0) >> 6) ];
		// fourth 6-bit
		out[out_index++] = BASE64[ in[in_index + 2] & 0x3F ];
		in_index += 3;
	}
	out[out_index] = '\0';
	return;
}
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
	// DEBUG(0 ,("Tracim: get_tracim_data().\n"));
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
	// DEBUG(0, ("Tracim: connect_to_service().\n"));
    struct sockaddr_un addr;
    int ret;
    
    if (data->connected && data->socket_fd >= 0) {
		// DEBUG(0, ("Tracim: connect_to_service() : Already connected.\n"));
        return 0;
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
        DEBUG(0, ("tracim: ERROR : Empty the buffer of '%s'\n", response_buf));
	}
    /* Send request */
	int len = strlen(request_str);
	if (len>=MAX_REQUEST_SIZE) { // assert()
		DEBUG(0, ("tracim: ERROR : request too long : %s (%d)\n", request_str, len));
	}
	DEBUG(0, ("tracim: Sending request: %s (%d)\n", request_str, len));
	ssize_t tosend = strlen(request_str);
	flock(data->socket_fd, LOCK_EX);
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
    DEBUG(0, ("tracim: Received response: %s (%ld)\n", response_buf, bytes_received));

    /* Parse JSON response */
    response = json_loads(response_buf, 0, &error);
    if (!response) {
		response = json_loads(response_buf, 0, &error);
		char * pt = response_buf+2;
		while (*pt!='{' && pt<response_buf+sizeof(response_buf)) pt++;
		*pt = '\0';
        DEBUG(0, ("tracim: Failed to parse JSON response: retry %s\n", response_buf));
		response = json_loads(response_buf, 0, &error);
		if (!response) {
			DEBUG(0, ("tracim: Failed to parse JSON response: %s\n", error.text));
        	return NULL;
		}
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
	int result = 0;
    
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
    
    json_t *request = json_object();
    json_object_set_new(request, "op", json_string("init"));
    json_object_set_new(request, "mount", json_string(handle->conn->connectpath));
    json_object_set_new(request, "user", json_string(data->user));
    json_t *response = send_request(data, request);
    json_decref(request);
    if (response) {
		json_t *success_obj = json_object_get(response, "success");
		if (success_obj && json_is_true(success_obj)) {
			result = 0;
		} else {
			result = -1;
			success_obj = json_object_get(response, "error");
			DEBUG(0, ("Tracim: tracim_connect() failed: %s\n", json_string_value(success_obj)));
		}
	} else {
        DEBUG(0, ("tracim_connect: Failed to get response for open\n"));
        return -1;
    }
    json_decref(response);
    DEBUG(0, ("tracim: Connected to service %s, socket: %s\n", service, socket_path));
    return 0;
}

static void tracim_disconnect(vfs_handle_struct *handle)
{
	DEBUG(0, ("Tracim: tracim_disconnect().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    
    if (data && data->socket_fd >= 0) {
        close(data->socket_fd);
        data->socket_fd = -1;
        data->connected = false;
    	talloc_free(data);
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
	char * path = smb_fname->base_name;
	if (fsp && fsp->fsp_name && fsp->fsp_name->base_name && strlen(fsp->fsp_name->base_name)>1) {
		path = fsp->fsp_name->base_name;
	}
    DEBUG(0, ("Tracim: tracim_openat(%s, %s, %i, %d).\n", path, smb_fname->stream_name, smb_fname->flags, fsp->fsp_flags.is_pathref));
    json_t *request, *response, *success_obj, *fd_obj;
    int fd = -1;
    if (!data) {
        DEBUG(0, ("tracim_openat: Failed to get VFS tracim data\n"));
        return fd; // SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
	if (fsp->fsp_flags.is_directory) {
        DEBUG(0, ("tracim_openat: is directory\n"));
		// fd = eventfd(0, FD_CLOEXEC);
	}
	if (fsp->fsp_flags.is_pathref) {
		DEBUG(0, ("tracim_openat: is pathref\n"));
	}
	
    request = json_object();
    json_object_set_new(request, "op", json_string("open"));
    json_object_set_new(request, "path", json_string(path));
    json_object_set_new(request, "flags", json_integer(how->flags));
    json_object_set_new(request, "mode", json_integer(how->mode));
    json_object_set_new(request, "user", json_string(data->user));
    response = send_request(data, request);
    json_decref(request);
    if (!response) {
        DEBUG(0, ("tracim_openat: Failed to get response for open\n"));
        return fd; // SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }

    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
        fd_obj = json_object_get(response, "handle");
        if (fd_obj && json_is_integer(fd_obj)) {
            fd = json_integer_value(fd_obj);
            DEBUG(0, ("tracim_openat: Successfully opened %s, fd=%d\n", path, fd));
        } else {
            DEBUG(0, ("tracim_openat: No fd..."));
		}
    } else {
        DEBUG(0, ("tracim_openat: Open failed for %s\n", path));
    }
    json_decref(response);
	// fd = eventfd(0, FD_CLOEXEC);
	DEBUG(0, ("Tracim: tracim_openat() : %s, %d.\n", path, fd));
	// result = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
	// DEBUG(0, ("Tracim: tracim_openat() : file SMB_VFS_NEXT_OPENAT : %s, %ld, %d, %ld : %d.\n", smb_fname->base_name, smb_fname->st.st_ex_size, smb_fname->st.st_ex_mode, smb_fname->st.st_ex_mtime.tv_sec, result));
    return fd; // SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how); // >= 0 ? result : 
}

static int tracim_close(vfs_handle_struct *handle, files_struct *fsp)
{
	DEBUG(0, ("Tracim: tracim_close().\n"));
    struct tracim_data *data = get_tracim_data(handle);
    json_t *request, *response, *success_obj;
    int result = 0;
    if (!data) {
        return -1; // SMB_VFS_NEXT_CLOSE(handle, fsp);
    }
	int fd = 0;
	if (fsp->fsp_flags.is_pathref) {
		fd = fsp_get_pathref_fd(fsp);
	} else {
		fd = fsp_get_io_fd(fsp);
	}
	if (fd>0) {
		request = json_object();
		json_object_set_new(request, "op", json_string("close"));
		json_object_set_new(request, "handle", json_integer(fd));
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
		// result = SMB_VFS_NEXT_CLOSE(handle, fsp);
		fsp->vfs_extension = NULL;
		DEBUG(0, ("Tracim: tracim_close() : %d.\n", result));
	} else {
		DEBUG(0, ("Tracim: close_fn called with invalid fd\n"));
	}
    return result; // SMB_VFS_NEXT_CLOSE(handle, fsp);
}

int tracim_stat_sub(json_t *request, vfs_handle_struct *handle, SMB_STRUCT_STAT *const sbuf, files_struct *const fsp) {
    json_t *response, *json_obj, *stat_obj;
    struct tracim_data *data = get_tracim_data(handle);
    int result = -1;
    if (!data) {
		DEBUG(0, ("Tracim: tracim_stat() : fail get data.\n"));
    	json_decref(request);
        return result; // SMB_VFS_NEXT_STAT(handle, smb_fname);
    }
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
				// fsp->fsp_flags.is_directory = 1;
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
		sbuf->st_ex_nlink = 2;
    	sbuf->st_ex_uid = handle->conn->session_info->unix_token->uid;
    	sbuf->st_ex_gid = handle->conn->session_info->unix_token->gid;
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
	return 0;
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
	int fd = 0;
	if (fsp->fsp_flags.is_pathref) {
		fd = fsp_get_pathref_fd(fsp);
	} else {
		fd = fsp_get_io_fd(fsp);
	}
    DEBUG(0, ("Tracim: tracim_fstat(%d)\n", fd));
    json_t *request = json_object();
    json_object_set_new(request, "fd", json_integer(fd));
	return tracim_stat_sub(request, handle, sbuf, fsp);
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
    DEBUG(0, ("Tracim: tracim_stat(%s, %s, %i).\n",
		smb_fname->base_name, smb_fname->stream_name, smb_fname->flags));
    json_t *request;
    request = json_object();
	char * path = smb_fname->base_name;
	if (smb_fname->fsp && smb_fname->fsp->fsp_name && smb_fname->fsp->fsp_name->base_name && strlen(smb_fname->fsp->fsp_name->base_name)>1) {
		path = smb_fname->fsp->fsp_name->base_name;
	}
    json_object_set_new(request, "path", json_string(path));
	return tracim_stat_sub(request, handle, &smb_fname->st, smb_fname->fsp);
}
int tracim_lstat(struct vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	int ret;
    DEBUG(0, ("Tracim: tracim_lstat(%s, %s, %i, %p).\n",
		smb_fname->base_name, smb_fname->stream_name, smb_fname->flags, smb_fname->fsp));
	// ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
    json_t *request;
    request = json_object();
	char * path = smb_fname->base_name;
	if (smb_fname->fsp && smb_fname->fsp->fsp_name && smb_fname->fsp->fsp_name->base_name && strlen(smb_fname->fsp->fsp_name->base_name)>1) {
		path = smb_fname->fsp->fsp_name->base_name;
	}
    json_object_set_new(request, "path", json_string(path));
	return tracim_stat_sub(request, handle, &smb_fname->st, smb_fname->fsp);
}
/**
 * @brief Get metadata relative to a directory handle
 * TODO : Maybe not well implemented
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
    json_t *request;
    request = json_object();
	char * path = smb_fname->base_name;
	if (smb_fname->fsp && smb_fname->fsp->fsp_name && smb_fname->fsp->fsp_name->base_name && strlen(smb_fname->fsp->fsp_name->base_name)>1) {
		path = smb_fname->fsp->fsp_name->base_name;
	}
    json_object_set_new(request, "path", json_string(path));
	return tracim_stat_sub(request, handle, sbuf, smb_fname->fsp);
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
        return result;
    }
	char * path = smb_fname->base_name;
	if (smb_fname->fsp && smb_fname->fsp->fsp_name && smb_fname->fsp->fsp_name->base_name && strlen(smb_fname->fsp->fsp_name->base_name)>1) {
		path = smb_fname->fsp->fsp_name->base_name;
	}
    request = json_object();
    json_object_set_new(request, "op", json_string("unlink"));
    json_object_set_new(request, "path", json_string(path));
	json_object_set_new(request, "fd", json_integer(fsp_get_pathref_fd(dirfsp)));
    response = send_request(data, request);
    json_decref(request);
    if (!response) {
        return result;
    }
    success_obj = json_object_get(response, "success");
    if (success_obj) {
        result = json_is_true(success_obj) ? 0 : -1;
    }
    json_decref(response);
    return result; // >= 0 ? result : SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
}

static int tracim_renameat(vfs_handle_struct *handle,
			  files_struct *srcfsp,
			  const struct smb_filename *smb_fname_src,
			  files_struct *dstfsp,
			  const struct smb_filename *smb_fname_dst)
{
	DEBUG(0, ("Tracim: tracim_renameat().\n"));
	int srcfd = fsp_get_pathref_fd(srcfsp);
	char * src = smb_fname_src->base_name;
	int dstfd = fsp_get_pathref_fd(dstfsp);
	char * dst = smb_fname_dst->base_name;
    struct tracim_data *data = get_tracim_data(handle);
    json_t *request, *response, *success_obj;
    int result = -1;
    
    if (!data) {
        return result;
    }
    request = json_object();
    json_object_set_new(request, "op", json_string("rename"));
    json_object_set_new(request, "src", json_string(src));
    json_object_set_new(request, "dst", json_string(dst));
	json_object_set_new(request, "srcfd", json_integer(srcfd));
	json_object_set_new(request, "dstfd", json_integer(dstfd));
    response = send_request(data, request);
    json_decref(request);
    if (!response) {
        return result;
    }
    success_obj = json_object_get(response, "success");
    if (success_obj) {
        result = json_is_true(success_obj) ? 0 : -1;
    }
    json_decref(response);
    return result;
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
	DEBUG(0, ("Tracim: tracim_opendir(%s from %s).\n", fsp->fsp_name->base_name, fsp->fsp_name->stream_name));
    DIR *result = NULL;
    json_t *request, *response, *success_obj, *json_obj;
    struct tracim_data *data = get_tracim_data(handle);
    
    request = json_object();
    json_object_set_new(request, "op", json_string("opendir"));
    json_object_set_new(request, "path", json_string(fsp->fsp_name->base_name));
    json_object_set_new(request, "attr", json_integer(attr));
    json_object_set_new(request, "user", json_string(data->user));

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
		DEBUG(3, ("tracim: Failed to get response for readdir\n"));
		return SMB_VFS_NEXT_READDIR(handle, dirfsp, dirp);
	}
    success_obj = json_object_get(response, "success");
	if (success_obj) {
		if (json_is_true(success_obj)) {
			result = talloc(talloc_tos(), struct dirent);
			if (!result) {
				errno = ENOMEM;
				DEBUG(0, ("Tracim: tracim_readdir ERROR: ENOMEM\n"));
				return NULL;
			}
			entry_obj = json_object_get(response, "name");
			strncpy(result->d_name, json_string_value(entry_obj), sizeof(result->d_name) - 1);
			result->d_name[sizeof(result->d_name) - 1] = '\0';
			entry_obj = json_object_get(response, "ino");
			result->d_ino = json_integer_value(entry_obj);
			entry_obj = json_object_get(response, "type");
			result->d_type = (unsigned char)json_integer_value(entry_obj);
			DEBUG(0, ("tracim_readdir: '%s'\n", result->d_name));
		} else {
			entry_obj = json_object_get(response, "error");
			const char * v = json_string_value(entry_obj);
			if (strcmp("No more entries", v)!=0) {
				DEBUG(0, ("Tracim: tracim_readdir ERROR: %s\n", v));
			} else {
				DEBUG(0, ("Tracim: tracim_readdir: %s\n", v));
			}
		}
	} else {
		DEBUG(0, ("Tracim: tracim_readdir failed\n"));
	}
    json_decref(response);
	// result = SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);
    return result;
}
/**
 * @brief Custom closedir function to clean up our custom structure
 * 
 * @param handle 
 * @param dirp 
 * @return int 
 */
static int tracim_closedir(vfs_handle_struct *handle, DIR *dirp)
{
    struct vfs_example_dir *custom_dir = (struct vfs_example_dir *)dirp;
    int result = -1;
	json_t *request, *response, *success_obj, *entry_obj;
	int fd = (int)dirp;
    DEBUG(0, ("Tracim: tracim_closedir(%d)\n", fd));
    struct tracim_data *data = get_tracim_data(handle);
    if (!data) {
        DEBUG(0, ("tracim_closedir: Failed to get VFS tracim data\n"));
        return result;
    }

    request = json_object();
    json_object_set_new(request, "op", json_string("closedir"));
    json_object_set_new(request, "handle", json_integer(fd));
    json_object_set_new(request, "user", json_string(data->user));
    response = send_request(data, request);
    json_decref(request);
	if (!response) {
		DEBUG(0, ("tracim: Failed to get response for closedir\n"));
		return result;
	}
    success_obj = json_object_get(response, "success");
	if (!success_obj) {
		if (json_is_true(success_obj)) {
			result = 0;
		} else {
			entry_obj = json_object_get(response, "error");
			DEBUG(0, ("Tracim: tracim_closedir failed: %s\n", json_string_value(entry_obj)));
		}
	} else {
		DEBUG(0, ("Tracim: tracim_closedir failed\n"));
	}
    json_decref(response);
    return result;
}
enum ndr_err_code tracim_checker(struct ndr_push * s, ndr_flags_type ndr_flags, const void * r)
{
	return NDR_ERR_SUCCESS;
}
/**
 * @brief Fill the 'value', wich mustn't exceed 'size' bytes. Used by fget_ea_dos_attribute called by default create_file_fn.
 *  EA names used internally in Samba. KEEP UP TO DATE with prohibited_ea_names in trans2.c !.
 * "user.SAMBA_PAI"  EA to use for DOS attributes
 * "user.DOSATTRIB" Prefix for DosStreams in the vfs_streams_xattr module : Only one used?
 * "user.DosStream." Prefix for xattrs storing streams.
 * "user.SAMBA_STREAMS"  EA to use to store reparse points.
 * #define SAMBA_XATTR_REPARSE_ATTRIB "user.SmbReparse"
 * 
 * @param handle 
 * @param fsp 
 * @param name 
 * @param value 
 * @param size 
 * @return ssize_t : size of value
 */
ssize_t tracim_fgetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp,
	const char *name, void *value, size_t size)
{
	struct xattr_DOSATTRIB dosattrib;
	memset(&dosattrib, 0, sizeof(dosattrib));
	ssize_t result = size;
    DEBUG(0, ("Tracim: tracim_fgetxattr(%s, %s, %ld)\n", fsp->fsp_name->base_name, name, size));
	if (strcmp(name, SAMBA_XATTR_DOS_ATTRIB)==0) { // See set_ea_dos_attribute()
    	DEBUG(0, ("Tracim: tracim_fgetxattr(%s, %s, %ld) : SAMBA_XATTR_DOS_ATTRIB\n", fsp->fsp_name->base_name, name, size));
		uint32_t dosmode = FILE_ATTRIBUTE_NORMAL;
		// dosmode &= ~FILE_ATTRIBUTE_OFFLINE;
		DATA_BLOB blob;
		blob.data = (uint8_t *)value;
		blob.length = size;
		// user.DOSATTRIB : Read-Only = 0x1, Hidden = 0x2, System = 0x4, Archive = 0x20 : https://lists.samba.org/archive/samba/2015-August/193472.html
		dosattrib.version = 5;
		dosattrib.info.info5.attrib = dosmode;
		// XATTR_DOSINFO_ATTRIB ( 0x00000001 ), XATTR_DOSINFO_EA_SIZE ( 0x00000002 ), XATTR_DOSINFO_SIZE ( 0x00000004 ), 
		// XATTR_DOSINFO_ALLOC_SIZE ( 0x00000008 ), XATTR_DOSINFO_CREATE_TIME ( 0x00000010 ), XATTR_DOSINFO_CHANGE_TIME ( 0x00000020 ), XATTR_DOSINFO_ITIME ( 0x00000040 )
		dosattrib.info.info5.valid_flags = XATTR_DOSINFO_ATTRIB|XATTR_DOSINFO_CREATE_TIME;
		time_t rawtime = time(NULL);
		struct timespec ts = time_t_to_full_timespec(rawtime);
		dosattrib.info.info5.create_time = full_timespec_to_nt_time(&ts);
		enum ndr_err_code ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &dosattrib, 
			(ndr_push_flags_fn_t)ndr_push_xattr_DOSATTRIB);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("tracim_fgetxattr: ndr_push_struct_blob failed: %s\n",ndr_errstr(ndr_err)));
			return -1;
		}
		if (blob.data == NULL || blob.length == 0) {
			DEBUG(0, ("tracim_fgetxattr: no blob data: %p / %ld\n", blob.data, blob.length));
			return -1;
		}
		if (size < blob.length) {
			DEBUG(0, ("tracim_fgetxattr: not enougth space: %ld < %ld\n", size, blob.length));
            data_blob_free(&blob);
            errno = ERANGE;
            return -1;
        }
        memcpy(value, blob.data, blob.length);
		result = blob.length; // sizeof(struct xattr_DOSATTRIB);
	} else {
    	DEBUG(0, ("Tracim: tracim_fgetxattr(%s, %s, %ld) : unimplemented\n", fsp->fsp_name->base_name, name, size));
	}
	char * encoded = (char*)malloc(result*2+1);
	base64_encode(value, result, encoded);
    DEBUG(0, ("Tracim: tracim_fgetxattr(%s, %s, %ld) : %ld :%s\n", fsp->fsp_name->base_name, name, size, result, encoded));
	free(encoded);
	return result;
}
/**
 * @brief Fill 'list' : a char* of size 'size'.
 * 
 * @param handle 
 * @param fsp 
 * @param list : Return list of char* ssize_t char* separated by \0
 * @param size 
 * @return ssize_t 
 */
ssize_t tracim_flistxattr(struct vfs_handle_struct *handle, struct files_struct *fsp,
	char *list, size_t size)
{
    DEBUG(0, ("Tracim: tracim_flistxattr(%s) : \n", fsp->fsp_name->base_name));
	list[0] = '\0';
	return 0;
}
int tracim_fsetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp,
	const char *name, const void *value, size_t size, int flags)
{
	int result = -1;
    DEBUG(0, ("Tracim: tracim_fsetxattr(%s, %s=%s)\n", fsp->fsp_name->base_name, name, (char*)value));
    struct tracim_data *data = get_tracim_data(handle);
    if (!data) {
        DEBUG(0, ("tracim_fsetxattr: Failed to get VFS tracim data\n"));
        return result;
    }
	char * encoded = (char*)malloc(size*2+1);
	base64_encode(value, size, encoded);
    json_t *request = json_object();
    json_object_set_new(request, "op", json_string("xattr"));
    json_object_set_new(request, "path", json_string(fsp->fsp_name->base_name));
    json_object_set_new(request, "name", json_string(name));
    json_object_set_new(request, "value", json_string(encoded));
    json_object_set_new(request, "user", json_string(data->user));
    json_t *response = send_request(data, request);
    json_decref(request);
	free(encoded);
	if (!response) {
		DEBUG(0, ("tracim_fsetxattr: Failed to get response\n"));
		return result;
	}
    json_t *success_obj = json_object_get(response, "success");
	if (!success_obj) {
		if (json_is_true(success_obj)) {
			result = 0;
		} else {
			success_obj = json_object_get(response, "error");
			DEBUG(0, ("Tracim: tracim_fsetxattr failed: %s\n", json_string_value(success_obj)));
		}
	} else {
		DEBUG(0, ("Tracim: tracim_fsetxattr failed\n"));
	}
    json_decref(response);
	return 0;
}
int tracim_fremovexattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name)
{
    DEBUG(0, ("Tracim: tracim_fremovexattr(%s, %s) : TODO\n", fsp->fsp_name->base_name, name));
	return 0;
}

static ssize_t tracim_pread(vfs_handle_struct *handle, files_struct *fsp, 
                            void *data_buf, size_t n, off_t offset)
{
	int fd = fsp_get_pathref_fd(fsp);
	DEBUG(0, ("Tracim: tracim_pread(%d).\n", fd));
    ssize_t result = -1;
    struct tracim_data *data = get_tracim_data(handle);
    if (!data) {
        DEBUG(0, ("tracim_pread: Failed to get VFS tracim data\n"));
        return result;
    }
    json_t *request, *response, *success_obj, *data_obj;
    const char *encoded_data;
    
    request = json_object();
    json_object_set_new(request, "op", json_string("read"));
    json_object_set_new(request, "fd", json_integer(fd));
    json_object_set_new(request, "size", json_integer(n));
    json_object_set_new(request, "offset", json_integer(offset));
    response = send_request(data, request);
    json_decref(request);
    if (!response) {
        return -1;
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
                    memcpy(data_buf, encoded_data, decoded_len);
                    result = strlen(encoded_data);
                }
            }
        }
        data_obj = json_object_get(response, "size");
		if (data_obj && json_is_integer(data_obj)) {
			int size = json_integer_value(data_obj);
			if (size!=result) {
				DEBUG(0, ("Tracim: tracim_pread() : Warning : size conflict : %d VS %ld.\n", size, result));
				result = size;
			}
		}
    }
    
    json_decref(response);
    return result;
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
        return result;
    }
    
    /* Encode data as base64 - simplified version */
    encoded_data = talloc_array(NULL, char, n * 2); /* Rough size */
    if (!encoded_data) {
        return -1;
    }
    
    memcpy(encoded_data, data_buf, n);
    encoded_data[n] = '\0';
    request = json_object();
    json_object_set_new(request, "op", json_string("write"));
    json_object_set_new(request, "fd", json_integer(fsp_get_pathref_fd(fsp)));
    json_object_set_new(request, "data", json_string(encoded_data));
    json_object_set_new(request, "size", json_integer(n));
    json_object_set_new(request, "offset", json_integer(offset));
    response = send_request(data, request);
    json_decref(request);
    talloc_free(encoded_data);
    if (!response) {
        return -1;
    }
    success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
		result = n;
        bytes_obj = json_object_get(response, "size");
        if (bytes_obj && json_is_integer(bytes_obj)) {
            int size = json_integer_value(bytes_obj);
			if (size!=n) {
				DEBUG(0, ("Tracim: tracim_pwrite() : Warning : size conflict : %d VS %ld.\n", size, n));
				result = size;
			}
        }
    }
    json_decref(response);
    return result; // >= 0 ? result : SMB_VFS_NEXT_PWRITE(handle, fsp, data_buf, n, offset);
}
static off_t tracim_lseek(vfs_handle_struct *handle, files_struct *fsp, off_t offset, int whence)
{
    struct file_context *ctx = (struct file_context *)fsp->vfs_extension;
    off_t result;
    DEBUG(0, ("Tracim: tracim_lseek()\n"));

    /* if (!ctx || ctx->is_directory) {
        errno = EISDIR;
        return -1;
    }
    
    if (ctx->temp_path) {
        // Use standard lseek on temporary file
        result = lseek(fsp->fh->fd, offset, whence);
    } else {
        // Handle seeking for memory-based files
        result = handle_memory_lseek(ctx->db_path, fsp, offset, whence);
    } */

    return result;
}
/**
 * @brief Reports total disk space, available space, and free space for a filesystem.
 * 
 * @param handle : VFS handle structure
 * @param smb_fname : Path/filename to check (usually share root)
 * @param bsize : Bytes per allocation unit (block size)
 * @param dfree : Number of free allocation units
 * @param dsize : Total number of allocation units
 * @return uint64_t 
 */
uint64_t tracim_disk_free(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
    DEBUG(0, ("Tracim: tracim_disk_free() : TODO\n"));
    int ret = 0; // SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
  	*dfree = 1000;
	*bsize = 4096;
	*dsize = 1000;
    return ret;
}
int tracim_get_quota (struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt)
{
    DEBUG(0, ("Tracim: tracim_get_quota() : TODO\n"));
	qt->bsize = 4096;
	qt->hardlimit = 1000; // In bsize units
	qt->softlimit = 1000; // In bsize units
	qt->curblocks = 1; // In bsize units
	qt->ihardlimit = 1000; // inode hard limit.
	qt->isoftlimit = 1000; // inode soft limit.
	qt->curinodes = 1; // Current used inodes.

}

NTSTATUS tracim_create_file(struct vfs_handle_struct *handle,
				   struct smb_request *req,
				   struct files_struct *dirfsp,
				   struct smb_filename *smb_fname,
				   uint32_t access_mask,
				   uint32_t share_access,
				   uint32_t create_disposition,
				   uint32_t create_options,
				   uint32_t file_attributes,
				   uint32_t oplock_request,
				   const struct smb2_lease *lease,
				   uint64_t allocation_size,
				   uint32_t private_flags,
				   struct security_descriptor *sd,
				   struct ea_list *ea_list,
				   files_struct **result,
				   int *pinfo,
				   const struct smb2_create_blobs *in_context_blobs,
				   struct smb2_create_blobs *out_context_blobs)
{
    const char *fname = smb_fname->base_name;
    DEBUG(0, ("Tracim: tracim_create_file(%s)\n", fname));
    NTSTATUS status = NT_STATUS_OK;
    connection_struct *conn = handle->conn;
    int fd = -1;
    int open_flags = 0;
    mode_t mode = 0644;
    /* bool file_existed = false;
    struct stat st;
    int info = 0;
    *result = NULL;
    // Handle create disposition
    switch (create_disposition) {
        case FILE_SUPERSEDE:
            open_flags = O_CREAT | O_TRUNC | O_RDWR;
            info = file_existed ? FILE_WAS_SUPERSEDED : FILE_WAS_CREATED;
            break;
            
        case FILE_OPEN:
            if (!file_existed) {
                return NT_STATUS_OBJECT_NAME_NOT_FOUND;
            }
            open_flags = O_RDWR;
            info = FILE_WAS_OPENED;
            break;
            
        case FILE_CREATE:
            if (file_existed) {
                return NT_STATUS_OBJECT_NAME_COLLISION;
            }
            open_flags = O_CREAT | O_EXCL | O_RDWR;
            info = FILE_WAS_CREATED;
            break;
            
        case FILE_OPEN_IF:
            open_flags = O_CREAT | O_RDWR;
            info = file_existed ? FILE_WAS_OPENED : FILE_WAS_CREATED;
            break;
            
        case FILE_OVERWRITE:
            if (!file_existed) {
                return NT_STATUS_OBJECT_NAME_NOT_FOUND;
            }
            open_flags = O_TRUNC | O_RDWR;
            info = FILE_WAS_OVERWRITTEN;
            break;
            
        case FILE_OVERWRITE_IF:
            open_flags = O_CREAT | O_TRUNC | O_RDWR;
            info = file_existed ? FILE_WAS_OVERWRITTEN : FILE_WAS_CREATED;
            break;
        default:
            return NT_STATUS_INVALID_PARAMETER;
    }
    if (access_mask & FILE_WRITE_DATA) {
        // Already set O_RDWR above
    } else if (access_mask & FILE_READ_DATA) {
        open_flags &= ~O_RDWR;
        open_flags |= O_RDONLY;
    }

    if (create_options & FILE_DELETE_ON_CLOSE) {
        DBG_DEBUG("Delete on close requested for %s\n", fname);
    } */
    
	struct tracim_data *data = get_tracim_data(handle);
	json_t *request, *response, *success_obj, *bytes_obj;
	char *encoded_data;
	if (!data) {
		return NT_STATUS_ABANDONED;
	}
	request = json_object();
	json_object_set_new(request, "op", json_string("create"));
	json_object_set_new(request, "path", json_string(fname));
	json_object_set_new(request, "flags", json_integer(open_flags));
	json_object_set_new(request, "mode", json_integer(mode));
	json_object_set_new(request, "size", json_integer(allocation_size));
	json_object_set_new(request, "attr", json_integer(file_attributes));
    if (create_options & FILE_DIRECTORY_FILE) {
		json_object_set_new(request, "dir", json_integer(1));
        if (mkdir(fname, 0755) != 0) {
            if (errno == EEXIST && create_disposition == FILE_OPEN_IF) {
				DEBUG(0, ("tracim_create_file: FILE_DIRECTORY_FILE/FILE_OPEN_IF : %s.\n", fname));
            } else {
				DEBUG(0, ("tracim_create_file: FILE_DIRECTORY_FILE/not FILE_OPEN_IF : %s.\n", fname));
            }
        }
        fd = -1;
    } else {
		json_object_set_new(request, "dir", json_integer(0));
		DEBUG(0, ("tracim_create_file: SIMPLE_FILE : %s.\n", fname));
    }
	response = send_request(data, request);
	json_decref(request);
	if (!response) {
		return NT_STATUS_ABANDONED;
	}
	success_obj = json_object_get(response, "success");
	if (success_obj && json_is_true(success_obj)) {
		success_obj = json_object_get(response, "fd");
		if (success_obj && json_is_integer(success_obj)) {
			fd = json_integer_value(success_obj);
		}
	} else {
		success_obj = json_object_get(response, "error");
		if (success_obj) {
			DEBUG(0, ("tracim_create_file: ERROR creating %s : %s.", fname, json_string_value(success_obj)));
			return NT_STATUS_ABANDONED;
		}
	}
	json_decref(response);
	/*
    DEBUG(0, ("Tracim: tracim_create_file() : fsp_new\n"));
	// status = fsp_new(conn, conn, &fsp);
	// if (!NT_STATUS_IS_OK(status)) {
	// 	return status;
	// }
    status = file_new(req, conn, &fsp);
    if (!NT_STATUS_IS_OK(status)) {
        if (fd != -1) close(fd);
        return status;
    }
    DEBUG(0, ("Tracim: tracim_create_file() : cp_smb_filename\n"));
    fsp->fsp_name = cp_smb_filename(fsp, smb_fname);
	fsp_set_fd(fsp, fd);
    if (fsp->fsp_name == NULL) {
        file_free(req, fsp);
        if (fd != -1) close(fd);
        return NT_STATUS_NO_MEMORY;
    }
    // fsp->fh->position_information = 0;
    // fsp->fh->private_options = private_flags;
    fsp->access_mask = access_mask;
    fsp->share_mode_flags = share_access;
    // fsp->fh->gen_id = get_gen_count();
    
    if (create_options & FILE_DIRECTORY_FILE) {
        fsp->fsp_flags.is_directory = true;
		fsp_set_fd(fsp, fd);
    } else {
        fsp->fsp_flags.is_directory = false;
        // if (fstat(fd, &st) == 0) {
            // fsp->file_id = vfs_file_id_from_sbuf(conn, &st);
            // fsp->fh->file_size = st.st_size;
        // }
    }
    fsp->oplock_type = NO_OPLOCK;
    if (oplock_request != NO_OPLOCK) {
        fsp->oplock_type = EXCLUSIVE_OPLOCK;
    } */
    
	// status = create_file_tracim(
	// 	handle->conn, req, dirfsp, smb_fname,
	// 	access_mask, share_access,
	// 	create_disposition, create_options,
	// 	file_attributes, oplock_request,
	// 	lease,
	// 	allocation_size, private_flags,
	// 	sd, ea_list, result,
	// 	pinfo, in_context_blobs, out_context_blobs);
	// smb_fname->st.st_ex_nlink = 1; // To force VALID_STAT to say file exists.
	status = SMB_VFS_NEXT_CREATE_FILE(
		handle, req, dirfsp, smb_fname,
		access_mask, share_access,
		create_disposition, create_options,
		file_attributes, oplock_request,
		lease,
		allocation_size, private_flags,
		sd, ea_list, result,
		pinfo, in_context_blobs, out_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
    	DEBUG(0, ("tracim_create_file: ERROR : Fail created file: %s (fd=%d), force : TODO\n", fname, fd));
		return status;
	}
    // Add to files_struct list
    // DLIST_ADD(conn->sconn->files, fsp);
    // conn->num_files_open++;
    DEBUG(0, ("tracim_create_file: Successfully created file: %s (fd=%d)\n", fname, fd));
	// fsp_set_fd(smb_fname->fsp, fd);
	/* *result = fsp;
    if (pinfo) {
        *pinfo = info;
    } */
    return status;
}

/* Values for the second argument to `fcntl'.  */
// 
/**
 * @brief Used to set/get metadata like blocking file. We need to implement it because otherwise it's samba use FS call on our fd.
 * 
 * @param handle
 * @param fsp
 * @param cmd
 * @param cmd_arg 
 * @return int 
 */
static int tracim_fcntl(vfs_handle_struct *handle, files_struct *fsp, int cmd, va_list cmd_arg)
{
    int fd = fsp_get_pathref_fd(fsp);
    DEBUG(0, ("Tracim: tracim_fcntl(cmd=%d on fd=%d)\n", cmd, fd));
	/*
	 * SMB_VFS_FCNTL() is currently only called by vfs_set_blocking() to
	 * clear O_NONBLOCK, etc for LOCK_MAND and FIFOs. Ignore it.
	 */
	if (cmd == F_GETFL) {
		return 0;
	} else if (cmd == F_SETFL) {
		va_list dup_cmd_arg;
		int opt;
		va_copy(dup_cmd_arg, cmd_arg);
		opt = va_arg(dup_cmd_arg, int);
		va_end(dup_cmd_arg);
		if (opt == 0) {
			return 0;
		}
		DBG_ERR("tracim_fcntl : unexpected fcntl SETFL(%d)\n", opt);
		goto err_out;
	}
	DBG_ERR("tracim_fcntl : unexpected fcntl: %d\n", cmd);
err_out:
	errno = EINVAL;
	return -1;
}
/**
 * @brief https://lwn.net/Articles/586904/
 * 
 * @param handle 
 * @param fd 
 * @param cmd 
 * @param flock 
 * @return int 
 */
int tracim_posix_lock(vfs_handle_struct *handle, int fd, int cmd, struct flock *flock)
{
	struct tracim_data *data = get_tracim_data(handle);
	char *encoded_data;
	if (!data) {
		return -1;
	}
    DEBUG(0, ("Tracim: tracim_lock(fd=%d, op=%d)\n", fd, cmd));
	char * op;
	json_t *request = json_object();
	if (cmd == F_SETLK || cmd == F_SETLKW) {
		flock->l_pid = getpid();
		json_object_set_new(request, "len", json_integer(flock->l_len));
		json_object_set_new(request, "pid", json_integer(flock->l_pid));
		json_object_set_new(request, "start", json_integer(flock->l_start));
		char * type;
		if(flock->l_type & F_RDLCK) {
			if(flock->l_type & F_WRLCK) {
				type = "rw";
			} else type = "r";
		} else if(flock->l_type & F_WRLCK) {
			type = "w";
		} else if(flock->l_type == F_UNLCK) {
			type = "un";
		}
		json_object_set_new(request, "type", json_string(type));
		char * whence;
		switch(flock->l_whence) {
			case SEEK_SET:
				whence = "set";
				break;
			case SEEK_CUR:
				whence = "cur";
				break;
			default: // case SEEK_END:
				whence = "end";
				break;
		}
		json_object_set_new(request, "whence", json_string(whence));
	} else if (cmd == F_GETLK) {
	}
	json_object_set_new(request, "op", json_string("lock"));
	json_object_set_new(request, "fd", json_integer(fd));
	json_t *response = send_request(data, request);
	json_decref(request);
    if (!response) {
        DEBUG(0, ("tracim_lock: ERROR : Failed to get response\n"));
        return -1; // SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }
    json_t *success_obj = json_object_get(response, "success");
    if (success_obj && json_is_true(success_obj)) {
		if (cmd == F_SETLK || cmd == F_SETLKW) {
			DEBUG(0, ("tracim_lock: S.\n"));
		} else if (cmd == F_GETLK) {
			DEBUG(0, ("tracim_lock: G.\n"));
			success_obj = json_object_get(response, "len");
			if(success_obj && json_is_integer(success_obj)) {
				flock->l_len = json_integer_value(success_obj);
			}
			success_obj = json_object_get(response, "pid");
			if(success_obj && json_is_integer(success_obj)) {
				flock->l_pid = json_integer_value(success_obj);
			}
			success_obj = json_object_get(response, "start");
			if(success_obj && json_is_integer(success_obj)) {
				flock->l_start = json_integer_value(success_obj);
			}
			success_obj = json_object_get(response, "type");
			if(success_obj && json_is_string(success_obj)) {
				const char *str = json_string_value(success_obj);
				flock->l_type = 0;
				if (strcmp(str, "un") == 0) {
					flock->l_type = F_UNLCK;
				} else {
					if (strstr(str, "w") != NULL) {
						flock->l_type |= F_WRLCK;
					}
					if (strstr(str, "r") != NULL) {
						flock->l_type |= F_RDLCK;
					}
				}
			}
			success_obj = json_object_get(response, "whence");
			if(success_obj && json_is_string(success_obj)) {
				const char *str = json_string_value(success_obj);
				flock->l_whence = 0;
				if (strcmp(str, "set") == 0) {
					flock->l_whence = SEEK_SET;
				} else if (strcmp(str, "cur") == 0) {
					flock->l_whence = SEEK_CUR;
				} else if (strcmp(str, "end") == 0) {
					flock->l_whence = SEEK_END;
				}
			}
		}
    } else {
		success_obj = json_object_get(response, "error");
		if (success_obj) {
			DEBUG(0, ("tracim_lock() : ERROR : %s.", json_string_value(success_obj)));
  			json_decref(response);
			return -1;
		}
    }
    json_decref(response);
	return 0;
}
int tracim_truncate(vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
	struct tracim_data *data = get_tracim_data(handle);
	char *encoded_data;
	if (!data) {
		return -1;
	}
	int result = 0;
    int fd = fsp_get_pathref_fd(fsp);
    DEBUG(0, ("Tracim: tracim_truncate(fd=%d)\n", fd));
    json_t *request = json_object();
    json_object_set_new(request, "op", json_string("truncate"));
    json_object_set_new(request, "fd", json_integer(fd));
    json_object_set_new(request, "user", json_string(data->user));
    json_t *response = send_request(data, request);
    json_decref(request);
    if (response) {
		json_t *success_obj = json_object_get(response, "success");
		if (success_obj && json_is_true(success_obj)) {
			result = 0;
		} else {
			result = -1;
			success_obj = json_object_get(response, "error");
			DEBUG(0, ("Tracim: tracim_connect() failed: %s\n", json_string_value(success_obj)));
		}
	} else {
        DEBUG(0, ("tracim_connect: Failed to get response for open\n"));
        return -1;
    }
    json_decref(response);
	return result;
}

int tracim_allocate(vfs_handle_struct *handle, files_struct *fsp,
			uint32_t mode, off_t offset, off_t len)
{
	struct tracim_data *data = get_tracim_data(handle);
	char *encoded_data;
	if (!data) {
		return -1;
	}
	int result = 0;
    int fd = fsp_get_pathref_fd(fsp);
    DEBUG(0, ("Tracim: vfswrap_allocate(fd=%d)\n", fd));
    json_t *request = json_object();
    json_object_set_new(request, "op", json_string("allocate"));
    json_object_set_new(request, "fd", json_integer(fd));
    json_object_set_new(request, "offset", json_integer(offset));
    json_object_set_new(request, "len", json_integer(len));
    json_object_set_new(request, "user", json_string(data->user));
    json_t *response = send_request(data, request);
    json_decref(request);
    if (response) {
		json_t *success_obj = json_object_get(response, "success");
		if (success_obj && json_is_true(success_obj)) {
			result = 0;
		} else {
			result = -1;
			success_obj = json_object_get(response, "error");
			DEBUG(0, ("Tracim: tracim_connect() failed: %s\n", json_string_value(success_obj)));
		}
	} else {
        DEBUG(0, ("tracim_connect: Failed to get response for open\n"));
        return -1;
    }
    json_decref(response);
	return result;
}
/**
 * @brief 
 * 
 * @param handle 
 * @param fsp 
 * @param op 
 * @param offset 
 * @param count 
 * @param type
 * @return true 
 * @return false 
 */
static bool tracim_lock(struct vfs_handle_struct *handle,
			     files_struct *fsp, int op, off_t offset,
			     off_t count, int type)
{
    int fd = fsp_get_pathref_fd(fsp);
    DEBUG(0, ("Tracim: tracim_lock(op=%d on fd=%d)\n", op, fd));
	struct flock flock = { 0, };
	int ret;
	bool ok = false;
	flock.l_type = type; // F_RDLCK  F_WRLCK  F_UNLCK
	flock.l_whence = SEEK_SET; // SEEK_SET SEEK_CUR SEEK_END
	flock.l_start = offset;
	flock.l_len = count;
	flock.l_pid = 0;
	ret = tracim_posix_lock(handle, fd, op, &flock);
	if (op == F_GETLK) {
		/* lock query, true if someone else has locked */
		if ((ret != -1) &&
		    (flock.l_type != F_UNLCK) &&
		    (flock.l_pid != 0) && (flock.l_pid != getpid())) {
			ok = true;
			goto out;
		}
		ok = false;
		goto out;
	}
	if (ret == -1) {
		ok = false;
		goto out;
	}
	ok = true;
out:
	return ok;
}
/**
 * @brief 
 * 
 * @param handle 
 * @param fsp 
 * @param poffset 
 * @param pcount 
 * @param ptype 
 * @param ppid 
 * @return true 
 * @return false 
 */
static bool tracim_getlock(struct vfs_handle_struct *handle,
				files_struct *fsp, off_t *poffset,
				off_t *pcount, int *ptype, pid_t *ppid)
{
    int fd = fsp_get_pathref_fd(fsp);
    DEBUG(0, ("Tracim: tracim_lockget(fd=%d)\n", fd));
	struct flock flock = { 0, };
	int ret;
	flock.l_type = *ptype;
	flock.l_whence = SEEK_SET;
	flock.l_start = *poffset;
	flock.l_len = *pcount;
	flock.l_pid = 0;
	ret = tracim_posix_lock(handle, fd, F_GETLK, &flock);
	if (ret == -1) {
		return false;
	}
	*ptype = flock.l_type;
	*poffset = flock.l_start;
	*pcount = flock.l_len;
	*ppid = flock.l_pid;
	return true;
}

/* VFS operations structure for Samba 4.x : Not ok before */
static struct vfs_fn_pointers tracim_functions = {
    .connect_fn = tracim_connect,
    .disconnect_fn = tracim_disconnect,
    .openat_fn = tracim_openat,
    .close_fn = tracim_close,

	.stat_fn = tracim_stat,
	.fstat_fn = tracim_fstat,
	.fstatat_fn = tracim_fstatat,
	.lstat_fn = tracim_lstat,
 
    .pread_fn = tracim_pread,
	.lseek_fn = tracim_lseek,
    .pwrite_fn = tracim_pwrite,
    .unlinkat_fn = tracim_unlinkat,

    .fgetxattr_fn = tracim_fgetxattr,
    .fsetxattr_fn = tracim_fsetxattr,
    .fremovexattr_fn = tracim_fremovexattr,
    .flistxattr_fn = tracim_flistxattr,
 
    .fdopendir_fn = tracim_opendir,
    .readdir_fn = tracim_readdir,
    .closedir_fn = tracim_closedir,

	.file_id_create_fn = NULL,
	.fstreaminfo_fn = NULL,
	.brl_lock_windows_fn = NULL,
	.brl_unlock_windows_fn = NULL,
	.strict_lock_check_fn = NULL,
	.translate_name_fn = NULL,
	.fsctl_fn = NULL,
	/* NT ACL Operations */
	.fget_nt_acl_fn = NULL,
	.fset_nt_acl_fn = NULL,
	.audit_file_fn = NULL,

	.disk_free_fn = tracim_disk_free,
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	// .get_quota_fn = tracim_get_quota
	.create_file_fn = tracim_create_file,
	.renameat_fn = tracim_renameat,
	.fcntl_fn = tracim_fcntl,

	.lock_fn = tracim_lock,
	.getlock_fn = tracim_getlock,
	// .brl_lock_windows_fn = vfswrap_brl_lock_windows,
	// .brl_unlock_windows_fn = vfswrap_brl_unlock_windows,
	// .strict_lock_check_fn = vfswrap_strict_lock_check,
	// For best performances : pread_recv_fn && pread_send_fn && pwrite_recv_fn && pwrite_send_fn
	.ftruncate_fn = tracim_truncate,
	.fallocate_fn = tracim_allocate
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