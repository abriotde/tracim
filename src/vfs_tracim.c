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
#include "system/filesys.h"
#include "security.h"
#include "fake_file.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/sys_rw.h"
#include "../librpc/gen_ndr/ioctl.h" // For create_file_unixpath()
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

/**
 * @brief Copy of create_file_unixpath from open.c. : Wrapper around open_file_ntcreate and open_directory
 * 
 */
static NTSTATUS create_file_unixpath(connection_struct *conn,
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
				     int *pinfo)
{
	struct smb2_lease none_lease;
	int info = FILE_WAS_OPENED;
	files_struct *base_fsp = NULL;
	files_struct *fsp = NULL;
	bool free_fsp_on_error = false;
	NTSTATUS status;
	int ret;
	struct smb_filename *parent_dir_fname = NULL;
	struct smb_filename *smb_fname_atname = NULL;

	DBG_DEBUG("access_mask = 0x%"PRIx32" "
		  "file_attributes = 0x%"PRIx32" "
		  "share_access = 0x%"PRIx32" "
		  "create_disposition = 0x%"PRIx32" "
		  "create_options = 0x%"PRIx32" "
		  "oplock_request = 0x%"PRIx32" "
		  "private_flags = 0x%"PRIx32" "
		  "ea_list = %p, "
		  "sd = %p, "
		  "fname = %s\n",
		  access_mask,
		  file_attributes,
		  share_access,
		  create_disposition,
		  create_options,
		  oplock_request,
		  private_flags,
		  ea_list,
		  sd,
		  smb_fname_str_dbg(smb_fname));

	if (create_options & FILE_OPEN_BY_FILE_ID) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto fail;
	}

	if (create_options & NTCREATEX_OPTIONS_INVALID_PARAM_MASK) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (!(create_options & FILE_OPEN_REPARSE_POINT) &&
	    (smb_fname->fsp != NULL) && /* new files don't have an fsp */
	    VALID_STAT(smb_fname->fsp->fsp_name->st))
	{
		mode_t type = (smb_fname->fsp->fsp_name->st.st_ex_mode &
			       S_IFMT);

		switch (type) {
		case S_IFREG:
			FALL_THROUGH;
		case S_IFDIR:
			break;
		case S_IFLNK:
			/*
			 * We should never get this far with a symlink
			 * "as such". Report as not existing.
			 */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			goto fail;
		default:
			status = NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED;
			goto fail;
		}
	}

	if (req == NULL) {
		oplock_request |= INTERNAL_OPEN_ONLY;
	}

	if (lease != NULL) {
		uint16_t epoch = lease->lease_epoch;
		uint16_t version = lease->lease_version;

		if (req == NULL) {
			DBG_WARNING("Got lease on internal open\n");
			status = NT_STATUS_INTERNAL_ERROR;
			goto fail;
		}
		DEBUG(0, ("Tracim: create_file_unixpath() - TODO : Not implemented part : lease_match.\n"));
		// Try to ignore that part
		/* status = lease_match(conn,
				req,
				&lease->lease_key,
				conn->connectpath,
				smb_fname,
				&version,
				&epoch);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OPLOCK_NOT_GRANTED)) {
			// Dynamic share file. No leases and update epoch...
			none_lease = *lease;
			none_lease.lease_state = SMB2_LEASE_NONE;
			none_lease.lease_epoch = epoch;
			none_lease.lease_version = version;
			lease = &none_lease;
		} else if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		} */
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && (access_mask & DELETE_ACCESS)
	    && !is_named_stream(smb_fname)) {
		DEBUG(0, ("Tracim: create_file_unixpath() - TODO : Not implemented part : open_streams_for_delete.\n"));
		/* // We can't open a file with DELETE access if any of the
		// streams is open without FILE_SHARE_DELETE
		status = open_streams_for_delete(conn, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		} */
	}

	if (access_mask & SEC_FLAG_SYSTEM_SECURITY) {
		bool ok;

		ok = security_token_has_privilege(get_current_nttok(conn),
						  SEC_PRIV_SECURITY);
		if (!ok) {
			DBG_DEBUG("open on %s failed - "
				"SEC_FLAG_SYSTEM_SECURITY denied.\n",
				smb_fname_str_dbg(smb_fname));
			status = NT_STATUS_PRIVILEGE_NOT_HELD;
			goto fail;
		}

		if (conn_using_smb2(conn->sconn) &&
		    (access_mask == SEC_FLAG_SYSTEM_SECURITY))
		{
			/*
			 * No other bits set. Windows SMB2 refuses this.
			 * See smbtorture3 SMB2-SACL test.
			 *
			 * Note this is an SMB2-only behavior,
			 * smbtorture3 SMB1-SYSTEM-SECURITY already tests
			 * that SMB1 allows this.
			 */
			status = NT_STATUS_ACCESS_DENIED;
			goto fail;
		}
	}

	/*
	 * Files or directories can't be opened DELETE_ON_CLOSE without
	 * delete access.
	 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=13358
	 */
	if ((create_options & FILE_DELETE_ON_CLOSE) &&
	    ((access_mask & DELETE_ACCESS) == 0)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && is_named_stream(smb_fname))
	{
		uint32_t base_create_disposition;
		struct smb_filename *smb_fname_base = NULL;
		uint32_t base_privflags;

		if (create_options & FILE_DIRECTORY_FILE) {
			DBG_DEBUG("Can't open a stream as directory\n");
			status = NT_STATUS_NOT_A_DIRECTORY;
			goto fail;
		}

		switch (create_disposition) {
		case FILE_OPEN:
			base_create_disposition = FILE_OPEN;
			break;
		default:
			base_create_disposition = FILE_OPEN_IF;
			break;
		}

		smb_fname_base = cp_smb_filename_nostream(
			talloc_tos(), smb_fname);

		if (smb_fname_base == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		/*
		 * We may be creating the basefile as part of creating the
		 * stream, so it's legal if the basefile doesn't exist at this
		 * point, the create_file_unixpath() below will create it. But
		 * if the basefile exists we want a handle so we can fstat() it.
		 */

		ret = vfs_stat(conn, smb_fname_base);
		if (ret == -1 && errno != ENOENT) {
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(smb_fname_base);
			goto fail;
		}
		if (ret == 0) {
			status = openat_pathref_fsp(conn->cwd_fsp,
						    smb_fname_base);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("open_smb_fname_fsp [%s] failed: %s\n",
					smb_fname_str_dbg(smb_fname_base),
					nt_errstr(status));
				TALLOC_FREE(smb_fname_base);
				goto fail;
			}

			DEBUG(0, ("Tracim: create_file_unixpath() - TODO : Not implemented part : check_base_file_access.\n"));
			/*
			// * https://bugzilla.samba.org/show_bug.cgi?id=10229
			// * We need to check if the requested access mask
			// * could be used to open the underlying file (if
			// * it existed), as we're passing in zero for the
			// * access mask to the base filename.
			status = check_base_file_access(smb_fname_base->fsp,
							access_mask);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(10, ("Permission check "
					"for base %s failed: "
					"%s\n", smb_fname->base_name,
					nt_errstr(status)));
				TALLOC_FREE(smb_fname_base);
				goto fail;
			}*/
		}

		base_privflags = NTCREATEX_FLAG_STREAM_BASEOPEN;

		/* Open the base file. */
		status = create_file_unixpath(conn,
					      NULL,
					      dirfsp,
					      smb_fname_base,
					      0,
					      FILE_SHARE_READ
					      | FILE_SHARE_WRITE
					      | FILE_SHARE_DELETE,
					      base_create_disposition,
					      0,
					      0,
					      0,
					      NULL,
					      0,
					      base_privflags,
					      NULL,
					      NULL,
					      &base_fsp,
					      NULL);
		TALLOC_FREE(smb_fname_base);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("create_file_unixpath for base %s failed: "
				   "%s\n", smb_fname->base_name,
				   nt_errstr(status)));
			goto fail;
		}
	}

	if (smb_fname->fsp != NULL) {

		fsp = smb_fname->fsp;

		/*
		 * We're about to use smb_fname->fsp for the fresh open.
		 *
		 * Every fsp passed in via smb_fname->fsp already
		 * holds a fsp->fsp_name. If it is already this
		 * fsp->fsp_name that we got passed in as our input
		 * argument smb_fname, these two are assumed to have
		 * the same lifetime: Every fsp hangs of "conn", and
		 * fsp->fsp_name is its talloc child.
		 */

		if (smb_fname != smb_fname->fsp->fsp_name) {
			/*
			 * "smb_fname" is temporary in this case, but
			 * the destructor of smb_fname would also tear
			 * down the fsp we're about to use. Unlink
			 * them from each other.
			 */
			smb_fname_fsp_unlink(smb_fname);

			/*
			 * "fsp" is ours now
			 */
			free_fsp_on_error = true;
		}

		status = fsp_bind_smb(fsp, req);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		if (fsp_is_alternate_stream(fsp)) {
			struct files_struct *tmp_base_fsp = fsp->base_fsp;

			fsp_set_base_fsp(fsp, NULL);

			fd_close(tmp_base_fsp);
			file_free(NULL, tmp_base_fsp);
		}
	} else {
		/*
		 * No fsp passed in that we can use, create one
		 */
		status = file_new(req, conn, &fsp);
		if(!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		free_fsp_on_error = true;

		status = fsp_set_smb_fname(fsp, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	SMB_ASSERT(fsp->fsp_name->fsp != NULL);
	SMB_ASSERT(fsp->fsp_name->fsp == fsp);

	if (base_fsp) {
		/*
		 * We're opening the stream element of a
		 * base_fsp we already opened. Set up the
		 * base_fsp pointer.
		 */
		fsp_set_base_fsp(fsp, base_fsp);
	}

	if (dirfsp != NULL) {
		status = SMB_VFS_PARENT_PATHNAME(
			conn,
			talloc_tos(),
			smb_fname,
			&parent_dir_fname,
			&smb_fname_atname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	} else {
		/*
		 * Get a pathref on the parent. We can re-use this for
		 * multiple calls to check parent ACLs etc. to avoid
		 * pathname calls.
		 */
		status = parent_pathref(talloc_tos(),
					conn->cwd_fsp,
					smb_fname,
					&parent_dir_fname,
					&smb_fname_atname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		dirfsp = parent_dir_fname->fsp;
		status = fsp_set_smb_fname(dirfsp, parent_dir_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	/*
	 * If it's a request for a directory open, deal with it separately.
	 */

	if (create_options & FILE_DIRECTORY_FILE) {

		if (create_options & FILE_NON_DIRECTORY_FILE) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}

		/* Can't open a temp directory. IFS kit test. */
		if (!(file_attributes & FILE_FLAG_POSIX_SEMANTICS) &&
		     (file_attributes & FILE_ATTRIBUTE_TEMPORARY)) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}

		DEBUG(0, ("Tracim: create_file_unixpath() - TODO : Not implemented part : open_directory.\n"));
		/*
		 // * We will get a create directory here if the Win32
		 // * app specified a security descriptor in the
		 // * CreateDirectory() call.		 
		oplock_request = 0;
		status = open_directory(conn,
					req,
					access_mask,
					share_access,
					create_disposition,
					create_options,
					file_attributes,
					dirfsp->fsp_name,
					smb_fname_atname,
					&info,
					fsp);
		*/
	} else {

		/*
		 * Ordinary file case.
		 */

		if (allocation_size) {
			fsp->initial_allocation_size = smb_roundup(fsp->conn,
							allocation_size);
		}
		/*
		status = open_file_ntcreate(conn,
					    req,
					    access_mask,
					    share_access,
					    create_disposition,
					    create_options,
					    file_attributes,
					    oplock_request,
					    lease,
					    private_flags,
					    dirfsp->fsp_name,
					    smb_fname_atname,
					    &info,
					    fsp);
		if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_IS_A_DIRECTORY)) {

			// A stream open never opens a directory
			if (base_fsp) {
				status = NT_STATUS_FILE_IS_A_DIRECTORY;
				goto fail;
			}

			// * Fail the open if it was explicitly a non-directory
			// * file.
			if (create_options & FILE_NON_DIRECTORY_FILE) {
				status = NT_STATUS_FILE_IS_A_DIRECTORY;
				goto fail;
			}
			DEBUG(0, ("Tracim: create_file_unixpath() - TODO : Not implemented part : open_directory2.\n"));
			oplock_request = 0;
			/* status = open_directory(conn,
						req,
						access_mask,
						share_access,
						create_disposition,
						create_options,
						file_attributes,
						dirfsp->fsp_name,
						smb_fname_atname,
						&info,
						fsp);
			* /
		}
		*/
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	fsp->fsp_flags.is_fsa = true;

	if ((ea_list != NULL) &&
	    ((info == FILE_WAS_CREATED) || (info == FILE_WAS_OVERWRITTEN))) {
		status = set_ea(conn, fsp, ea_list);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	if (!fsp->fsp_flags.is_directory &&
	    S_ISDIR(fsp->fsp_name->st.st_ex_mode))
	{
		status = NT_STATUS_ACCESS_DENIED;
		goto fail;
	}

	/* Save the requested allocation size. */
	if ((info == FILE_WAS_CREATED) || (info == FILE_WAS_OVERWRITTEN)) {
		if ((allocation_size > (uint64_t)fsp->fsp_name->st.st_ex_size)
		    && !(fsp->fsp_flags.is_directory))
		{
			fsp->initial_allocation_size = smb_roundup(
				fsp->conn, allocation_size);
			if (vfs_allocate_file_space(
				    fsp, fsp->initial_allocation_size) == -1) {
				status = NT_STATUS_DISK_FULL;
				goto fail;
			}
		} else {
			fsp->initial_allocation_size = smb_roundup(
				fsp->conn, (uint64_t)fsp->fsp_name->st.st_ex_size);
		}
	} else {
		fsp->initial_allocation_size = 0;
	}

	if ((info == FILE_WAS_CREATED) &&
	    lp_nt_acl_support(SNUM(conn)) &&
	    !fsp_is_alternate_stream(fsp)) {
		if (sd != NULL) {
			/*
			 * According to the MS documentation, the only time the security
			 * descriptor is applied to the opened file is iff we *created* the
			 * file; an existing file stays the same.
			 *
			 * Also, it seems (from observation) that you can open the file with
			 * any access mask but you can still write the sd. We need to override
			 * the granted access before we call set_sd
			 * Patch for bug #2242 from Tom Lackemann <cessnatomny@yahoo.com>.
			 */

			uint32_t sec_info_sent;
			uint32_t saved_access_mask = fsp->access_mask;

			sec_info_sent = get_sec_info(sd);

			fsp->access_mask = FILE_GENERIC_ALL;

			if (sec_info_sent & (SECINFO_OWNER|
						SECINFO_GROUP|
						SECINFO_DACL|
						SECINFO_SACL)) {
				status = set_sd(fsp, sd, sec_info_sent);
			}

			fsp->access_mask = saved_access_mask;

			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}
		} else if (lp_inherit_acls(SNUM(conn))) {
			DEBUG(0, ("Tracim: create_file_unixpath() - TODO : Not implemented part : inherit_new_acl.\n"));
			/* // Inherit from parent. Errors here are not fatal.
			status = inherit_new_acl(dirfsp, fsp);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(10,("inherit_new_acl: failed for %s with %s\n",
					fsp_str_dbg(fsp),
					nt_errstr(status) ));
			} */
		}
	}

	if ((conn->fs_capabilities & FILE_FILE_COMPRESSION)
	 && (create_options & FILE_NO_COMPRESSION)
	 && (info == FILE_WAS_CREATED)) {
		status = SMB_VFS_SET_COMPRESSION(conn, fsp, fsp,
						 COMPRESSION_FORMAT_NONE);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("failed to disable compression: %s\n",
				  nt_errstr(status)));
		}
	}

	DEBUG(10, ("create_file_unixpath: info=%d\n", info));

	*result = fsp;
	if (pinfo != NULL) {
		*pinfo = info;
	}

	smb_fname->st = fsp->fsp_name->st;

	TALLOC_FREE(parent_dir_fname);

	return NT_STATUS_OK;

 fail:
	DEBUG(10, ("create_file_unixpath: %s\n", nt_errstr(status)));

	if (fsp != NULL) {
		/*
		 * The close_file below will close
		 * fsp->base_fsp.
		 */
		base_fsp = NULL;
		close_file_smb(req, fsp, ERROR_CLOSE);
		if (free_fsp_on_error) {
			file_free(req, fsp);
			fsp = NULL;
		}
	}
	if (base_fsp != NULL) {
		close_file_free(req, &base_fsp, ERROR_CLOSE);
	}

	TALLOC_FREE(parent_dir_fname);

	return status;
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
        return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
    }
	char * path = smb_fname->base_name;
	if (smb_fname->fsp && smb_fname->fsp->fsp_name && smb_fname->fsp->fsp_name->base_name && strlen(smb_fname->fsp->fsp_name->base_name)>1) {
		path = smb_fname->fsp->fsp_name->base_name;
	}
    request = json_object();
    json_object_set_new(request, "op", json_string("unlink"));
    json_object_set_new(request, "path", json_string(path));
    json_object_set_new(request, "flags", json_integer(flags));
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
/**
 * @brief Fill the 'value', wich mustn't exceed 'size' bytes
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
    DEBUG(0, ("Tracim: tracim_fgetxattr(%s, %s, %ld)\n", fsp->fsp_name->base_name, name, size));
	// * user.DOSATTRIB : Read-Only = 0x1, Hidden = 0x2, System = 0x4, Archive = 0x20 : https://lists.samba.org/archive/samba/2015-August/193472.html
	ssize_t result = 0;
	memset(value, 0, size);
	// ssize_t result = SMB_VFS_NEXT_GETXATTR(handle, fsp, name, value, size);
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
    DEBUG(0, ("Tracim: tracim_fsetxattr(%s, %s=%s) : TODO\n", fsp->fsp_name->base_name, name, (char*)value));
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
	int fd = fsp_get_io_fd(fsp);
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
	DEBUG(0, ("Tracim: tracim_pwrite() : TODO.\n"));
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
    json_object_set_new(request, "fd", json_integer(fsp_get_io_fd(fsp)));
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
        bytes_obj = json_object_get(response, "size");
        if (bytes_obj && json_is_integer(bytes_obj)) {
            int size = json_integer_value(bytes_obj);
			if (size!=result) {
				DEBUG(0, ("Tracim: tracim_pwrite() : Warning : size conflict : %d VS %ld.\n", size, result));
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
    DEBUG(0, ("Tracim: tracim_lseek() : TODO\n"));

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
/**
 * @brief Copy of open.c : create_file_default()
 * 
 */
NTSTATUS create_file_tracim(connection_struct *conn,
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
	int info = FILE_WAS_OPENED;
	files_struct *fsp = NULL;
	NTSTATUS status;
	bool stream_name = false;
	struct smb2_create_blob *posx = NULL;

    	DEBUG(0, ("tracim_create_file: access_mask = 0x%" PRIu32
		  " file_attributes = 0x%" PRIu32
		  " share_access = 0x%" PRIu32
		  " create_disposition = 0x%" PRIu32
		  " create_options = 0x%" PRIu32
		  " oplock_request = 0x%" PRIu32
		  " private_flags = 0x%" PRIu32
		  " ea_list = %p, sd = %p, fname = %s\n",
		  access_mask,
		  file_attributes,
		  share_access,
		  create_disposition,
		  create_options,
		  oplock_request,
		  private_flags,
		  ea_list,
		  sd,
		  smb_fname_str_dbg(smb_fname)));

	if (req != NULL) {
    	DEBUG(0, ("tracim_create_file() : get_deferred_open_message_state\n"));
		/*
		 * Remember the absolute time of the original request
		 * with this mid. We'll use it later to see if this
		 * has timed out.
		 */
		// segfault : get_deferred_open_message_state(req, &req->request_time, NULL);
	}

	/*
	 * Check to see if this is a mac fork of some kind.
	 */
	DEBUG(0, ("tracim_create_file() : is_ntfs_stream_smb_fname\n"));
	stream_name = is_ntfs_stream_smb_fname(smb_fname);
	if (stream_name) {
		DEBUG(0, ("tracim_create_file() : stream_name\n"));
		enum FAKE_FILE_TYPE fake_file_type = is_fake_file(smb_fname);
		if (req != NULL && fake_file_type != FAKE_FILE_TYPE_NONE) {
			/*
			 * Here we go! support for changing the disk quotas
			 * --metze
			 *
			 * We need to fake up to open this MAGIC QUOTA file
			 * and return a valid FID.
			 *
			 * w2k close this file directly after opening xp
			 * also tries a QUERY_FILE_INFO on the file and then
			 * close it
			 */
			status = open_fake_file(req, conn, req->vuid,
						fake_file_type, smb_fname,
						access_mask, &fsp);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}

			ZERO_STRUCT(smb_fname->st);
			goto done;
		}
		if (!(conn->fs_capabilities & FILE_NAMED_STREAMS)) {
			status = NT_STATUS_OBJECT_NAME_INVALID;
			goto fail;
		}
	}

	DEBUG(0, ("tracim_create_file() : is_ntfs_default_stream_smb_fname\n"));
	if (is_ntfs_default_stream_smb_fname(smb_fname)) {
		DEBUG(0, ("tracim_create_file() : is_ntfs_stream_smb_fname\n"));
		int ret;
		/* We have to handle this error here. */
		if (create_options & FILE_DIRECTORY_FILE) {
			status = NT_STATUS_NOT_A_DIRECTORY;
			goto fail;
		}
		ret = vfs_stat(conn, smb_fname);
		if (ret == 0 && VALID_STAT_OF_DIR(smb_fname->st)) {
			status = NT_STATUS_FILE_IS_A_DIRECTORY;
			goto fail;
		}
	}

	DEBUG(0, ("tracim_create_file() : smb2_create_blob_find\n"));
	posx = smb2_create_blob_find(in_context_blobs, SMB2_CREATE_TAG_POSIX);
	if (posx != NULL) {
		DEBUG(0, ("tracim_create_file() : posx != NULL\n"));
		uint32_t wire_mode_bits = 0;
		mode_t mode_bits = 0;
		SMB_STRUCT_STAT sbuf = { 0 };
		enum perm_type ptype =
			(create_options & FILE_DIRECTORY_FILE) ?
			PERM_NEW_DIR : PERM_NEW_FILE;

		if (posx->data.length != 4) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}

		wire_mode_bits = IVAL(posx->data.data, 0);
		status = unix_perms_from_wire(
			conn, &sbuf, wire_mode_bits, ptype, &mode_bits);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		/*
		 * Remove type info from mode, leaving only the
		 * permissions and setuid/gid bits.
		 */
		mode_bits &= ~S_IFMT;
		file_attributes = (FILE_FLAG_POSIX_SEMANTICS | mode_bits);
	}

	DEBUG(0, ("tracim_create_file() : create_file_unixpath\n"));
	status = create_file_unixpath(conn,
				      req,
				      dirfsp,
				      smb_fname,
				      access_mask,
				      share_access,
				      create_disposition,
				      create_options,
				      file_attributes,
				      oplock_request,
				      lease,
				      allocation_size,
				      private_flags,
				      sd,
				      ea_list,
				      &fsp,
				      &info);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

 done:
	DEBUG(10, ("create_file: info=%d\n", info));

	*result = fsp;
	if (pinfo != NULL) {
		*pinfo = info;
	}
	return NT_STATUS_OK;

 fail:
	DEBUG(10, ("create_file: %s\n", nt_errstr(status)));

	if (fsp != NULL) {
		close_file_free(req, &fsp, ERROR_CLOSE);
	}
	return status;
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
    DEBUG(0, ("Tracim: tracim_create_file(%s) : TODO\n", fname));
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
    	DEBUG(0, ("tracim_create_file: Fail created file: %s (fd=%d), force : TODO\n", fname, fd));
		return NT_STATUS_OK;
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
    int fd = fsp_get_io_fd(fsp);
    DEBUG(0, ("Tracim: tracim_fcntl(cmd=%d on fd=%d) : TODO\n", cmd, fd));
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

//    .fgetxattr_fn = tracim_fgetxattr,
//    .fsetxattr_fn = tracim_fsetxattr,
//    .fremovexattr_fn = tracim_fremovexattr,
//    .flistxattr_fn = tracim_flistxattr,
 
    .fdopendir_fn = tracim_opendir,
    .readdir_fn = tracim_readdir,
    .closedir_fn = tracim_closedir,

	.disk_free_fn = tracim_disk_free,
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	// .get_quota_fn = tracim_get_quota
	.create_file_fn = tracim_create_file,
	.fcntl_fn = tracim_fcntl

	// For best performances : pread_recv_fn && pread_send_fn && pwrite_recv_fn && pwrite_send_fn
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