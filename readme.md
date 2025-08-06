
# Install

Run:
 
	$ sudo ./install.sh

## Common fail causes

### Compile

Usually compile fail because "./configure" was not running in the good source files (After "git checkout" for exemple). So try run

	$ cd samba
	$ make clean
	$ ./configure
	$ cd ..
	$ sudo ./install.sh

# Documentation

## For Samba VFS C part:

The Samba VFS module, is named tracim. So the dynamic library to put in VFS folder is tracim.so.

https://wiki.samba.org/index.php/Writing_a_Samba_VFS_Module

## For Tracim Python part:

WebDav

https://demo.tracim.fr/api/doc/

tracim/backend/tracim_backend/lib/webdav/resources.py

* class SambaVFSAppFactory(object): # backend/tracim_backend/lib/webdav/__init__.py : WebdavAppFactory / CaldavAppFactory
  - def get_wsgi_app


https://github.com/tracim/tracim/blob/develop/backend/tracim_backend/lib/core/content.py
- create() (créé un contenu vide)
- get_one()
- get_all() (pour lister les contenus enfant d'un espace et/ou d'un dossier)
- move()
- update_content()
- update_file_data()
- delete()
- save()

# Warning

* For writing the C Samba VFS module, we are dependant of the minor version of Samba deamon (smbd). So it imply to compile a VFS driver for each version of Samba in production... A Samba bug report is open for this : https://bugzilla.samba.org/show_bug.cgi?id=15878

