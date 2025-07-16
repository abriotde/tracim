
# Install

Run:
 
	$ sudo ./install.sh

On fail : 

In samba/bin/default/docs-xml/smbdotconf/parameters.all.xml

- Remove 1 of double definition of "neutralize_nt4_emulation".

- Remove all "Himmelblaud" definitions.

And relaunch script.

# Documentation

## For Samba VFS C part:

The Samba VFS module, is named tracim. So the dynamic library to put in VFS folder is tracim.so.

https://wiki.samba.org/index.php/Writing_a_Samba_VFS_Module

## For Tracim Python part:

WebDav

https://demo.tracim.fr/api/doc/


./backend/tracim_backend/lib/webdav/resources.py

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

