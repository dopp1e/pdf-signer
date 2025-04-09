= Summary

The entirety of the auxiliary application is complete and working as expected.

*Implemented So Far:*
- RSA key generation;
- AES encryption of the private key based on the SHA256 hash of a PIN / password;
- detection of connected pendrives;
- saving the RSA generated to a connected pendrive under a selected name;
- exporting the public part of a given key to another location, as selected by the user;
- checking the password of a private key;
- deletion of a key;
- all of the aforementioned functionalities are a part of a coherently themed GUI.

*To Do:*
- loading a PDF file;
- adding a signature based on a specific key to the loaded PDF file;
- listing the signatures of a loaded PDF file;
- checking whether a signature has been signed by the private counterpart of a public key;
- implementing a GUI to allow for easy usage of all these functions.