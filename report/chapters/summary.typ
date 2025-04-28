= Summary

#show link: set text(blue, style: "italic")

As per the project's requirements, the entirety of both applications was implemented, allowing one user (_A_) to generate keys using an auxiliary application and use the main application to sign documents, as well as for another user (_B_) to verify the signatures using the same main application.

This implementation was done in Python, its code is available on #link("https://github.com/jakub-jedrzejczyk/pdf-signer", "Github"), and it follows the requirements of the project, those being:
- The key generation application generates a public/private 4096-bit long RSA key pair and stores it in a file, with the private key being encrypted using AES, where the 256-bit key is the hash from a password.
- This key pair is stored on an automatically detected USB drive.
- The main application allows the user to sign a PDF document using the private key and verify the signature using the public key.
- All applications provide appropriate error handling and user feedback so that the user is aware of the application's state at all times.