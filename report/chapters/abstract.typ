= Abstract

== The Goal

The goal of the project is to develop a set of application that allow the process of emulating the qualified electronic signature, i.e. signing _.pdf_ documents, including the hardware toll needed for personal verification.

The project consists of two applications: a main one, which would allow a user with a pendrive containing a set of keys to sign any _.pdf_ document, as well as verify any file against a public key contained in any file on the device.
The second application is a key generator, which allows the user to generate an RSA key pair to be stored on the pendrive. This concept is illustrated in the following diagram.

#figure(
  image("../images/apps_diagram.png"),
  caption: "Block diagram of the project concept."
)

== Chosen Technologies

The code of the project is written in Python, using the _cryptography_ library for handling the cryptographic operations, _PyQt_ for the GUI, and _PyHanko_ for the PDF signing and verification.
The products of the project are being developed for Linux, with no guarantee of working on another OS.
The code is documentation is built using _Doxygen_ and this report is written in _Typst_.