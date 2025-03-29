# pdf-signer

A simple application for creating keys on a separate device and using them to digitally sign a PDF file using the PAdES standard for the University subject _Security of Computer Systems_.

## Assumptions

This software assumes a number of things about the end user's setup, including, but not limited to:
- the aforementioned separate device being automatically mounting to a specific location in the user's filesystem,
- the user having installed certain python libraries on their device,
- most likely using a UNIX-based system - sorry Windows enjoyers.