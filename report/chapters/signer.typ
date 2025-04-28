= Signer

== Description

The signer (also called the _main application_) is responsible for signing PDF files using the keys previously generated using _keygen_, as well as verifying already signed PDF files using any public key provided by the user.
The signature should follow the PAdES standard, a specific set of restrictions and extensions to the PDF standard that ensure the integrity and authenticity of the signed document.

== Functionality Overview

The application starts in signing mode, allowing the user to sign a PDF file using a private key that is stored on a USB drive.

#figure(
  image("../images/signer_signage_no_key_no_file.png"),
  caption: "Signer right after starting up."
)

As can be seen on the image, should the application not find a generated key on the USB drive, it will display a message indicating so.
At that point, even selecting a PDF file will not allow the user to sign it.

#figure(
  image("../images/signer_signage_no_key.png"),
  caption: "Signer with a key and a PDF."
)

Should the user add a key to the USB drive, the application will allow the user to sign a PDF file.

#figure(
  image("../images/signer_signage_ready.png"),
  caption: "Signer, ready to sign a PDF."
)

After pressing the "Sign the PDF" button, the application will first prompt the user to provide a password to decrypt the saved private key.

#figure(
  image("../images/signer_password_prompt.png"),
  caption: "Password prompt for the private key."
)

Should the provided password not be correct, the application will inform of the fact most likely being the case.

#figure(
  image("../images/signer_incorrect_password.png"),
  caption: "Signer after providing an incorrect password."
)

Meanwhile, if the password is correct, the application will proceed to sign the PDF file using the private key, and inform the user of the success of the operation.

#figure(
  image("../images/signer_signed_ready.png"),
  caption: "Signer, ready to save the signed PDF."
)

At this point the file is signed and saved in the application's memory, but not yet saved to the disk -- should the user close the application, the signed file will be lost.
This state is further indicated by the "Save the PDF" button being enabled and an appropriate message indicated below.
After pressing this button the user will be prompted to select a location to save the signed PDF file, together with the name of the file.

#figure(
  image("../images/signer_saving_file.png"),
  caption: "Saving the signed PDF file."
)

Once that's done, the file will be saved to the specified location and the user will be notified of the success of the operation.

#figure(
  image("../images/signer_saved.png"),
  caption: "Signer notifying the user of the file having been saved."
)

Similarly to the signing mode, the verification mode of the application allows the user to verify a PDF file using a public key that is stored on a USB drive.
By default, due to the application's intended purpose, it tries to suggest to select a public key file rather than use a public key directly from the USB drive. 

#figure(
  image("../images/signer_verification_no_key_no_file.png"),
  caption: "Signer's verification mode when no key is detected."
)

Should the user try to verify a PDF file using a public key from a USB drive that has no keys saved on it, the application will not allow the user to verify a selected PDF file.

#figure(
  image("../images/signer_verification_no_key.png"),
  caption: "Signer's verification mode after selecting a USB drive with no keys and a PDF file."
)

At the same time, if the user chooses to then select a public key file instead of a USB drive's public key, the application will allow the user to verify a selected PDF file.

#figure(
  image("../images/signer_verification_key_file_ok.png"),
  caption: "Signer's verification mode after selecting a public key file and a PDF file."
)

Once a valid public key file is selected and the "Verify" button is pressed by the user, the application will attempt to verify the selected PDF file using the provided public key.

#figure(
  image("../images/signer_verified.png"),
  caption: "Signer notifying of a successful verification."
)

If the user chose a key that does not have a matching signature in the PDF file, the application will notify the user of that fact.

#figure(
  image("../images/signer_no_key_found.png"),
  caption: "Signer notifying of the signature not matching the provided public key."
)

The very same happens if the PDF has been modified after being signed, while the signature does not match the provided public key.
In such a case, the application does not check for the signature's validity.

#figure(
  image("../images/signer_no_key_modified.png"),
  caption: "Signer notifying of the signature not matching the provided public key when a PDF file has been modified."
)

Lastly, if the user tries to verify a PDF file that contains a signature that matches the provided public key, but the signature is invalid, whether it be due to the file or the signature itself being modified, the application will notify the user of that fact.

#figure(
  image("../images/signer_invalid_signature.png"),
  caption: "Signer notifying of the signature being invalid."
)

== Implementation

The signing functionality of the application is primarily provided by the _pyhanko_ library. Using it, the following function allows to sign any PDF file given its path and a signer object.

#figure(
  [
    ```py
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

def sign_pdf_file(
  file_path: str,
  signer: signers.Signer
) -> bytes | bool:
  with open(file_path, 'rb') as file:
    pdf_writer = IncrementalPdfFileWriter(file, strict=False)
    sieg_field_spec =  fields.SigFieldSpec(sig_field_name="pdf-signer signature", on_page=0)
    fields.append_signature_field(pdf_writer, sieg_field_spec)
    signature_metadata = signers.PdfSignatureMetadata(
      field_name="pdf-signer signature",
      subfilter=fields.SigSeedSubFilter.PADES
    )

    try:
      signed_pdf = signers.sign_pdf(
        pdf_writer,
        signer=signer,
        signature_meta=signature_metadata
      )
      return signed_pdf
    except:
      return False
  return False
```
  ],
  caption: "Function used for signing a pdf file."
)

This allows to add a signature field to any PDF file, confirming its contents have been verified and signed by a user, even one already containing a signature field (assuming the already existing field allows such modifications). Said signature follows the CMS standard @housleyCryptographicMessageSyntax2009, though only a small subset of it is necessary for the functionality of this application.

For the purposes of this project, the signing requires specifying the name of the field (```py sieg_field_spec = fields.SigFieldSpec(sig_field_name="pdf-signer signature", on_page=0)```), and additional metadata -- in this case, the field name once more and the subfilter, specifying what kind of signature is used (```py signature_metadata = signers.PdfSignatureMetadata(field_name="pdf-signer signature", subfilter=fields.SigSeedSubFilter.PADES)```).
The signing process is then performed using the ```py signers.sign_pdf(...)``` function, which returns the signed PDF file, with the signature field at the specified location -- here, it's the first page of the document.

For this to be done, however, a signer object must be created first, and in the case of this application, an appropriate wrapper function handles creating said object.

#figure(
  [
    ```py
from cryptography.hazmat.primitives import serialization as crypto_serialization
from pyhanko.sign import signers
from pyhanko import keys
from pyhanko_certvalidator.registry import SimpleCertificateStore

def make_signed_pdf(
  pdf_file_path: str,
  password: str,
  key_location: str,
  key: str
) -> bytes | bool:
  key_result, key = Logic.load_private_key(password, key_location, key)
  if not key_result:
    return False
  
  private_key = crypto_serialization.load_pem_private_key(key, password=None)
  pyhanko_key = keys.load_private_key_from_pemder_data(key, passphrase=None)

  signing_cert = Logic.create_certificate(private_key)
  cert_store = SimpleCertificateStore()
  pdf_signer = signers.SimpleSigner(
    signing_cert=signing_cert,
    signing_key=pyhanko_key,
    cert_registry=cert_store
  )

  return Logic.sign_pdf_file(pdf_file_path, pdf_signer)
```
  ],
  caption: "PDF signing wrapper function."
)

This function uses the previously introduces function to load a private key given its path and a password - should it fail, the entire function returns ```py False```, indicating the signing process cannot be completed.

The private key in the form of bytes is then used to create two key objects - one for the creation of a signing certificate and another for the signing process itself.

Before signing, a certificate store must be created, which is a simple object that stores the certificate used for signing. The ```py SimpleCertificateStore``` class is used for this purpose, as it's the simplest implementation of the required interface.

It's use is to store the makeshift certificate created using the ```py Logic.create_certificate(...)``` function - this function creates a self-signed X.509 certificate using the private key, which is then used for signing the PDF file.

Those two objects, together with the appropriately loaded private key allow to create a signer object that is then used to sign the PDF file.

```py
from asn1crypto import x509 as asn1_x509
from asn1crypto import keys as asn1_keys
from asn1crypto import algos as asn1_algos
from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta, timezone


def create_certificate(private_key):
  subject_data = { 
    'country_name': 'PL', 
    'state_or_province_name': 'Pomerania', 
    'locality_name': 'Danzig', 
    'organization_name': 'Politechnika Gdanska', 
    'common_name': 'pg.edu.pl', 
  }
  issuer_data = subject_data
  subject = asn1_x509.Name.build(subject_data)
  issuer = asn1_x509.Name.build(issuer_data)
  public_key_der = private_key.public_key().public_bytes(
    encoding=crypto_serialization.Encoding.DER,
    format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
  )
  public_key_info = asn1_keys.PublicKeyInfo.load(public_key_der)
  serial_bytes = os.urandom(20)
  serial_number = int.from_bytes(serial_bytes, 'big')
  if serial_bytes[0] & 0x80:
      serial_number = int.from_bytes(b'\x00' + serial_bytes, 'big')
  now = datetime.now(timezone.utc) # Use timezone-aware datetime
  not_valid_before = now
  not_valid_after = now + timedelta(days=10)
  validity = asn1_x509.Validity({
    'not_before': asn1_x509.Time({'utc_time': not_valid_before}),
    'not_after': asn1_x509.Time({'utc_time': not_valid_after}),
  })
  hash_algo = hashes.SHA256()
  if isinstance(private_key, rsa.RSAPrivateKey):
    sig_algo_ident = asn1_algos.SignedDigestAlgorithm({
      'algorithm': 'sha256_rsa'
    })
    padding_algo = padding.PKCS1v15()
    signing_hash_algo = hash_algo
  else:
    raise TypeError(f"Unsupported private key type: {type(private_key)}")
  tbs_signature_algo = sig_algo_ident
  tbs_certificate_data = { 
    'version': 'v3', 
    'serial_number': serial_number, 
    'signature': tbs_signature_algo, 
    'issuer': issuer, 
    'validity': validity, 
    'subject': subject, 
    'subject_public_key_info': public_key_info 
  }
  tbs_certificate = asn1_x509.TbsCertificate(tbs_certificate_data)
  bytes_to_sign = tbs_certificate.dump()
  if isinstance(private_key, (rsa.RSAPrivateKey)):
    signature_bytes = private_key.sign(bytes_to_sign, padding_algo, signing_hash_algo)
  else:
    raise TypeError(f"Unsupported private key type for signing: {type(private_key)}")
  certificate_data = {
    'tbs_certificate': tbs_certificate,
    'signature_algorithm': sig_algo_ident,
    'signature_value': signature_bytes,
  }

  final_certificate = asn1_x509.Certificate(certificate_data)

  return final_certificate
```

#figure(
  [],
  caption: "Certificate creation function."
)

This function generally produces very similar certificates -- while a certificate is technically required for the signing process, its actual details are not important, as the application is used for checking the validity of the PDF file, rather than the authenticity of the signer.

Knowing that, the subject and issuer details, as required by the X.509 standard @X5092025 are set to the same values, and the certificate is set to be valid for 10 days -- should this app be deployed long-term, it might be worth considering extending this period, or even allowing the signing user to specify the length of said period.

The serial number of each certificate is generated randomly, meaning that each certificate is generally unique, even if the same private key is used for signing multiple documents. The signature algorithm is set to SHA256 with RSA, which is a common choice for digital signatures.

These are used to create a TBS (To Be Signed) certificate, which is then signed using the private key. The resulting certificate is then returned as an X.509 certificate object, which can be used for signing PDF files.

Finally, the last important functionality of the signer is the verification of the signed PDF files. This is done using the ```py verify_pdf(...)``` function, which takes a path to a PDF file and a path to a public key file, and returns an integer indicating the result of the verification process.

These return codes are as follows:
- 0: No signature matching the provided public key was found.
- 1: Signature matching the provided public key was found and it was valid.
- 2: The public key file could not be read.
- 3: The PDF file does not contain any signatures.
- 4: The signature matching the provided public key was found, but it was invalid.
- 5: Any other error was encountered during the verification process.

```py
def verify_pdf(pdf_path: str, public_key_path: str) -> int:
  try:
    with open(public_key_path, 'rb') as pk_file:
      provided_public_key_pem = pk_file.read()
    provided_public_key = crypto_serialization.load_pem_public_key(
      provided_public_key_pem
    )
    provided_public_key_der = provided_public_key.public_bytes(
      encoding=crypto_serialization.Encoding.DER,
      format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
  except Exception as e:
    return 2
  try:
    with open(pdf_path, 'rb') as doc:
      reader = PdfFileReader(doc, strict=False)
      if not reader.embedded_signatures:
        return 3

      found_matching_valid_signature = False
      for sig_index, sig in enumerate(reader.embedded_signatures):
        signing_cert = sig.signer_cert
        if not signing_cert:
          # if couldn't find a certificate
          continue # move to the next signature
        try:
          embedded_public_key: asn1_keys.PublicKeyInfo = signing_cert.public_key
          if not embedded_public_key:
              continue
          embedded_public_key_der = embedded_public_key.dump()
        except AttributeError:
          continue
        except Exception as e:
          continue
        if embedded_public_key_der == provided_public_key_der:
          try:
            vc = ValidationContext()
            status = validation.validate_pdf_signature(sig, vc)
            
            if (status.intact):
              found_matching_valid_signature = True
            else:
              return 4
          except Exception as e:
            pass
      return int(not found_matching_valid_signature)
  except Exception as e:
    return 5
```

#figure(
  [],
  caption: "PDF signature verification function."
)

The function first attempts to load the public key from the provided path, returning an appropriate error code if it fails.
Once it has been loaded, it is parsed into a DER format.

Then the function attempts to load the PDF file, returning an error code if that fails.
Once the opened file is loaded as a PDF, is is checked for any signatures -- a lack of signatures means the function returns an error code.
If a signature is found and it contains a certificate, the public key is extracted from it and compared to the one provided by the user.
If the public keys match, the signature is validated using the ```py validation.validate_pdf_signature(...)``` function, which returns a status object containing information about the signature.

The most important part of the status object is the ```py intact``` attribute, which indicates whether the signature's hash matches the contents of the PDF file itself @PyhankosignvalidationPackagePyHanko.