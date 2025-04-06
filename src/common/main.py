from pyhanko import keys
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

from pyhanko_certvalidator.registry import SimpleCertificateStore

from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from asn1crypto import x509 as asn1_x509
from asn1crypto import keys as asn1_keys
from asn1crypto import algos as asn1_algos

import os
from datetime import datetime, timedelta, timezone
import hashlib
from PyQt6.QtCore import QFile, QDir
import io
from typing import List, Tuple 


class Logic:
    """
    A class containing the main logic for the application.
    """
    def represents_int(a: str) -> int | bool:
        """
        Checks if the given string can be converted to an integer.
        
        Args:
            a: The string to check.
        
        Returns:
            int: The integer value if conversion is successful.
            bool: False if conversion fails.
        """
        try:
            return int(a)
        except ValueError:
            return False



    def is_divisible(divisee: int, divisor: int) -> bool:
        """
        Used for checking if a number is divisible by another number.

        Args:
            divisee: The number to be divided.
            divisor: The number to divide by.
        
        Returns:
            bool: True if divisee is divisible by divisor, False otherwise.
        """
        return divisee % divisor == 0



    def filename(path: str) -> str:
        """
        Returns the filename from the given path.

        Args:
            path: The path to the file.

        Returns:
            str: The filename without the directory.
        """
        return os.path.basename(path)



    def generate_key(public_exponent: int, key_size: int, password: str) -> Tuple[bytes, bytes, bytes]:
        """
        Generates an RSA key pair and encrypts the private key with AES-GCM.
        The public key is returned in PEM format.
        The private key is encrypted with the provided password.
        
        Args:
            public_exponent: Public exponent for RSA key generation.
            key_size: Size of the RSA key to generate.
            password: Password used to encrypt the private key.
        
        Returns:
            Tuple[bytes, bytes, bytes]: A tuple containing:
                - Nonce used for AES-GCM encryption.
                - Encrypted private key.
                - Public key in PEM format.
        """
        key = rsa.generate_private_key(
                public_exponent,
                key_size
            )

        private_key = key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption()
            )

        public_key = key.public_key().public_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PublicFormat.PKCS1
                )

        aes_key = hashlib.sha256(password.encode()).digest()
        aes = AESGCMSIV(aes_key)
        nonce = os.urandom(12)
        return nonce, aes.encrypt(nonce, data=private_key, associated_data=None), public_key



    def make_location(watch_folder: str, pendrive_name: str) -> str:
        """
        Returns the path to the location where keys and signatures are stored.
        The location is structured as:
        `watch_folder/pendrive_name/.pdf-signer`.
        
        Args:
            watch_folder: Path to the watch folder.
            pendrive_name: Name of the pendrive.
        Returns:
            str: Path to the location.
        """
        return watch_folder + QDir.separator() + pendrive_name



    def prepare_location(watch_folder: str, pendrive_name: str) -> bool:
        """
        Prepares the location for storing keys and signatures.
        Creates the necessary directories if they do not exist.
        
        Args:
            watch_folder: Path to the watch folder.
            pendrive_name: Name of the pendrive.
        Returns:
            bool: True if the location was prepared successfully, False otherwise.
        """
        try:
            location = Logic.make_location(watch_folder, pendrive_name)
            location_dir = QDir(location)
            if not location_dir.exists(".pdf-signer"):
                location_dir.mkdir(".pdf-signer")
            return True
        except:
            return False



    def make_key_location(watch_folder: str, pendrive_name: str) -> str:
        """
        Returns the path to the key directory.
        
        Args:
            watch_folder: Path to the watch folder.
            pendrive_name: Name of the pendrive.
        
        Returns:
            str: Path to the key directory.
        """
        return Logic.make_location(watch_folder, pendrive_name) + QDir.separator() + ".pdf-signer"



    def make_key_path(location: str, key_name: str) -> str:
        """
        Returns the path to the key directory.

        Args:
            location: Path to the key directory.
            key_name: Name of the key.
        
        Returns:
            str: Path to the key directory.
        """
        return location + QDir.separator() + key_name



    def nonce_path(location: str, key_name: str) -> str:
        """
        Returns the path to the nonce file.

        Args:
            location: Path to the key directory.
            key_name: Name of the key.

        Returns:
            str: Path to the nonce file.
        """
        return Logic.make_key_path(location, key_name) + QDir.separator() + "nonce"



    def private_key_path(location: str, key_name: str) -> str:
        """
        Returns the path to the private key file.

        Args:
            location: Path to the key directory.
            key_name: Name of the key.

        Returns:
            str: Path to the private key file.
        """
        return Logic.make_key_path(location, key_name) + QDir.separator() + "private_key"



    def public_key_path(location: str, key_name: str) -> str:
        """
        Returns the path to the public key file.
        
        Args:
            location: Path to the key directory.
            key_name: Name of the key.
            
        Returns:
            str: Path to the public key file.
        """
        return Logic.make_key_path(location, key_name) + QDir.separator() + "public_key"



    def does_key_exist(
        location: str,
        key_name: str
    ) -> bool:
        """
        Checks if a key directory exists at the specified location.

        Args:
            location: Path to the key directory.
            key_name: Name of the key.
        
        Returns:
            bool: True if the key directory exists, False otherwise.
        """
        key_path = Logic.make_key_path(location, key_name)
        dir = QDir(key_path)
        return dir.exists()



    def make_key(
        key_size: int,
        password: str,
        location: str,
        key_name: str
    ) -> int:
        """
        Creates a new key directory with the specified key name and generates
        a new RSA key pair. The private key is encrypted with the provided password.
        The public key is saved in the same directory.

        Args:
            key_size: Size of the RSA key to generate.
            password: Password used to encrypt the private key.
            location: Path to the key directory.
            key_name: Name of the key.
        
        Returns:
            int: 0 if the key was created successfully, 1 if an error occurred.
        """
        try:
            dir = QDir(location)
            dir.mkdir(key_name)
            nonce, encrypted_private_key, public_key = Logic.generate_key(65537, key_size, password)
            
            nonce_file = QFile(Logic.nonce_path(location, key_name))
            if (nonce_file.open(QFile.OpenModeFlag.WriteOnly)):
                nonce_file.write(nonce)
                nonce_file.close()

            private_key_file = QFile(Logic.private_key_path(location, key_name))
            if (private_key_file.open(QFile.OpenModeFlag.WriteOnly)):
                private_key_file.write(encrypted_private_key)
                private_key_file.close()

            public_key_file = QFile(Logic.public_key_path(location, key_name))
            if (public_key_file.open(QFile.OpenModeFlag.WriteOnly)):
                public_key_file.write(public_key)
                public_key_file.close()
            
            return 0
        except:
            return 1



    def load_private_key(
        password: str, 
        location: str, 
        key_name: str
    ) -> Tuple[bool, bytes]:
        """
        Loads the private key from the specified location.

        Args:
            password: Password used to encrypt the private key.
            location: Path to the key directory.
            key_name: Name of the key.
        
        Returns:
            Tuple[bool, bytes]: A tuple containing a boolean indicating success or failure,
                                and the private key as bytes if successful.
        """
        key_path = Logic.make_key_path(location, key_name)
        dir = QDir(key_path)
        if not dir.exists():
            return False, None
        
        nonce = 0
        nonce_file = QFile(Logic.nonce_path(location, key_name))
        if (nonce_file.open(QFile.OpenModeFlag.ReadOnly)):
            nonce = nonce_file.readAll()
            nonce_file.close()

        private_key = 0
        private_key_file = QFile(Logic.private_key_path(location, key_name))
        if (private_key_file.open(QFile.OpenModeFlag.ReadOnly)):
            private_key = private_key_file.readAll()
            private_key_file.close()

        aes_key = hashlib.sha256(password.encode()).digest()
        aes = AESGCMSIV(aes_key)

        try:
            private_key = aes.decrypt(nonce, data=private_key, associated_data=None)
        except:
            return False, None
        
        return True, private_key



    def list_keys(location: str) -> List[str]:
        """
        Lists all keys in the specified location.

        Args:
            location: Path to the key directory.

        Returns:
            List[str]: List of key names.
        """
        dir = QDir(location)
        dir.setFilter(QDir.Filter.Dirs | QDir.Filter.NoDotAndDotDot)
        key_list = dir.entryList()
        return key_list



    def delete_key(location: str, key: str) -> bool:
        """
        Deletes the specified key directory.

        Args:
            location: Path to the key directory.
            key: Name of the key to delete.

        Returns:
            bool: True if the deletion was successful, False otherwise.
        """
        try:
            path = Logic.make_key_path(location, key)
            dir = QDir(path)
            dir.removeRecursively()
            return True
        except:
            return False



    def copy_file(source: str, destination: str) -> bool:
        """
        Copies a file from source to destination.
        Args:
            source: Path to the source file.
            destination: Path to the destination file.
            
        Returns:
            bool: True if the copy was successful, False otherwise.
        """
        return QFile.copy(source, destination)



    def copy_public_key(watch_folder: str, pendrive: str, key: str, dest: str) -> bool:
        """
        Copies the public key file from the pendrive to the destination.
        
        Args:
            watch_folder: Path to the watch folder.
            pendrive: Name of the pendrive.
            key: Name of the key.
            dest: Destination path where the public key will be copied.

        Returns:
            bool: True if the copy was successful, False otherwise.
        """
        source = Logic.public_key_path(Logic.make_key_location(watch_folder, pendrive), key)
        return Logic.copy_file(source, dest)


    
    def load_pdf_file(path: str) -> bytes:
        """
        Loads the PDF file as bytes.

        Args:
            path: Path to the PDF file.

        Returns:
            bytes: The PDF file as bytes.
        """
        with open(path, 'rb') as pdf_bytes:
            return pdf_bytes



    def sign_pdf_file(
        file_path: str,
        signer: signers.Signer
    ) -> bytes | bool:
        """
        Signs the PDF file using the provided signer.
        
        Args:
            file_path: Path to the PDF file to sign.
            signer: Signer object used for signing the PDF.
        
        Returns:
            bytes: The signed PDF file as bytes.
            bool: False if signing fails.
        """
        with open(file_path, 'rb') as file:
            # incremental writer as recommended by PyHanko
            # (will also support with already signed PDFs)
            # strict=False to avoid weird PDF version errors, I think?
            pdf_writer = IncrementalPdfFileWriter(file, strict=False)
            sieg_field_spec =  fields.SigFieldSpec(sig_field_name="pdf-signer signature", on_page=0)
            fields.append_signature_field(pdf_writer, sieg_field_spec)
            # signature metadata, specifying the usage
            # of a PAdES signature
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


    def create_certificate(private_key):
        """
        Creates a self-signed X.509 certificate using asn1crypto for the structure,
        signed by the provided cryptography private key.

        Args:
            private_key: A cryptography private key object
                        (e.g., RSAPrivateKey, EllipticCurvePrivateKey).

        Returns:
            asn1crypto.x509.Certificate: The generated certificate object.

        Raises:
            TypeError: If the private key type is unsupported.
            ValueError: If signing fails.
        """

        subject_data = {
            'country_name': 'PL',
            'state_or_province_name': 'Pomerania',
            'locality_name': 'Danzig',
            'organization_name': 'Politechnika Gdanska',
            'common_name': 'pg.edu.pl',
        }
        issuer_data = subject_data # self-signed

        subject = asn1_x509.Name.build(subject_data)
        issuer = asn1_x509.Name.build(issuer_data)

        public_key_der = private_key.public_key().public_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_info = asn1_keys.PublicKeyInfo.load(public_key_der)

        serial_bytes = os.urandom(20)
        serial_number = int.from_bytes(serial_bytes, 'big')
        # ensure positive interpretation in DER (if MSB is 1, prepend 0x00)
        # asn1crypto's int handling might cover this, but explicit is safer
        if serial_bytes[0] & 0x80:
            serial_number = int.from_bytes(b'\x00' + serial_bytes, 'big')

        # validity
        now = datetime.now(timezone.utc) # Use timezone-aware datetime
        not_valid_before = now
        not_valid_after = now + timedelta(days=10)

        # asn1crypto Time objects can often take datetime directly
        validity = asn1_x509.Validity({
            'not_before': asn1_x509.Time({'utc_time': not_valid_before}),
            'not_after': asn1_x509.Time({'utc_time': not_valid_after}),
        })

        # signature algorithm
        hash_algo = hashes.SHA256() # we'll use SHA256 because why not

        if isinstance(private_key, rsa.RSAPrivateKey):
            sig_algo_ident = asn1_algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
            padding_algo = padding.PKCS1v15()
            signing_hash_algo = hash_algo
        else:
            raise TypeError(f"Unsupported private key type: {type(private_key)}")

        # the AlgorithmIdentifier within TBSCertificate MUST match the one
        # used for the final signatureAlgorithm field outside the TBSCertificate
        tbs_signature_algo = sig_algo_ident

        # construct TBSCertificate data
        # note: version is v3 (integer 2) because we might add extensions later
        # if no extensions, v1 (integer 0) is technically sufficient, but v3 is common
        tbs_certificate_data = {
            'version': 'v3', # corresponds to integer 2
            'serial_number': serial_number,
            'signature': tbs_signature_algo, # algorithm ID used to sign *this* TBS
            'issuer': issuer,
            'validity': validity,
            'subject': subject,
            'subject_public_key_info': public_key_info
        }

        # create and sign TBSCertificate ---
        tbs_certificate = asn1_x509.TbsCertificate(tbs_certificate_data)

        # get the bytes to be signed (DER encoding of TBSCertificate)
        bytes_to_sign = tbs_certificate.dump() # DER encode

        # sign the DER-encoded TBS data using the cryptography key
        if isinstance(private_key, (rsa.RSAPrivateKey)):
            signature_bytes = private_key.sign(
                bytes_to_sign,
                padding_algo, # type: ignore # padding_algo is PSS or PKCS1v15 for RSA
                signing_hash_algo
            )
        else:
            # this case should have been caught earlier, but we can be safe
            raise TypeError(f"Unsupported private key type for signing: {type(private_key)}")

        # construct final certificate
        certificate_data = {
            'tbs_certificate': tbs_certificate,
            'signature_algorithm': sig_algo_ident, # Must match TBS 'signature' field
            'signature_value': signature_bytes,
        }

        final_certificate = asn1_x509.Certificate(certificate_data)

        return final_certificate



    def make_signed_pdf(
        pdf_file_path: str,
        password: str,
        key_location: str,
        key: str
    ) -> bytes | bool:
        """
        Signs the PDF file using the private key and certificate stored in the specified location.

        Args:
            pdf_file_path: Path to the PDF file to sign.
            password: Password used to encrypt the private key.
            key_location: Location where the private key is stored.
            key: Name of the key.

        Returns:
            bytes: The signed PDF file as bytes.
            bool: False if signing fails.
        """
        key_result, key = Logic.load_private_key(password, key_location, key)
        if not key_result:
            return False
        
        private_key = crypto_serialization.load_pem_private_key(key, password=None)
        pyhanko_key = keys.load_private_key_from_pemder_data(key, passphrase=None)

        # create a self-signed certificate using the private key
        signing_cert = Logic.create_certificate(private_key)
        # make a make-shift certificate store,
        # a simple one will suffice
        cert_store = SimpleCertificateStore()
        pdf_signer = signers.SimpleSigner(
            signing_cert=signing_cert,
            signing_key=pyhanko_key,
            cert_registry=cert_store
        )

        return Logic.sign_pdf_file(pdf_file_path, pdf_signer)



    def save_file(path: str, file_bytes: io.BytesIO) -> bool:
        """
        Saves the file bytes to the specified path.
        
        Args:
            path: Path where the file will be saved.
            file_bytes: BytesIO object containing the file data.

        Returns:
            bool: True if the file was saved successfully, False otherwise.
        """

        try:
            with open(path, 'wb') as file:
                file.write(file_bytes.read())
            return True
        except:
            return False


        
    def verify_pdf(pdf_path: str, public_key_path: str) -> int:
        """
        Verifies if a PDF contains at least one signature that was signed
        using the private key corresponding to the provided public key file.

        Args:
            pdf_path: Path to the PDF file to verify.
            public_key_path: Path to the PEM-encoded public key file
                            (expected in PKCS1 format as generated by generate_key).

        Returns:
            0 if a signature matching the provided public key was found.
            1 if no signature matched the public key.
            2 if the public key could not be loaded.
            3 if the PDF file has no signatures.
            4 if any other error was encountered.
        """

        # load the public key
        try:
            with open(public_key_path, 'rb') as pk_file:
                provided_public_key_pem = pk_file.read()
            provided_public_key = crypto_serialization.load_pem_public_key(
                provided_public_key_pem
            )
            # get DER format for reliable comparison (SubjectPublicKeyInfo is standard)
            provided_public_key_der = provided_public_key.public_bytes(
                encoding=crypto_serialization.Encoding.DER,
                format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            return 2

        # read the PDF and Find Signatures
        try:
            with open(pdf_path, 'rb') as doc:
                reader = PdfFileReader(doc, strict=False)

                if not reader.embedded_signatures:
                    # if file has no signatures
                    return 3

                found_matching_valid_signature = False
                for sig_index, sig in enumerate(reader.embedded_signatures):
                    # extract public key
                    signing_cert = sig.signer_cert
                    if not signing_cert:
                        # if couldn't find a certificate
                        continue # move to the next signature

                    # the signing_cert object should have a public_key
                    # property returning a cryptography key object.
                    try:
                        # access the public key from the certificate
                        embedded_public_key: asn1_keys.PublicKeyInfo = signing_cert.public_key
                        if not embedded_public_key:
                            continue

                        # serialize the embedded public key to DER for comparison
                        embedded_public_key_der = embedded_public_key.dump()
                    except AttributeError:
                        continue
                    except Exception as e:
                        continue

                    # compare public keys
                    if embedded_public_key_der == provided_public_key_der:
                        # verify integrity if matched
                        try:
                            sig.compute_integrity_info()
                            found_matching_valid_signature = True

                        except Exception as e:
                            pass

                # return result
                return int(not found_matching_valid_signature)

        except Exception as e:
            # any other errors
            return 4
