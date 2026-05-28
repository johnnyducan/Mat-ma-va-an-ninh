# ============================================================
# PDF DIGITAL SIGNATURE PKCS12 / PAdES
# FINAL WORKING VERSION - FULL FIX
# ============================================================

# ============================================================
# AUTO INSTALL MODULES
# ============================================================

import sys
import subprocess

def install(package):

    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", package]
    )

packages = [

    "gradio",

    "pyHanko",

    "pyhanko-certvalidator",

    "cryptography",

    "pillow",

    "asn1crypto"
]

for pkg in packages:

    try:

        __import__(pkg.lower().replace("-", "_"))

    except:

        install(pkg)

# ============================================================
# IMPORTS
# ============================================================

import os
import tempfile

import gradio as gr

from datetime import datetime, timedelta

# ============================================================
# PIL
# ============================================================

from PIL import Image

# ============================================================
# ASN1CRYPTO
# ============================================================

from asn1crypto import x509 as asn1_x509
from asn1crypto import keys as asn1_keys

# ============================================================
# CRYPTOGRAPHY
# ============================================================

from cryptography import x509

from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import (

    Encoding,

    NoEncryption,

    BestAvailableEncryption,

    PrivateFormat,

    pkcs12
)

from cryptography.hazmat.primitives.asymmetric import rsa

# ============================================================
# PYHANKO
# ============================================================

from pyhanko.sign import signers

from pyhanko.sign.fields import SigFieldSpec

from pyhanko.sign.signers import PdfSigner

from pyhanko.pdf_utils.incremental_writer import (
    IncrementalPdfFileWriter
)

from pyhanko.sign.validation import (
    validate_pdf_signature
)

from pyhanko.pdf_utils.reader import PdfFileReader

from pyhanko.stamp import TextStampStyle

from pyhanko.pdf_utils.images import PdfImage

from pyhanko_certvalidator.registry import (
    SimpleCertificateStore
)

# ============================================================
# OUTPUT DIR
# ============================================================

OUTPUT_DIR = "signed_output"

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

# ============================================================
# SIGN IMAGE
# ============================================================

SIGN_IMAGE = "sample_data/conguoiyeu.png"

# ============================================================
# CREATE STAMP STYLE
# ============================================================

def create_stamp_style():

    try:

        stamp_style = TextStampStyle(

            stamp_text=
            "KÝ SỐ ĐIỆN TỬ\n"
            "Signer: %(signer)s\n"
            "Time: %(ts)s",

            background=PdfImage(SIGN_IMAGE),

            background_opacity=0.25,

            border_width=1
        )

        return stamp_style

    except Exception as e:

        print("Lỗi tạo stamp:", e)

        return TextStampStyle(

            stamp_text=
            "Digitally Signed\n"
            "%(signer)s\n"
            "%(ts)s"
        )

# ============================================================
# GENERATE CERTIFICATE + PFX
# ============================================================

def generate_certificate(

    common_name,

    organization,

    country,

    password
):

    try:

        # ====================================================
        # PRIVATE KEY
        # ====================================================

        private_key = rsa.generate_private_key(

            public_exponent=65537,

            key_size=2048
        )

        # ====================================================
        # SUBJECT
        # ====================================================

        subject = issuer = x509.Name([

            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                country
            ),

            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                organization
            ),

            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name
            )
        ])

        # ====================================================
        # CERTIFICATE
        # ====================================================

        cert = (

            x509.CertificateBuilder()

            .subject_name(subject)

            .issuer_name(issuer)

            .public_key(
                private_key.public_key()
            )

            .serial_number(
                x509.random_serial_number()
            )

            .not_valid_before(
                datetime.utcnow()
            )

            .not_valid_after(
                datetime.utcnow()
                + timedelta(days=365)
            )

            .sign(
                private_key,
                hashes.SHA256()
            )
        )

        # ====================================================
        # ENCRYPTION
        # ====================================================

        if password.strip() == "":

            encryption_algo = NoEncryption()

        else:

            encryption_algo = BestAvailableEncryption(
                password.encode()
            )

        # ====================================================
        # EXPORT PFX
        # ====================================================

        pfx_data = pkcs12.serialize_key_and_certificates(

            name=common_name.encode(),

            key=private_key,

            cert=cert,

            cas=None,

            encryption_algorithm=encryption_algo
        )

        # ====================================================
        # SAVE PFX
        # ====================================================

        pfx_path = os.path.join(
            OUTPUT_DIR,
            f"{common_name}.pfx"
        )

        with open(pfx_path, "wb") as f:

            f.write(pfx_data)

        # ====================================================
        # SAVE CERTIFICATE
        # ====================================================

        cert_path = os.path.join(
            OUTPUT_DIR,
            f"{common_name}.pem"
        )

        with open(cert_path, "wb") as f:

            f.write(
                cert.public_bytes(
                    Encoding.PEM
                )
            )

        return (

            pfx_path,

            cert_path,

            "Sinh certificate + PFX thành công."
        )

    except Exception as e:

        return (
            None,
            None,
            f"Lỗi generate certificate: {str(e)}"
        )

# ============================================================
# SIGN PDF
# ============================================================

def sign_pdf(

    pdf_file,

    pfx_file,

    pfx_password
):

    try:

        if pdf_file is None:

            return None, "Chưa upload PDF."

        if pfx_file is None:

            return None, "Chưa upload PFX."

        # ====================================================
        # LOAD PKCS12
        # ====================================================

        with open(pfx_file.name, "rb") as f:

            pfx_data = f.read()

        (
            private_key,
            certificate,
            additional_certificates
        ) = pkcs12.load_key_and_certificates(

            pfx_data,

            pfx_password.encode()
            if pfx_password
            else None
        )

        # ====================================================
        # CHECK
        # ====================================================

        if private_key is None:

            return None, "Không đọc được private key."

        if certificate is None:

            return None, "Không đọc được certificate."

        # ====================================================
        # CONVERT CERTIFICATE
        # ====================================================

        cert_asn1 = asn1_x509.Certificate.load(

            certificate.public_bytes(
                Encoding.DER
            )
        )

        # ====================================================
        # CONVERT PRIVATE KEY
        # ====================================================

        private_key_der = private_key.private_bytes(

            encoding=Encoding.DER,

            format=PrivateFormat.PKCS8,

            encryption_algorithm=NoEncryption()
        )

        signing_key = asn1_keys.PrivateKeyInfo.load(
            private_key_der
        )

        # ====================================================
        # CERT STORE
        # ====================================================

        cert_store = SimpleCertificateStore()

        cert_store.register(cert_asn1)

        if additional_certificates:

            for cert in additional_certificates:

                cert_asn1_extra = asn1_x509.Certificate.load(

                    cert.public_bytes(
                        Encoding.DER
                    )
                )

                cert_store.register(
                    cert_asn1_extra
                )

        # ====================================================
        # CREATE SIGNER
        # ====================================================

        signer = signers.SimpleSigner(

            signing_cert=cert_asn1,

            signing_key=signing_key,

            cert_registry=cert_store
        )

        # ====================================================
        # SIGN META
        # ====================================================

        signature_meta = signers.PdfSignatureMetadata(

            field_name="Signature1",

            reason="Approved Document",

            location="Vietnam"
        )

        # ====================================================
        # STAMP STYLE
        # ====================================================

        stamp_style = create_stamp_style()

        # ====================================================
        # OUTPUT PDF
        # ====================================================

        output_pdf = os.path.join(

            OUTPUT_DIR,

            "signed_" +
            os.path.basename(pdf_file.name)
        )

        # ====================================================
        # SIGN PDF
        # ====================================================

        with open(pdf_file.name, "rb") as inf:

            writer = IncrementalPdfFileWriter(
                inf
            )

            pdf_signer = PdfSigner(

                signature_meta,

                signer=signer,

                stamp_style=stamp_style,

                new_field_spec=SigFieldSpec(

                    sig_field_name="Signature1",

                    box=(40, 40, 280, 150)
                )
            )

            with open(output_pdf, "wb") as outf:

                pdf_signer.sign_pdf(

                    writer,

                    output=outf
                )

        return (

            output_pdf,

            "Ký PDF chuẩn Adobe thành công."
        )

    except Exception as e:

        return (
            None,
            f"Lỗi ký PDF: {str(e)}"
        )

# ============================================================
# VERIFY PDF
# ============================================================

def verify_pdf(pdf_file):

    try:

        if pdf_file is None:

            return "Chưa upload PDF."

        with open(pdf_file.name, "rb") as doc:

            reader = PdfFileReader(doc)

            signatures = reader.embedded_signatures

            if len(signatures) == 0:

                return "PDF chưa có chữ ký số."

            sig = signatures[0]

            status = validate_pdf_signature(sig)

            cert = sig.signer_cert

            result = f"""
==================================
VERIFY PDF SIGNATURE
==================================

Người ký:
{cert.subject.human_friendly}

Nhà phát hành:
{cert.issuer.human_friendly}

Hiệu lực từ:
{cert.not_valid_before}

Hiệu lực đến:
{cert.not_valid_after}

Hash Algorithm:
{sig.md_algorithm}

Kết quả verify:
{
'HỢP LỆ'
if status.bottom_line
else 'KHÔNG HỢP LỆ'
}
"""

            return result

    except Exception as e:

        return f"Lỗi verify: {str(e)}"

# ============================================================
# GRADIO UI
# ============================================================

with gr.Blocks(
    title="PDF Digital Signature"
) as demo:

    gr.Markdown("""

# 🔐 PDF Digital Signature PKCS12 / PAdES

## Chức năng

- Sinh Certificate
- Sinh PFX
- Ký PDF chuẩn Adobe
- Hiển thị hình ảnh chữ ký
- Verify chữ ký số
""")

    with gr.Tab("1. Sinh Certificate"):

        common_name = gr.Textbox(
            label="Common Name",
            value="Đinh Hoàng Gia"
        )

        organization = gr.Textbox(
            label="Organization",
            value="University"
        )

        country = gr.Textbox(
            label="Country",
            value="VN"
        )

        password = gr.Textbox(
            label="PFX Password",
            type="password"
        )

        gen_btn = gr.Button(
            "Sinh Certificate + PFX"
        )

        pfx_output = gr.File(
            label="PFX File"
        )

        cert_output = gr.File(
            label="PEM Certificate"
        )

        gen_status = gr.Textbox(
            label="Trạng thái"
        )

        gen_btn.click(

            generate_certificate,

            inputs=[
                common_name,
                organization,
                country,
                password
            ],

            outputs=[
                pfx_output,
                cert_output,
                gen_status
            ]
        )

    with gr.Tab("2. Ký PDF"):

        pdf_input = gr.File(
            label="Upload PDF"
        )

        pfx_input = gr.File(
            label="Upload PFX"
        )

        pfx_pass = gr.Textbox(
            label="PFX Password",
            type="password"
        )

        sign_btn = gr.Button(
            "Ký PDF"
        )

        signed_pdf = gr.File(
            label="PDF đã ký"
        )

        sign_status = gr.Textbox(
            label="Trạng thái"
        )

        sign_btn.click(

            sign_pdf,

            inputs=[
                pdf_input,
                pfx_input,
                pfx_pass
            ],

            outputs=[
                signed_pdf,
                sign_status
            ]
        )

    with gr.Tab("3. Verify Signature"):

        verify_pdf_input = gr.File(
            label="Upload PDF đã ký"
        )

        verify_btn = gr.Button(
            "Verify"
        )

        verify_result = gr.Textbox(
            label="Kết quả verify",
            lines=20
        )

        verify_btn.click(

            verify_pdf,

            inputs=verify_pdf_input,

            outputs=verify_result
        )

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    demo.launch()
