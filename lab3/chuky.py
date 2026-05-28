
# ============================================================
# BÀI TẬP 2 - RSA DIGITAL SIGNATURE PDF + GRADIO
#
# CHỨC NĂNG
# 1. Sinh khóa RSA
# 2. Ký số PDF
# 3. Chèn hình chữ ký vào PDF
# 4. Verify chữ ký số
#
# YÊU CẦU CÀI THƯ VIỆN
# !pip install gradio pycryptodome pypdf reportlab cryptography
#
# ============================================================

import os
import io
import json
import base64
import hashlib
import tempfile

from datetime import datetime, timedelta

import gradio as gr

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

# ============================================================
# TỰ ĐỘNG TẠO THƯ MỤC OUTPUT
# ============================================================

OUTPUT_DIR = "signed_output"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# ============================================================
# SINH KHÓA RSA
# ============================================================

def generate_keys(bits=2048):

    key = RSA.generate(bits)

    private_key = key.export_key().decode()

    public_key = key.publickey().export_key().decode()

    return private_key, public_key

# ============================================================
# TÍNH HASH FILE PDF
# ============================================================

def calculate_pdf_hash(pdf_path):

    sha256 = hashlib.sha256()

    with open(pdf_path, "rb") as f:
        while True:
            data = f.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()

# ============================================================
# TẠO OVERLAY CHỮ KÝ
# ============================================================

def create_signature_overlay(
    signature_image,
    signer_name,
    sign_time,
    output_overlay="overlay.pdf"
):

    packet = io.BytesIO()

    c = canvas.Canvas(packet)

    # Vị trí góc trái dưới
    x = 40
    y = 40

    # Hình chữ ký
    c.drawImage(
        ImageReader(signature_image),
        x,
        y,
        width=120,
        height=60,
        mask='auto'
    )

    # Thông tin chữ ký
    c.setFont("Helvetica", 10)

    c.drawString(x + 130, y + 45, f"Người ký: {signer_name}")
    c.drawString(x + 130, y + 30, f"Ký lúc: {sign_time}")

    c.drawString(
        x + 130,
        y + 15,
        "RSA-SHA256 Digital Signature"
    )

    c.save()

    packet.seek(0)

    with open(output_overlay, "wb") as f:
        f.write(packet.read())

    return output_overlay

# ============================================================
# KÝ SỐ PDF
# ============================================================

def sign_pdf(
    pdf_file,
    private_key_text,
    signer_name
):

    try:

        if pdf_file is None:
            return None, "Lỗi: Chưa upload PDF."

        if not private_key_text.strip():
            return None, "Lỗi: Chưa có Private Key."

        # ============================================
        # Đọc khóa bí mật
        # ============================================

        private_key = RSA.import_key(private_key_text)

        # ============================================
        # Tính hash PDF
        # ============================================

        pdf_hash = calculate_pdf_hash(pdf_file.name)

        hash_obj = SHA256.new(pdf_hash.encode())

        # ============================================
        # Ký RSA
        # ============================================

        signature = pkcs1_15.new(private_key).sign(hash_obj)

        signature_b64 = base64.b64encode(signature).decode()

        # ============================================
        # Metadata chữ ký
        # ============================================

        sign_time = datetime.now()

        expire_time = sign_time + timedelta(days=365)

        metadata = {
            "signer": signer_name,
            "sign_time": sign_time.strftime("%Y-%m-%d %H:%M:%S"),
            "expire_time": expire_time.strftime("%Y-%m-%d %H:%M:%S"),
            "signature": signature_b64,
            "hash_algorithm": "SHA256",
        }

        # ============================================
        # Overlay hình chữ ký
        # ============================================

        signature_image = "sample_data/conguoiyeu.png"

        overlay_path = os.path.join(
            OUTPUT_DIR,
            "overlay.pdf"
        )

        create_signature_overlay(
            signature_image,
            signer_name,
            metadata["sign_time"],
            overlay_path
        )

        # ============================================
        # Merge PDF
        # ============================================

        original_pdf = PdfReader(pdf_file.name)

        overlay_pdf = PdfReader(overlay_path)

        writer = PdfWriter()

        first_page = original_pdf.pages[0]

        first_page.merge_page(overlay_pdf.pages[0])

        writer.add_page(first_page)

        # Các trang còn lại
        for i in range(1, len(original_pdf.pages)):
            writer.add_page(original_pdf.pages[i])

        # ============================================
        # Gắn metadata chữ ký
        # ============================================

        writer.add_metadata({
            "/Signer": metadata["signer"],
            "/SignTime": metadata["sign_time"],
            "/ExpireTime": metadata["expire_time"],
            "/Signature": metadata["signature"],
            "/HashAlgorithm": metadata["hash_algorithm"],
        })

        # ============================================
        # Xuất file PDF đã ký
        # ============================================

        output_pdf = os.path.join(
            OUTPUT_DIR,
            f"signed_{os.path.basename(pdf_file.name)}"
        )

        with open(output_pdf, "wb") as f:
            writer.write(f)

        return output_pdf, "Ký số PDF thành công."

    except Exception as e:

        return None, f"Lỗi ký số: {str(e)}"

# ============================================================
# VERIFY CHỮ KÝ PDF
# ============================================================

def verify_pdf(
    pdf_file,
    public_key_text
):

    try:

        if pdf_file is None:
            return "Lỗi: Chưa upload PDF."

        if not public_key_text.strip():
            return "Lỗi: Chưa nhập Public Key."

        # ============================================
        # Đọc metadata
        # ============================================

        reader = PdfReader(pdf_file.name)

        meta = reader.metadata

        signer = meta.get("/Signer", "Không có")

        sign_time = meta.get("/SignTime", "Không có")

        expire_time = meta.get("/ExpireTime", "Không có")

        signature_b64 = meta.get("/Signature", "")

        # ============================================
        # Kiểm tra tồn tại chữ ký
        # ============================================

        if not signature_b64:
            return "PDF chưa có chữ ký số."

        # ============================================
        # Tính hash file hiện tại
        # ============================================

        current_hash = calculate_pdf_hash(pdf_file.name)

        hash_obj = SHA256.new(current_hash.encode())

        # ============================================
        # Verify RSA
        # ============================================

        public_key = RSA.import_key(public_key_text)

        signature = base64.b64decode(signature_b64)

        try:

            pkcs1_15.new(public_key).verify(
                hash_obj,
                signature
            )

            status = "HỢP LỆ"

        except (ValueError, TypeError):

            status = "KHÔNG HỢP LỆ"

        # ============================================
        # Kiểm tra hết hạn
        # ============================================

        expire_dt = datetime.strptime(
            expire_time,
            "%Y-%m-%d %H:%M:%S"
        )

        now = datetime.now()

        if now > expire_dt:
            expire_status = "ĐÃ HẾT HIỆU LỰC"
        else:
            expire_status = "CÒN HIỆU LỰC"

        # ============================================
        # Kết quả verify
        # ============================================

        result = f"""
==================================
KẾT QUẢ VERIFY CHỮ KÝ SỐ PDF
==================================

Người ký:
{signer}

Thời gian ký:
{sign_time}

Hết hiệu lực:
{expire_time}

Tình trạng chứng thư:
{expire_status}

Tình trạng chữ ký:
{status}
"""

        return result

    except Exception as e:

        return f"Lỗi verify: {str(e)}"

# ============================================================
# GIAO DIỆN GRADIO
# ============================================================

with gr.Blocks(title="RSA PDF Digital Signature") as demo:

    gr.Markdown("""
# 🔐 RSA PDF Digital Signature

## Chức năng
- Sinh khóa RSA
- Ký số PDF
- Verify chữ ký số PDF
""")

    # ========================================================
    # TAB 1 - SINH KHÓA
    # ========================================================

    with gr.Tab("1. Sinh khóa RSA"):

        bit_size = gr.Dropdown(
            choices=[1024, 2048, 3072, 4096],
            value=2048,
            label="Kích thước RSA"
        )

        btn_gen = gr.Button("Sinh khóa")

        private_key_box = gr.Textbox(
            label="Private Key (BÍ MẬT)",
            lines=12
        )

        public_key_box = gr.Textbox(
            label="Public Key (CÔNG KHAI)",
            lines=12
        )

        btn_gen.click(
            generate_keys,
            inputs=bit_size,
            outputs=[private_key_box, public_key_box]
        )

    # ========================================================
    # TAB 2 - KÝ SỐ PDF
    # ========================================================

    with gr.Tab("2. Ký số PDF"):

        signer_name = gr.Textbox(
            label="Tên người ký",
            value="Ông Đinh Hoàng Gia"
        )

        pdf_input = gr.File(
            label="Upload PDF"
        )

        private_key_sign = gr.Textbox(
            label="Private Key",
            lines=10
        )

        sign_btn = gr.Button("Ký số PDF")

        signed_pdf_output = gr.File(
            label="PDF đã ký"
        )

        sign_status = gr.Textbox(
            label="Trạng thái"
        )

        sign_btn.click(
            sign_pdf,
            inputs=[
                pdf_input,
                private_key_sign,
                signer_name
            ],
            outputs=[
                signed_pdf_output,
                sign_status
            ]
        )

    # ========================================================
    # TAB 3 - VERIFY PDF
    # ========================================================

    with gr.Tab("3. Verify chữ ký số"):

        verify_pdf_input = gr.File(
            label="Upload PDF đã ký"
        )

        public_key_verify = gr.Textbox(
            label="Public Key",
            lines=10
        )

        verify_btn = gr.Button("Verify")

        verify_result = gr.Textbox(
            label="Kết quả Verify",
            lines=15
        )

        verify_btn.click(
            verify_pdf,
            inputs=[
                verify_pdf_input,
                public_key_verify
            ],
            outputs=verify_result
        )

# ============================================================
# CHẠY APP
# ============================================================

if __name__ == "__main__":
    demo.launch()
