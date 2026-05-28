# ============================================================
# ỨNG DỤNG RSA + GRADIO
# Tác giả minh họa: Ông Đinh Hoàng Gia
#
# Chức năng:
# 1. Sinh cặp khóa RSA
#    - Private Key: bảo mật
#    - Public Key : gửi công khai
#
# 2. Mã hóa thông báo UTF8 tiếng Việt
#    - Đầu ra Base64
#
# 3. Giải mã thông báo
#
# 4. Kiểm tra lỗi:
#    - Message quá dài
#    - Sai khóa
#    - Dữ liệu Base64 lỗi
# ============================================================



import gradio as gr
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# ============================================================
# SINH KHÓA RSA
# ============================================================
def generate_keys(bits=2048):
    try:
        key = RSA.generate(bits)

        # PRIVATE KEY -> PHẢI BẢO MẬT
        private_key = key.export_key().decode("utf-8")

        # PUBLIC KEY -> GỬI CÔNG KHAI
        public_key = key.publickey().export_key().decode("utf-8")

        return private_key, public_key

    except Exception as e:
        return f"Lỗi: {str(e)}", ""

# ============================================================
# MÃ HÓA THÔNG ĐIỆP UTF8
# ============================================================
def encrypt_message(message, public_key_text):
    try:
        if not message.strip():
            return "Lỗi: Chưa nhập thông báo."

        if not public_key_text.strip():
            return "Lỗi: Chưa có Public Key."

        public_key = RSA.import_key(public_key_text)

        cipher = PKCS1_OAEP.new(
            public_key,
            hashAlgo=SHA256
        )

        message_bytes = message.encode("utf-8")

        # Giới hạn OAEP SHA256
        # max = key_size_bytes - 2*hash_size - 2
        key_size_bytes = public_key.size_in_bytes()
        hash_size = SHA256.digest_size

        max_length = key_size_bytes - 2 * hash_size - 2

        if len(message_bytes) > max_length:
            return (
                f"Lỗi: Message quá dài.\n"
                f"RSA {public_key.size_in_bits()} bits chỉ mã hóa tối đa "
                f"{max_length} bytes với OAEP SHA256.\n"
                f"Hiện tại: {len(message_bytes)} bytes."
            )

        encrypted = cipher.encrypt(message_bytes)

        # Base64 để dễ truyền
        encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

        return encrypted_b64

    except ValueError as ve:
        return f"Lỗi RSA: {str(ve)}"

    except Exception as e:
        return f"Lỗi mã hóa: {str(e)}"

# ============================================================
# GIẢI MÃ
# ============================================================
def decrypt_message(cipher_b64, private_key_text):
    try:
        if not cipher_b64.strip():
            return "Lỗi: Chưa nhập ciphertext."

        if not private_key_text.strip():
            return "Lỗi: Chưa có Private Key."

        private_key = RSA.import_key(private_key_text)

        cipher = PKCS1_OAEP.new(
            private_key,
            hashAlgo=SHA256
        )

        # Giải mã Base64
        encrypted_data = base64.b64decode(cipher_b64)

        decrypted = cipher.decrypt(encrypted_data)

        return decrypted.decode("utf-8")

    except ValueError:
        return (
            "Lỗi: Không thể giải mã.\n"
            "Nguyên nhân có thể:\n"
            "- Sai Private Key\n"
            "- Ciphertext bị sửa đổi\n"
            "- Dữ liệu không hợp lệ"
        )

    except base64.binascii.Error:
        return "Lỗi: Ciphertext Base64 không hợp lệ."

    except Exception as e:
        return f"Lỗi giải mã: {str(e)}"

# ============================================================
# GIAO DIỆN GRADIO
# ============================================================
with gr.Blocks(title="RSA Encryption Demo") as demo:

    gr.Markdown("""
    # 🔐 RSA Encryption Demo - Ông Đinh Hoàng Gia

    ## Chức năng
    - Sinh cặp khóa RSA
    - Mã hóa UTF8 tiếng Việt
    - Xuất Base64
    - Giải mã thông báo
    """)

    # ========================================================
    # SINH KHÓA
    # ========================================================
    with gr.Tab("1. Sinh khóa RSA"):

        bit_size = gr.Dropdown(
            choices=[1024, 2048, 3072, 4096],
            value=2048,
            label="Kích thước khóa RSA"
        )

        btn_gen = gr.Button("Sinh khóa RSA")

        private_key_box = gr.Textbox(
            label="Private Key (BÍ MẬT)",
            lines=12
        )

        public_key_box = gr.Textbox(
            label="Public Key (GỬI CÔNG KHAI)",
            lines=12
        )

        btn_gen.click(
            generate_keys,
            inputs=bit_size,
            outputs=[private_key_box, public_key_box]
        )

    # ========================================================
    # MÃ HÓA
    # ========================================================
    with gr.Tab("2. Mã hóa thông báo"):

        plaintext_box = gr.Textbox(
            label="Thông báo UTF8 tiếng Việt",
            lines=5,
            placeholder="Ví dụ: Xin chào ông Đinh Hoàng Gia!"
        )

        public_encrypt_box = gr.Textbox(
            label="Public Key của ông Gia",
            lines=10
        )

        encrypt_btn = gr.Button("Mã hóa")

        cipher_box = gr.Textbox(
            label="Ciphertext Base64",
            lines=8
        )

        encrypt_btn.click(
            encrypt_message,
            inputs=[plaintext_box, public_encrypt_box],
            outputs=cipher_box
        )

    # ========================================================
    # GIẢI MÃ
    # ========================================================
    with gr.Tab("3. Giải mã thông báo"):

        cipher_input_box = gr.Textbox(
            label="Ciphertext Base64",
            lines=8
        )

        private_decrypt_box = gr.Textbox(
            label="Private Key bí mật",
            lines=10
        )

        decrypt_btn = gr.Button("Giải mã")

        decrypted_box = gr.Textbox(
            label="Thông báo gốc",
            lines=5
        )

        decrypt_btn.click(
            decrypt_message,
            inputs=[cipher_input_box, private_decrypt_box],
            outputs=decrypted_box
        )

    # ========================================================
    # THÔNG TIN
    # ========================================================
    with gr.Accordion("Lưu ý bảo mật", open=False):

        gr.Markdown("""
        ## ⚠️ Lưu ý

        ### Private Key
        - Phải giữ bí mật tuyệt đối
        - Không gửi cho người khác

        ### Public Key
        - Có thể gửi công khai
        - Dùng để mã hóa dữ liệu gửi cho ông Gia

        ### RSA không phù hợp cho dữ liệu lớn
        - RSA thường chỉ mã hóa khóa AES
        - Dữ liệu lớn nên dùng Hybrid Encryption
        """)

# ============================================================
# CHẠY ỨNG DỤNG
# ============================================================
if __name__ == "__main__":
    demo.launch()

