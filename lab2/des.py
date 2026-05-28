import streamlit as st
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64


st.set_page_config(page_title="DES Encryption & Decryption", page_icon="🔐", layout="centered")

st.title("🔐 DES Encryption & Decryption")


tab1, tab2 = st.tabs(["Text Encryption", "File Encryption"])

with tab1:
    st.subheader("Mã hóa / Giải mã Text")

    if 'result' not in st.session_state:
        st.session_state.result = ""

    input_text = st.text_area("Nhập văn bản", height=100)
    des_key = st.text_input("Khóa DES (8 ký tự)", type="password", max_chars=8)

    
    col1, col2 = st.columns(2)

    
    with col1:
        if st.button("Mã hóa", use_container_width=True):
            if len(des_key) != 8:
                st.error("Lỗi: Khóa DES phải bao gồm chính xác 8 ký tự!")
            elif not input_text:
                st.warning("Vui lòng nhập văn bản cần mã hóa!")
            else:
                try:
                    
                    key = des_key.encode('utf-8')
                    cipher = DES.new(key, DES.MODE_ECB) 
                    
                    
                    padded_text = pad(input_text.encode('utf-8'), DES.block_size)
                    
                    encrypted_bytes = cipher.encrypt(padded_text)
                    st.session_state.result = base64.b64encode(encrypted_bytes).decode('utf-8')
                except Exception as e:
                    st.error(f"Đã xảy ra lỗi mã hóa: {e}")

    
    with col2:
        if st.button("Giải mã", use_container_width=True):
            if len(des_key) != 8:
                st.error("Lỗi: Khóa DES phải bao gồm chính xác 8 ký tự!")
            elif not input_text:
                st.warning("Vui lòng nhập chuỗi mã hóa (Base64) vào ô văn bản!")
            else:
                try:
                    
                    key = des_key.encode('utf-8')
                    cipher = DES.new(key, DES.MODE_ECB)
                    
                    
                    encrypted_bytes = base64.b64decode(input_text)
                    decrypted_padded_text = cipher.decrypt(encrypted_bytes)
                    decrypted_text = unpad(decrypted_padded_text, DES.block_size).decode('utf-8')
                    
                    st.session_state.result = decrypted_text
                except ValueError:
                    st.error("Lỗi: Key không đúng hoặc chuỗi đầu vào bị sai!")
                except Exception as e:
                    st.error(f"Đã xảy ra lỗi giải mã: {e}")


    st.text_area("Kết quả", value=st.session_state.result, height=100)

with tab2:
    st.write("Tính năng mã hóa file đang được phát triển...")
