# Hệ mã cổ điển và hệ mã công khai

Ứng dụng web được xây dựng bằng Streamlit để mã hóa và giải mã các loại mật mã khác nhau.

## Cài đặt

1. Clone repository này về máy local của bạn
2. Cài đặt các dependencies cần thiết:
```bash
pip install -r requirements.txt
```

## Chạy ứng dụng locally

```bash
streamlit run app.py
```

## Deploy lên Streamlit Cloud

1. Đăng ký tài khoản tại [Streamlit Cloud](https://streamlit.io/cloud)
2. Tạo một repository mới trên GitHub và push code lên đó
3. Trên Streamlit Cloud:
   - Click "New app"
   - Chọn repository của bạn
   - Chọn branch (thường là main)
   - Chọn file chính (app.py)
   - Click "Deploy"

## Cấu trúc project

- `app.py`: File chính chứa giao diện người dùng Streamlit
- `code.py`: Chứa các hàm mã hóa và giải mã
- `requirements.txt`: Liệt kê các dependencies cần thiết
- `README.md`: Hướng dẫn sử dụng và deploy

## Các tính năng

- Mã đảo ngược
- Mã Caesar
- Mã đổi chỗ
- Mã thay thế đơn
- Mã Affine
- Mã Vigenere
- Mã Hill
- Base64
- Hệ mã XOR
- Mã nhân
- Fernet chuỗi ký tự
- Thám mã Caesar
- Mã DES
- Mã RSA
- Mã Elgamal # Information_security
