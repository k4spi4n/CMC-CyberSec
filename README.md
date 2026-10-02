# ML-DSA Document Signer: Nhóm 8 (NIST FIPS 204)

Ứng dụng ký và xác minh tài liệu bằng chữ ký số hậu lượng tử **ML-DSA**. Dùng thư viện `pyca/cryptography` trên nền OpenSSL.

| Tài liệu | Nội dung |
|---|---|
| [REPORT.md](REPORT.md) | Giải thích chuẩn, thiết kế, **bảng đối chiếu NIST, code và bằng chứng**, kiểm thử, hạn chế |
| [AI_USAGE.md](AI_USAGE.md) | Prompt, cách kiểm chứng output của AI, lỗi AI đã sửa |
| [DEMO.md](DEMO.md) | Kịch bản demo 8–10 phút |
| `evidence/` | Log pytest, demo, benchmark, ảnh chụp web, thông tin môi trường |
| `docs/nist/NIST.FIPS.204.pdf` | Bản chuẩn gốc |

## Cài đặt

Yêu cầu Python ≥ 3.10.

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## Sử dụng CLI

```powershell
# bảng tham số
.venv\Scripts\python -m mldsa_app info

# sinh khóa (hỏi mật khẩu; hoặc --password-env TEN_BIEN)
.venv\Scripts\python -m mldsa_app keygen --alg ML-DSA-65 --out keys\alice

# ký -> tạo hop_dong.pdf.sig.json
.venv\Scripts\python -m mldsa_app sign hop_dong.pdf --key keys\alice.key.pem

# xác minh (exit code 0 = hợp lệ, 1 = không hợp lệ)
.venv\Scripts\python -m mldsa_app verify hop_dong.pdf --pub keys\alice.pub.pem

# kịch bản demo tự động 9 bước, benchmark so với RSA/ECDSA
.venv\Scripts\python -m mldsa_app demo
.venv\Scripts\python -m mldsa_app bench
```

Tùy chọn `--context` (≤ 255 byte, mặc định `CMC-CyberSec/doc-sign/v1`) phải giống nhau giữa lúc ký và lúc xác minh.

## Web demo

```powershell
.venv\Scripts\python -m mldsa_app.web
# mở http://127.0.0.1:5000
```

Các chức năng: sinh khóa, ký văn bản hoặc tệp, xác minh. Có các nút tấn công: *sửa 1 ký tự*, *lật 1 bit chữ ký*, *đổi context*.
Đây là bản **chỉ để demo**: khóa bí mật nằm trong RAM của server và server chỉ lắng nghe trên localhost.

## Kiểm thử

```powershell
.venv\Scripts\python -m pytest -v
```

| File | Số test | Nội dung |
|---|---|---|
| `tests/test_nist_vectors.py` | 166 | 75 keyGen, 45 sigVer pure, 45 sigVer external-μ từ **NIST ACVP**, cộng 1 test đếm số vector |
| `tests/test_crosscheck.py` | 12 | Đối chiếu chéo với dilithium-py (implementation độc lập) |
| `tests/test_core.py` | 80 | Kích thước, dữ liệu bị sửa, chữ ký bị sửa, khóa sai, context, input biên, lưu khóa, bundle, CLI |
| `tests/test_web.py` | 12 | API web và kiểm tra đầu vào |
