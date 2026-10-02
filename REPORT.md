# Báo cáo nhóm 8: Chữ ký hậu lượng tử ML-DSA (NIST FIPS 204)

> **Sản phẩm:** ứng dụng ký và xác minh tài liệu bằng ML-DSA, gồm CLI và web demo.
> **Thư viện mật mã:** `pyca/cryptography` 50.0.2 trên nền OpenSSL 4.0.3. Nhóm không tự cài đặt toán học lattice.
> **Kết quả kiểm thử:** 270/270 test pass. Trong đó có 165 vector chính thức của NIST ACVP, 12 test đối chiếu chéo với một implementation độc lập và 92 test chức năng, tấn công và input biên. Xem `evidence/pytest_report.txt`.

---

## 1. Hiểu tiêu chuẩn FIPS 204

### 1.1 Mục tiêu

FIPS 204 (ban hành 13/08/2024) chuẩn hóa **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm), được phát triển từ CRYSTALS-Dilithium. Giống mọi lược đồ chữ ký số, ML-DSA cung cấp:

- **Toàn vẹn dữ liệu:** phát hiện mọi thay đổi trái phép.
- **Xác thực nguồn gốc:** chỉ người giữ khóa bí mật mới tạo được chữ ký hợp lệ.
- **Chống chối bỏ (non-repudiation):** người nhận có thể chứng minh với bên thứ ba rằng chính người ký đã ký.

Điểm khác biệt quan trọng: ML-DSA được thiết kế để **an toàn cả trước kẻ tấn công có máy tính lượng tử quy mô lớn**. RSA (FIPS 186-5) và ECDSA dựa trên bài toán phân tích thừa số và logarit rời rạc, nên đều bị thuật toán Shor phá trong thời gian đa thức. ML-DSA dựa trên bài toán lattice, hiện chưa có thuật toán lượng tử nào giải hiệu quả.

### 1.2 Tính chất bảo mật và giả định (FIPS 204, §3.1–3.2)

| Khía cạnh | Nội dung |
|---|---|
| Mục tiêu bảo mật | **SUF-CMA** (strongly existentially unforgeable under chosen-message attack). Dù kẻ tấn công được xin chữ ký trên thông điệp tùy ý, chúng vẫn không tạo được *bất kỳ* chữ ký hợp lệ mới nào, kể cả chữ ký thứ hai cho một thông điệp đã được ký. |
| Tính chất bổ sung | **BUFF** (beyond unforgeability). ML-DSA không ký trực tiếp M mà ký μ = H(tr ‖ M′), với tr = H(pk). Nhờ đó chữ ký bị ràng buộc với đúng khóa công khai (§3.3). |
| Giả định khó | **MLWE** (Module Learning With Errors): từ **t** = **A s₁** + **s₂** không khôi phục được **s₁**, **s₂** ngắn. **SelfTargetMSIS** (một biến thể của Module-SIS): không tìm được vector ngắn thỏa ràng buộc hash. |
| Cấu trúc | Chữ ký kiểu Schnorr, theo mô hình **Fiat–Shamir with Aborts**. Người ký cam kết **w₁** = HighBits(**A y**), tính thử thách c = SampleInBall(H(μ ‖ w₁)), rồi trả lời **z** = **y** + c**s₁**. Nếu **z** có thể làm lộ thông tin về **s₁** thì *loại bỏ (abort) và thử lại* (Algorithm 7, dòng 23 và 28). |

### 1.3 Ba thuật toán chính

| Thuật toán | FIPS 204 | Đầu vào → đầu ra | Ghi chú |
|---|---|---|---|
| KeyGen | Alg. 1 → Alg. 6 | ξ (32 B ngẫu nhiên) → (pk, sk) | ρ sinh ra ma trận **A**. pk = (ρ, **t₁**), trong đó **t₁** là **t** đã bỏ d = 13 bit thấp. |
| Sign | Alg. 2 → Alg. 7 | (sk, M, ctx) → σ = (c̃, **z**, **h**) | M′ = 0x00 ‖ \|ctx\| ‖ ctx ‖ M, μ = H(tr ‖ M′, 64), sau đó chạy vòng lặp rejection sampling. |
| Verify | Alg. 3 → Alg. 8 | (pk, M, σ, ctx) → true/false | Tính lại **w′₁** = UseHint(**h**, **A z** − c**t₁**·2ᵈ), kiểm tra ‖**z**‖∞ < γ₁ − β, số bit 1 trong **h** ≤ ω, và c̃ = H(μ ‖ w′₁). |

### 1.4 Tham số bảo mật (FIPS 204, Table 1 và Table 2)

| Tham số | Ý nghĩa | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|---|
| q | modulus (2²³ − 2¹³ + 1) | 8380417 | 8380417 | 8380417 |
| d | số bit bỏ đi khỏi **t** | 13 | 13 | 13 |
| (k, ℓ) | kích thước ma trận **A** | (4,4) | (6,5) | (8,7) |
| η | biên hệ số khóa bí mật | 2 | 4 | 2 |
| τ | số hệ số ±1 trong c | 39 | 49 | 60 |
| λ | độ bền va chạm của c̃ (bit) | 128 | 192 | 256 |
| γ₁ | biên hệ số của **y** | 2¹⁷ | 2¹⁹ | 2¹⁹ |
| γ₂ | phạm vi làm tròn | (q−1)/88 | (q−1)/32 | (q−1)/32 |
| β = τ·η | | 78 | 196 | 120 |
| ω | số bit 1 tối đa trong hint | 80 | 55 | 75 |
| Số vòng lặp ký kỳ vọng | | 4.25 | 5.1 | 3.85 |
| **Security category** | | **2** | **3** | **5** |
| pk / sk / chữ ký (byte) | | 1312 / 2560 / 2420 | 1952 / 4032 / 3309 | 2592 / 4896 / 4627 |

Category 2 tương đương độ khó tìm va chạm SHA-256. Category 3 tương đương AES-192, category 5 tương đương AES-256. **Nhóm chọn mặc định ML-DSA-65** để cân bằng giữa an toàn và kích thước. Theo §3.6.1, ML-DSA-65 yêu cầu RBG có độ mạnh ít nhất 192 bit. DRBG mặc định của OpenSSL (CTR-DRBG AES-256 theo SP 800-90A) đạt 256 bit.

### 1.5 Các lựa chọn mà chuẩn cho phép

- **Hedged hay deterministic (§3.4):** mặc định là *hedged*, tức rnd ← RBG và ρ″ = H(K ‖ rnd ‖ μ). Cách này chống tấn công side-channel và fault tốt hơn. Biến thể deterministic (rnd = 0³²) chỉ dùng khi không có nguồn ngẫu nhiên. **Ứng dụng dùng hedged.**
- **Pure ML-DSA hay HashML-DSA (§5.4):** chuẩn ghi rõ *"In general, the 'pure' ML-DSA version is preferred"* và khuyến nghị mỗi cặp khóa chỉ dùng cho một trong hai. **Ứng dụng chỉ dùng pure ML-DSA.**
- **Context string ctx (Alg. 2, dòng 1):** chuỗi byte tối đa 255 byte, dùng để tách miền (domain separation). Chữ ký tạo trong ngữ cảnh "ký hợp đồng" sẽ không hợp lệ trong ngữ cảnh "thanh toán".
- **μ tính ở module khác (Alg. 7, dòng 6):** *"message representative that may optionally be computed in a different cryptographic module"*. Ứng dụng tận dụng điều này để ký tệp lớn theo luồng mà không phải đọc toàn bộ tệp vào RAM.
- **Lưu seed thay cho sk (§3.6.3, §4):** seed ξ 32 byte đủ để tái tạo sk, nhưng *"shall be treated with the same safeguards as a private key"*.

### 1.6 So sánh với chữ ký cổ điển (số đo thực tế, `evidence/benchmark.txt`)

| Thuật toán | KeyGen (ms) | Sign (ms) | Verify (ms) | pk (B) | Chữ ký (B) | Kháng lượng tử |
|---|---|---|---|---|---|---|
| ML-DSA-44 | 0.09 | 0.47 | 0.10 | 1312 | 2420 | Có |
| ML-DSA-65 | 0.15 | 0.90 | 0.15 | 1952 | 3309 | Có |
| ML-DSA-87 | 0.21 | 0.97 | 0.22 | 2592 | 4627 | Có |
| ECDSA P-256 | 0.01 | 0.02 | 0.06 | 65 | ~70 | Không |
| RSA-3072 PSS | 151.92 | 0.59 | 0.05 | 384 | 384 | Không |

Nhận xét: ML-DSA nhanh (KeyGen nhanh hơn RSA khoảng 1000 lần). Cái giá phải trả là kích thước: chữ ký ML-DSA-65 lớn khoảng 47 lần chữ ký ECDSA. Đây là đánh đổi điển hình của mật mã hậu lượng tử.

---

## 2. Thiết kế ứng dụng

```
mldsa_app/
  params.py    bảng tham số FIPS 204 (Table 1, 2)
  core.py      keygen, sign, verify, lưu khóa, ký theo luồng, bundle chữ ký
  cli.py       python -m mldsa_app {keygen, sign, verify, info, bench, demo}
  web.py       Flask demo (127.0.0.1:5000) + templates/index.html
tests/         270 test (pytest), vectors/ = NIST ACVP JSON
evidence/      log test, demo, benchmark, ảnh chụp web
```

### Các quyết định mật mã và lý do

| # | Quyết định | Lý do |
|---|---|---|
| D1 | Dùng `pyca/cryptography` (OpenSSL) thay vì tự viết | Thư viện uy tín và được duy trì. OpenSSL có code constant-time và xóa bộ nhớ nhạy cảm (§3.6.3). Tự cài lattice dễ sai và dễ rò rỉ side-channel. |
| D2 | Mặc định ML-DSA-65, cho phép chọn 44/87 | Category 3, kích thước chấp nhận được. Người dùng có thể chọn mức cao hơn. |
| D3 | Pure ML-DSA kèm context `CMC-CyberSec/doc-sign/v1` | §5.4 ưu tiên pure. Context có version giúp tách miền và nâng cấp định dạng sau này. |
| D4 | Ký tệp qua **external μ** (`MLDSAMuHasher` → `sign_mu`) | Hash từng khối 1 MiB nên ký được tệp lớn với bộ nhớ O(1). Chữ ký thu được *là chữ ký ML-DSA chuẩn* trên toàn bộ tệp, đã chứng minh bằng test đối chiếu chéo. rnd vẫn được sinh trong OpenSSL, đúng yêu cầu §5.4. |
| D5 | Hedged signing (mặc định của OpenSSL) | §3.4: chống fault và side-channel. Không cần biến thể deterministic để tương thích. |
| D6 | Khóa bí mật = seed ξ trong PKCS#8 PEM **mã hóa bằng mật khẩu** (`BestAvailableEncryption`) | §3.6.3 cho phép lưu seed nhưng bắt buộc bảo vệ như khóa bí mật. Seed nhỏ (32 B so với 4032 B). |
| D7 | Bộ tham số lấy **từ khóa công khai**, không lấy từ metadata | Chống tấn công nhầm lẫn thuật toán (algorithm confusion). |
| D8 | Context do **bên xác minh** quyết định | Kẻ tấn công không thể sửa metadata để chữ ký "lọt" sang ngữ cảnh khác. ctx nằm trong μ nên sửa metadata cũng vô ích (đã kiểm thử). |
| D9 | Kiểm tra độ dài chữ ký trước khi verify | §3.6.2: phải trả false khi độ dài sai. OpenSSL cũng kiểm tra, nhóm thêm một lớp kiểm tra ở tầng ứng dụng. |

**Định dạng bundle** (`*.sig.json`): `format`, `algorithm`, `context_b64`, `public_key_sha3_256`, `file_name`, `file_size`, `signed_at`, `signature_b64`. Chỉ `signature_b64` được bảo vệ bằng mật mã. Các trường còn lại là thông tin tham khảo và **không được dùng để ra quyết định bảo mật** (xem D7, D8). Lưu ý: `signed_at` không phải dấu thời gian tin cậy.

---

## 3. Bảng đối chiếu yêu cầu NIST, code và bằng chứng

| # | Yêu cầu FIPS 204 | Code thực hiện | Bằng chứng |
|---|---|---|---|
| R1 | KeyGen từ seed ξ cho đúng pk (Alg. 1, 6) | `core.generate_keypair`, `core.key_from_seed` (`core.py:65-74`) | `test_nist_vectors.py::test_keygen_from_seed_matches_nist`: **75/75** vector ACVP khớp từng byte |
| R2 | Verify chấp nhận chữ ký hợp lệ, từ chối thông điệp hoặc chữ ký bị sửa (Alg. 3, 8) | `core.verify_bytes` (`core.py:153`) | `test_sigver_pure_matches_nist`: **45/45** vector (sửa message, sửa c̃, sửa z, sửa hint) |
| R3 | μ tính ngoài module (Alg. 7 dòng 6, Alg. 8 dòng 7) | `core.compute_mu`, `sign_stream`, `verify_stream` (`core.py:140-171`) | `test_sigver_external_mu_matches_nist`: **45/45**. `test_streamed_signature_is_standard_signature`: chữ ký luồng được dilithium-py chấp nhận trên toàn bộ tệp |
| R4 | M′ = 0 ‖ \|ctx\| ‖ ctx ‖ M, \|ctx\| ≤ 255 (Alg. 2, 3 dòng 1) | `core.encode_context` (`core.py:132-137`) | `test_context_length_boundary` (0, 1, 255 OK, 256 bị từ chối), `test_context_utf8_byte_length_counts`, `test_our_signature_verifies_in_reference` (ctx khác thì fail ở implementation độc lập) |
| R5 | Kích thước pk, sk, σ theo Table 2 | `params.py` + kiểm tra độ dài trong `verify_file_stream` (`core.py:244-246`) | `test_sizes_match_fips204_table2` (cả 3 bộ), `test_param_table_consistency` (pk = 32 + 32k·10) |
| R6 | §3.6.2: trả false nếu độ dài σ hoặc pk sai | OpenSSL + kiểm tra độ dài ở tầng ứng dụng | `test_malformed_signature_rejected` (cắt ngắn, thêm byte, rỗng), `test_public_key_wrong_length_rejected` |
| R7 | Alg. 21: hint mã hóa sai thì Verify trả false | OpenSSL `HintBitUnpack` | `test_malformed_hint_rejected`, `test_every_region_of_signature_is_checked` |
| R8 | §3.4: hedged signing mặc định | `key.sign` / `key.sign_mu` của OpenSSL | `test_hedged_signatures_are_randomized`: hai chữ ký khác nhau, cả hai đều hợp lệ. Demo bước 4 |
| R9 | §3.6.1: ξ và rnd từ RBG được phê duyệt | OpenSSL DRBG (SP 800-90A) | `evidence/environment.txt` (OpenSSL 4.0.3). Đây là thiết kế, không kiểm thử trực tiếp được |
| R10 | §3.6.3: seed phải được bảo vệ như khóa bí mật | `core.save_private_key` với PKCS#8 mã hóa (`core.py:94-100`). CLI cảnh báo khi dùng `--no-password`. Web bắt mật khẩu ≥ 8 ký tự | `test_encrypted_private_key_roundtrip`, `test_wrong_password_rejected`, `test_export_requires_strong_password` |
| R11 | §5.4: ưu tiên pure, một khóa chỉ dùng một biến thể | Không có code HashML-DSA | Xem lại code: không có lời gọi pre-hash nào |
| R12 | §3.5: gắn khóa công khai với danh tính | Fingerprint SHA3-256(pk) hiển thị trong CLI và web | Ngoài phạm vi (không có PKI). Xem mục 6 |
| R13 | §3.6.4: không dùng số thực dấu phẩy động | OpenSSL dùng số nguyên. `params.py` dùng `//` | Xem lại code |
| R14 | Tương thích với implementation khác | Dùng đúng mã hóa pk/σ (Alg. 22, 26) | `test_crosscheck.py`: **12/12**. Cùng seed cho cùng pk, chữ ký kiểm tra chéo được hai chiều với dilithium-py |

Nguồn vector: [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files), thư mục `ML-DSA-keyGen-FIPS204` và `ML-DSA-sigVer-FIPS204` (SHA-256 của file nằm trong `evidence/environment.txt`). Hai nhóm vector không dùng được: *preHash* (ngoài phạm vi, R11) và *internal không qua μ*, vì API không mở `Sign_internal` với M′ tùy ý.

---

## 4. Kiểm thử bảo mật

Lệnh chạy: `.venv\Scripts\python -m pytest -v`. Kết quả **270 passed** (`evidence/pytest_report.txt`).

| Nhóm kịch bản | Test cụ thể | Kỳ vọng | Kết quả |
|---|---|---|---|
| **Dữ liệu bị sửa** | lật bit đầu/cuối, thêm byte, cắt byte, thay bằng rỗng (× 3 bộ tham số) | Từ chối | Pass |
| | Tệp hợp đồng sửa từ "100.000.000" thành "900.000.000" (demo bước 5, `test_bundle_tampered_file`) | Từ chối | Pass |
| **Chữ ký bị sửa** | lật bit trong c̃, z, hint. Cắt ngắn, thêm byte, toàn 0, ngẫu nhiên, rỗng. Hint sai định dạng | Từ chối | Pass |
| **Khóa sai** | khóa khác cùng bộ tham số. Khác bộ tham số (44 và 65). Mallory ký rồi giả fingerprint của Alice | Từ chối | Pass |
| | Sai mật khẩu khóa bí mật. Thiếu mật khẩu. Khóa EC thay cho ML-DSA | Báo lỗi | Pass |
| | pk sai độ dài. Seed khác 32 B (0, 31, 33, 64) | Báo lỗi | Pass |
| **Ngữ cảnh** | ctx khác, ctx có thêm `\x00`, ctx rỗng. Sửa `context_b64` trong metadata để khớp ctx mới | Từ chối | Pass |
| **Input biên** | message rỗng, 1 byte, 5 KB, 3 MiB + 17 B (nhiều khối), 20 MiB (demo) | Hợp lệ | Pass |
| | ctx 0, 1, 255 byte hợp lệ. 256 byte bị từ chối. 128 ký tự "đ" (256 byte UTF-8) bị từ chối | Đúng biên | Pass |
| **Metadata/định dạng** | sai `format`, sai `algorithm`, base64 hỏng, thiếu chữ ký, JSON hỏng, JSON là mảng | Từ chối, không crash | Pass |
| **Web API** | tên khóa chứa `<script>`, thuật toán lạ, PEM rác, mật khẩu xuất khóa < 8 ký tự | HTTP 400 | Pass |
| **Vector NIST** | 75 keyGen + 45 sigVer pure + 45 sigVer external-μ | Khớp kết quả NIST | 165/165 |
| **Đối chiếu chéo** | ứng dụng và dilithium-py: cùng seed cho cùng pk, chữ ký kiểm tra được hai chiều | Khớp | 12/12 |

---

## 5. Hướng dẫn chạy

Xem `README.md`. Tóm tắt:

```powershell
python -m venv .venv; .venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m mldsa_app demo      # kịch bản 9 bước
.venv\Scripts\python -m mldsa_app.web       # http://127.0.0.1:5000
.venv\Scripts\python -m pytest              # 270 test
```

---

## 6. Hạn chế và rủi ro còn lại

1. **Không có PKI hay chứng chỉ (§3.5).** Người xác minh phải nhận pk qua kênh tin cậy và so fingerprint thủ công.
2. **Không có dấu thời gian tin cậy.** Trường `signed_at` không được ký. Muốn chứng minh thời điểm ký cần TSA (RFC 3161).
3. **Web demo giữ khóa bí mật trong RAM** của tiến trình Flask để demo cho nhanh. Server chỉ bind `127.0.0.1` và không có xác thực người dùng. Không được dùng nguyên trạng cho môi trường thật.
4. **Python không xóa (zeroize) được bộ nhớ** chứa mật khẩu hay PEM. OpenSSL tự xóa giá trị trung gian bên trong nó (§3.6.3), nhưng các bản sao trong Python thì không.
5. **Không có HashML-DSA:** chủ động bỏ theo khuyến nghị §5.4. Nhờ external μ nên tệp lớn vẫn ký được.
6. **ML-DSA còn mới:** nhiều hệ thống đang triển khai theo kiểu *hybrid* (ECDSA + ML-DSA) trong giai đoạn chuyển tiếp. Đây là hướng mở rộng.

## 7. Tài liệu tham khảo

- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, 2024. https://doi.org/10.6028/NIST.FIPS.204 (bản lưu: `docs/nist/NIST.FIPS.204.pdf`)
- NIST SP 800-90A Rev. 1, *Recommendation for Random Number Generation Using Deterministic RBGs*.
- NIST ACVP-Server, test vectors ML-DSA. https://github.com/usnistgov/ACVP-Server
- pyca/cryptography: ML-DSA. https://cryptography.io
- G. Pope, *dilithium-py*: implementation Python thuần, chỉ dùng để đối chiếu chéo. https://github.com/GiacomoPope/dilithium-py
