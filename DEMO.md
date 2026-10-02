# Kịch bản demo (8–10 phút)

Chuẩn bị trước: mở sẵn 2 terminal ở thư mục dự án, chạy `.venv\Scripts\python -m mldsa_app.web` và mở http://127.0.0.1:5000. Mở sẵn `REPORT.md` ở mục 3 (bảng đối chiếu).

Slide: https://claude.ai/artifact/VDWUhcERMNMzVvmRcMSZ5R. Phúc trình bày slide 1–6, Bình slide 7–10, Luân slide 11–14, Duy slide 15–18.

| Phút | Người trình bày | Nội dung | Thao tác |
|---|---|---|---|
| 0:00–1:30 | Vũ Hoàng Phúc | **Vấn đề:** máy tính lượng tử dùng thuật toán Shor phá RSA/ECDSA. Kịch bản "thu bây giờ, giả mạo sau" với hợp đồng có hiệu lực dài hạn. NIST chuẩn hóa ML-DSA (FIPS 204, 08/2024). Ý tưởng chính: MLWE, Fiat–Shamir with aborts, SUF-CMA | Slide hoặc REPORT §1.1–1.3 |
| 1:30–2:30 | Vũ Hoàng Phúc | **Tham số:** 3 bộ 44/65/87, ứng với category 2/3/5. Vì sao chọn 65 | `python -m mldsa_app info` |
| 2:30–5:00 | Đặng Thái Bình | **Web demo:** (1) sinh khóa Alice, ML-DSA-65, chỉ ra pk 1952 B. (2) Ký "Bên A chuyển 100.000.000 VND". (3) Xác minh: **xanh**. (4) Bấm *Sửa 1 ký tự*: **đỏ**. (5) Ký lại, bấm *Lật 1 bit chữ ký*: **đỏ**. (6) Ký lại, bấm *Đổi context*: **đỏ**. (7) Sinh khóa Mallory, ký bằng Mallory nhưng xác minh bằng pk Alice: **đỏ** | Trình duyệt |
| 5:00–6:00 | Đặng Thái Bình | **Kịch bản đầy đủ trên CLI:** hedged signing (2 chữ ký khác nhau, đều hợp lệ), tấn công sửa metadata context, tệp rỗng, tệp 20 MiB ký theo luồng | `python -m mldsa_app demo` |
| 6:00–7:30 | Trần Vũ Luân | **Đối chiếu chuẩn:** đi qua bảng R1–R14. Nhấn mạnh 165 vector NIST ACVP và test đối chiếu chéo với dilithium-py | `python -m pytest -q` (≈ 2 giây) + REPORT §3 |
| 7:30–8:30 | Trần Vũ Luân | **Hiệu năng và đánh đổi:** ML-DSA nhanh, nhưng chữ ký lớn hơn ECDSA khoảng 47 lần | `python -m mldsa_app bench -n 20` |
| 8:30–9:30 | Đinh Thế Duy | **AI usage:** prompt, cách kiểm chứng (introspect API, đọc PDF gốc, vector NIST), các lỗi AI đã sửa. **Hạn chế:** không có PKI, không có timestamp, web giữ khóa trong RAM | AI_USAGE.md, REPORT §6 |

## Câu hỏi có thể gặp

| Câu hỏi | Gợi ý trả lời |
|---|---|
| Vì sao ký cùng tài liệu hai lần lại ra hai chữ ký khác nhau? | Hedged signing (§3.4): rnd mới mỗi lần ký, ρ″ = H(K ‖ rnd ‖ μ). Chống fault attack. Verify vẫn chấp nhận cả hai. |
| Rejection sampling để làm gì? | **z** = **y** + c**s₁** có thể làm lộ **s₁** nếu hệ số quá lớn. Khi đó hủy và thử lại (trung bình 5.1 lần với ML-DSA-65, theo Table 1). |
| Tệp 1 GB thì ký thế nào? Có dùng HashML-DSA không? | Không dùng HashML-DSA. Ứng dụng tính μ theo luồng (Alg. 7 dòng 6 cho phép tính μ ở module khác) rồi gọi `sign_mu`. Kết quả vẫn là chữ ký pure chuẩn; test `test_streamed_signature_is_standard_signature` chứng minh điều này. |
| Context string chống được gì? | Tách miền: chữ ký trên "hợp đồng" không dùng lại được làm chữ ký "thanh toán". ctx nằm trong M′ nên sửa metadata cũng vô ích. |
| Tại sao khóa bí mật chỉ 32 byte? | Lưu seed ξ (§3.6.3, §4). Từ seed tái tạo được sk 4032 B. Seed phải được bảo vệ như khóa bí mật, nên file PEM được mã hóa bằng mật khẩu. |
| Nếu kẻ tấn công sửa trường `algorithm` thành ML-DSA-44 thì sao? | Bộ tham số lấy từ khóa công khai. Bundle ghi sai thì bị từ chối ngay (`test_bundle_tampered_metadata`). |
| Làm sao biết thư viện cài đúng chuẩn? | 75/75 keyGen và 90/90 sigVer khớp vector chính thức của NIST, đồng thời tương thích chéo với một implementation độc lập. |
| ML-DSA có an toàn tuyệt đối không? | Không. An toàn dựa trên giả định MLWE/SelfTargetMSIS. Ngoài ra còn rủi ro side-channel và quản lý khóa. Vì vậy nhiều hệ thống dùng hybrid trong giai đoạn chuyển tiếp. |
