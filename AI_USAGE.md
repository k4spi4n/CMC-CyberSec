# AI_USAGE.md: Nhật ký sử dụng AI

## 1. Công cụ

| Công cụ | Vai trò |
|---|---|
| Claude Code (CLI), model Claude Opus 5.5 / Sonnet 5.5 | Đọc đề, chọn thư viện, viết code, test và tài liệu, chạy lệnh trong terminal |
| `pyca/cryptography` 50.0.2 (OpenSSL 4.0.3) | Thư viện mật mã thực hiện ML-DSA. AI **không** tự viết toán lattice |
| dilithium-py 1.4.0 | Implementation Python độc lập, **chỉ dùng trong test** để đối chiếu chéo |

## 2. Prompt chính

| # | Prompt (nguyên văn hoặc tóm tắt) | AI đã làm |
|---|---|---|
| P1 | `@NIST_Vibe_Coding_Assignment_Links.pdf` | Trích text và link từ PDF, tóm tắt 8 chủ đề, 5 yêu cầu chung và rubric, hỏi lại nhóm làm chủ đề nào |
| P2 | `chủ đề số 8` | Toàn bộ quy trình ở mục 3 |

> **Nhóm bổ sung:** ghi thêm các prompt tiếp theo khi chỉnh sửa (ví dụ "đổi giao diện", "thêm ML-DSA-87 vào demo") theo cùng định dạng bảng trên.

## 3. Quy trình AI thực hiện và cách kiểm chứng

| Bước | AI đề xuất hoặc làm | Nhóm và AI kiểm chứng bằng cách |
|---|---|---|
| Chọn thư viện | So sánh `cryptography` (OpenSSL), `pqcrypto` (PQClean), `dilithium-py` (Python thuần, không constant-time) | Cài thử cả ba vào venv, **introspect API thật** (`inspect.signature`) thay vì tin trí nhớ của AI. Chọn `cryptography` vì là thư viện uy tín, có `sign_mu`/`MLDSAMuHasher`, khóa PEM mã hóa được. Đã gỡ `pqcrypto` vì không dùng |
| Tham số | Viết `params.py` theo Table 1/2 | Đối chiếu với bảng tham số của dilithium-py **và** bản PDF FIPS 204 tải trực tiếp từ NIST. Thêm test tự kiểm tra (β = τ·η, pk = 32 + 320k) |
| Số mục và số thuật toán | Trích dẫn §3.4, §3.6.x, §5.4, Alg. 1–8, 21, 26 | Tải `NIST.FIPS.204.pdf`, trích text và **đọc lại từng mục** trước khi đưa vào báo cáo |
| Ký tệp lớn | Đề xuất dùng external μ thay vì HashML-DSA | Tìm câu gốc trong chuẩn (Alg. 7 dòng 6, §5.4 *"pure ML-DSA is preferred"*). Test chứng minh chữ ký luồng được dilithium-py chấp nhận trên toàn bộ tệp |
| Test vector | Tải ACVP keyGen, sigVer, sigGen | Phát hiện **sigGen không dùng được**: các vector deterministic cần rnd = 0, nhưng API chỉ có hedged. Đã xóa sigGen thay vì viết test "giả pass". Có test `test_vector_coverage` để đảm bảo test không âm thầm chạy 0 vector |
| Web UI | Viết Flask + HTML | Dùng Playwright chạy headless (sinh khóa, ký, xác minh, sửa văn bản) và chụp ảnh `evidence/web_*.png`. Phát hiện và sửa 2 lỗi (mục 4) |

## 4. Lỗi hoặc điểm sai của AI đã được phát hiện và sửa

1. **Bố cục web để trống một cột** (grid `minmax(330px)` chia thành 3 cột). Phát hiện qua ảnh chụp, đã sửa thành `minmax(min(100%, 420px))`.
2. **Sửa template nhưng không thấy thay đổi:** Flask chạy không ở chế độ debug nên cache template. Phải khởi động lại server mới thấy.
3. **Số liệu không nhất quán:** trang web ghi pk ECDSA là "64 B", trong khi benchmark đo được 65 B (điểm không nén SEC1). Đã sửa web cho khớp số đo.
4. **Demo bước 8 ban đầu chỉ kiểm tra metadata** (so sánh trường `context_b64`). Như vậy chưa chứng minh được phần mật mã thực sự ràng buộc ctx. Đã bổ sung kịch bản "sửa cả metadata" và test `test_bundle_context_relabel_attack`.

## 5. Quyết định nhóm phải tự hiểu và giải thích được

AI viết code, nhưng các câu hỏi sau nhóm phải tự trả lời được khi demo:

- Tại sao **không** tự cài ML-DSA? Vì side-channel, constant-time, xóa bộ nhớ (§3.6.3) và rủi ro lỗi.
- Hedged khác deterministic thế nào, tại sao chọn hedged (§3.4)?
- Tại sao bộ tham số lấy từ khóa công khai, không lấy từ tệp chữ ký?
- Context string chống được tấn công gì?
- Chữ ký luồng (external μ) có phải chữ ký ML-DSA chuẩn không? Chứng minh bằng test nào?
- Vì sao chữ ký ML-DSA lớn hơn ECDSA khoảng 47 lần, và có đáng đánh đổi không?

## 6. Bài học về vibe coding với mật mã

- **Không tin trí nhớ của AI về API hay số mục của chuẩn.** Luôn introspect thư viện và mở tài liệu gốc.
- **Vector chính thức của NIST là bằng chứng mạnh nhất.** Một test tự viết theo kiểu "ký rồi verify được" không chứng minh được implementation đúng chuẩn.
- **Một test pass vì không chạy gì là nguy hiểm.** Luôn có test đếm số vector.
- AI có xu hướng thêm metadata "tiện lợi" vào bundle. Phải phân biệt rõ trường nào được ký, trường nào không.
