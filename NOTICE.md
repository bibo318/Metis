# Thông báo Nguồn Gốc / Attribution Notice

## Metis – Nền tảng Phân tích Tình báo Mối đe dọa

**Metis** là phiên bản fork và bản địa hóa tiếng Việt của **MANTIS**.

### Dự án gốc / Original Project

| Thông tin | Chi tiết |
|-----------|---------|
| **Tên dự án** | MANTIS (Multi-source Analysis and Threat Intelligence Search) |
| **Tác giả** | fareedfauzi |
| **Repo gốc** | https://github.com/fareedfauzi/MANTIS |
| **Giấy phép** | Xem file LICENSE gốc |

### Những thay đổi trong Metis / Changes in Metis

#### Bản địa hóa và thương hiệu
- Đổi tên thương hiệu từ MANTIS → Metis
- Thêm ngôn ngữ tiếng Việt toàn bộ (Vietnamese full localization)
- Bản địa hóa giao diện người dùng sang tiếng Việt
- Thông báo lỗi và cảnh báo bằng tiếng Việt

#### Nâng cấp AI (LLM Gateway)
- Thêm class `LLMGateway` trong `backend/ai_service.py` để kiểm soát tập trung tất cả lời gọi AI
- Hỗ trợ ngân sách AI hàng ngày (`daily_budget_usd`) — tự động từ chối khi vượt ngưỡng
- Hỗ trợ mô hình phân tích sâu riêng biệt (`model_deep`) cho báo cáo chuyên sâu
- Audit log chi tiết với chi phí (cost_usd), token (input/output), và tier cho mỗi lần gọi AI
- Hỗ trợ CLI adapter (`claude_code`, `antigravity`, `copilot`, `opencode`) không cần API key

#### Pydantic Structured Output
- Thêm file mới `backend/ai_schemas.py` với schema Pydantic cho `TodaysIntelBrief` và `TodaysIntelReport`
- Validation tự động cho AI response — không còn crash khi JSON bị truncate
- Tương thích cả Pydantic v1 và v2
- Giá trị mặc định cho tất cả field — partial output vẫn hoạt động

#### EPSS Priority Labels P1–P5
- Thêm nhãn ưu tiên màu cho CVE trong "Hàng đợi ưu tiên lỗ hổng" (Today's Intelligence)
- P1 = KEV + EPSS ≥ 0.7 (đỏ), P2 = KEV (cam), P3 = EPSS ≥ 0.5 (vàng), P4 = EPSS ≥ 0.1 (xanh dương), P5 = còn lại (xám)
- Badge màu render trong frontend

#### Cài đặt AI mở rộng
- 2 field mới trong Settings → Metis AI: "Mô hình phân tích sâu" và "Ngân sách AI hàng ngày"
- DB migration an toàn với `ALTER TABLE` + `try/except sqlite3.OperationalError`

### Tuân thủ Giấy phép / License Compliance

Dự án này được phân phối theo cùng giấy phép với dự án gốc MANTIS.
Mọi credit và attribution đều được giữ nguyên theo yêu cầu của giấy phép.

This project is a fork of MANTIS by fareedfauzi. All credits and copyrights
belong to the original authors. This fork adds Vietnamese localization and
rebranding to "Metis".

**Original Repository:** https://github.com/fareedfauzi/MANTIS  
**Fork Repository:** https://github.com/bibo318/Metis
