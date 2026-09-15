# 🛡️ SHIELD-WEBAPP.LAB — Hướng dẫn Thực hành (Dành cho Học viên)

> **Module 2 · Labs Khai thác Web · LAB 2**  
> Môi trường thực hành khai thác 6 lỗ hổng Web cơ bản  
> ⚠️ **LƯU Ý: CHỈ DÀNH CHO MỤC ĐÍCH HỌC TẬP & THỰC HÀNH**

---

## 📋 Mục lục
1. [Yêu cầu & Cài đặt](#1-yêu-cầu--cài-đặt)
2. [Khởi động Lab](#2-khởi-động-lab)
3. [Nhiệm vụ của bạn](#3-nhiệm-vụ-của-bạn)
4. [Thông tin Đăng nhập](#4-thông-tin-đăng-nhập)
5. [Cấu trúc thư mục Log](#5-cấu-trúc-thư-mục-log)
6. [Quy định nộp bài](#6-quy-định-nộp-bài)

---

## 1. Yêu cầu & Cài đặt

### Yêu cầu hệ thống
- **Python:** Phiên bản 3.10 trở lên
- **Công cụ chặn bắt request:** Burp Suite Community (khuyến nghị cho một số lab)
- **Trình duyệt:** Chrome hoặc Firefox (có cấu hình proxy trỏ về Burp Suite)

### Cài đặt thư viện (Dependencies)
Mở Terminal / PowerShell tại thư mục chứa source code và chạy lệnh:
```powershell
pip install -r requirements.txt
```

---

## 2. Khởi động Lab

Để khởi động server, bạn chạy file `app.py`:
```powershell
python app.py
```

Sau khi thấy dòng chữ `* Running on http://127.0.0.1:5000`, hãy mở trình duyệt và truy cập vào **http://127.0.0.1:5000**.
*(Lưu ý: Bạn không được tắt cửa sổ Terminal này trong suốt quá trình làm lab).*

---

## 3. Nhiệm vụ của bạn

Ứng dụng web này đang chứa **6 lỗ hổng bảo mật** tương ứng với chuẩn OWASP Top 10. Hãy vào vai một pentester được thuê để tìm và khai thác các lỗ hổng này. Dưới đây là danh sách các lỗi bạn cần tìm:

- **L1:** SQL Injection (Union-based)
- **L2:** SQL Injection (Time-based blind)
- **L3:** Stored Cross-Site Scripting (XSS)
- **L4:** Insecure Direct Object Reference (IDOR)
- **L5:** Server-Side Request Forgery (SSRF)
- **L6:** Auth Bypass / Privilege Escalation

*Gợi ý: Trên giao diện web đã có sẵn các nhãn đánh dấu khu vực (ví dụ `[L1]`, `[L2]`) để khoanh vùng mục tiêu cho bạn. Tuy nhiên, bạn phải tự tìm ra payload và cách khai thác.*

---

## 4. Thông tin Đăng nhập

Tài khoản học viên được cấp sẵn để truy cập vào hệ thống:
- **Username:** `pentester`
- **Password:** `T3st!ng2024`

---

## 5. Cấu trúc thư mục Log

Là một chuyên gia bảo mật, ngoài việc tấn công, bạn cần biết hệ thống lưu vết (log) ở đâu để phân tích và phòng thủ.
Tất cả các hành vi truy cập và tấn công sẽ được ghi nhận tại file:
**`logs/access.log`**

Hoặc bạn có thể xem trực tiếp trên web thông qua URL (hãy tự tìm đường dẫn trên giao diện).

---

## 6. Quy định nộp bài

Với mỗi lỗ hổng (từ L1 đến L6), bạn cần nộp một báo cáo bao gồm 4 phần:
1. **Payload:** Chuỗi/Kịch bản tấn công bạn đã sử dụng.
2. **Bằng chứng (Screenshot):** Ảnh chụp màn hình kết quả khai thác thành công.
3. **Log hệ thống:** Copy lại dòng log tương ứng trong file `access.log` ghi nhận vết tấn công của bạn.
4. **Cách vá (Remediation):** Chỉ ra chính xác đoạn code bị lỗi nằm ở file nào, và đề xuất cách viết lại code (hoặc cấu hình) để vá hoàn toàn lỗ hổng đó.

**Thang điểm:** 10 điểm / 1 lỗ hổng (Tổng cộng 60 điểm).

---
*Chúc bạn thực hành tốt! Hãy nhớ reset lại database (bằng cách xóa file `lab.db`) nếu bạn lỡ làm hỏng dữ liệu trong lúc thử nghiệm.*
