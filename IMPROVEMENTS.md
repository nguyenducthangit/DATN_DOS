# Cải tiến Hệ thống Phát hiện DDoS

## Vấn đề đã được giải quyết

### 1. **Thông báo tấn công khi chưa có tấn công thực sự (False Positive)**

**Nguyên nhân:**

- Hệ thống coi bất kỳ traffic nào không phải `BenignTraffic` là tấn công
- Thiếu ngưỡng tin cậy (confidence threshold)
- Model có thể dự đoán sai do đặc trưng không chính xác

**Giải pháp:**

- Thêm ngưỡng tin cậy (confidence threshold = 0.7)
- Thêm ngưỡng rate tối thiểu (rate threshold = 100 packets/s)
- Chỉ coi là tấn công khi:
  - `attack_type != 'BenignTraffic'`
  - `confidence > 0.7`
  - `rate > 100 packets/s`

### 2. **Hiển thị nhiều loại tấn công không phân loại**

**Nguyên nhân:**

- Hệ thống hiển thị tất cả các alert mà không phân loại
- Không có cơ chế ưu tiên loại tấn công quan trọng
- Thiếu thông tin về mức độ nghiêm trọng

**Giải pháp:**

- Phân loại tấn công theo mức độ nghiêm trọng (1-5):

  - **Mức 5 (Cao nhất):** DDoS-SYN_Flood, DDoS-UDP_Flood, Mirai attacks
  - **Mức 4 (Cao):** DDoS-RSTFINFlood, DDoS-ICMP_Flood
  - **Mức 3 (Trung bình):** Web attacks (XSS, SQL Injection)
  - **Mức 2 (Thấp):** Reconnaissance attacks
  - **Mức 1 (Thấp nhất):** Các tấn công khác

- Thêm cooldown period (30 giây) để tránh spam alert từ cùng IP
- Chỉ hiển thị tấn công nghiêm trọng hơn nếu cùng IP

## Các cải tiến khác

### 3. **Cải thiện Dashboard**

- Hiển thị alert theo màu sắc và icon dựa trên mức độ nghiêm trọng
- Thêm thống kê phân loại tấn công theo loại
- Cải thiện CSS cho alert và stat items

### 4. **Cấu hình linh hoạt**

- Tạo file `config.py` với các tham số có thể điều chỉnh:
  - `confidence_threshold`: Ngưỡng tin cậy (0.7)
  - `rate_threshold`: Ngưỡng rate tối thiểu (100)
  - `block_rate_threshold`: Ngưỡng rate để block IP (1000)
  - `block_severity_threshold`: Ngưỡng nghiêm trọng để block IP (3)
  - `alert_cooldown_seconds`: Thời gian cooldown (30s)
  - `max_alerts`: Số lượng alert tối đa (100)

### 5. **Logic Block IP thông minh hơn**

- Chỉ block IP khi:
  - Rate > 1000 packets/s
  - Severity >= 3
  - Không phải IP local

## Cách sử dụng

### Điều chỉnh ngưỡng phát hiện:

```python
# Trong config.py
self.confidence_threshold = 0.8  # Tăng ngưỡng tin cậy
self.rate_threshold = 200        # Tăng ngưỡng rate
```

### Xem thống kê tấn công:

- Dashboard sẽ hiển thị:
  - Tổng số tấn công
  - Số IP bị block
  - Phân loại tấn công theo loại
  - Danh sách IP bị block

### Debug mode:

```python
# Trong config.py
self.debug = True
```

## Kết quả mong đợi

1. **Giảm False Positive:** Hệ thống sẽ ít báo tấn công giả hơn
2. **Phân loại rõ ràng:** Alert được hiển thị theo mức độ nghiêm trọng
3. **Hiệu suất tốt hơn:** Chỉ block IP thực sự nguy hiểm
4. **Dễ điều chỉnh:** Có thể thay đổi ngưỡng dễ dàng qua config
