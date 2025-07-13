# Hướng dẫn Test Hệ thống DDoS Detection

## Các vấn đề đã được sửa

### ✅ **Vấn đề 1: Không hiển thị tên nhãn tấn công**

- **Nguyên nhân:** Logic xử lý `attack_type` bị lỗi khi chuyển đổi giữa số và chuỗi
- **Đã sửa:** Cải thiện logic xử lý để hỗ trợ cả số và chuỗi

### ✅ **Vấn đề 2: Màn hình không hiển thị gì**

- **Nguyên nhân:** Logic hiển thị status không đúng
- **Đã sửa:** Cải thiện logic hiển thị status và alert

### ✅ **Vấn đề 3: Cảnh báo tấn công không hiển thị**

- **Nguyên nhân:** Debug mode chưa hoạt động đúng
- **Đã sửa:** Bật debug mode và cải thiện logic phát hiện

## Các bước test

### Bước 1: Kiểm tra hệ thống

```bash
# Kiểm tra interface
python3 check_interface.py

# Test detector
python3 test_detector.py
```

### Bước 2: Chạy hệ thống

```bash
# Chạy với quyền root
sudo python3 app/app.py
```

### Bước 3: Test toàn bộ hệ thống

```bash
# Test API và chức năng
python3 test_full_system.py
```

### Bước 4: Test tấn công

```bash
# Terminal 1: Chạy hệ thống (nếu chưa chạy)
sudo python3 app/app.py

# Terminal 2: Test tấn công
python3 test_attack.py
```

### Bước 5: Kiểm tra dashboard

- Mở browser: http://localhost:5000
- Vào dashboard: http://localhost:5000/dashboard/

## Các script test có sẵn

### 1. `check_interface.py`

- Kiểm tra interface mạng có sẵn
- Đề xuất interface phù hợp
- Kiểm tra quyền

### 2. `test_detector.py`

- Test detector với dữ liệu mẫu
- Kiểm tra logic xử lý tấn công
- Test phân loại severity

### 3. `test_full_system.py`

- Test toàn bộ hệ thống
- Kiểm tra API endpoints
- Test attack simulation

### 4. `test_attack.py`

- Script tấn công test
- SYN Flood, UDP Flood, ICMP Flood
- Tùy chỉnh target và duration

## Cách debug

### 1. Xem log real-time

```bash
tail -f ddos_detector.log
```

### 2. Kiểm tra status API

```bash
curl http://localhost:5000/api/status
```

### 3. Kiểm tra metrics

```bash
curl http://localhost:5000/api/metrics
```

### 4. Kiểm tra config

```bash
curl http://localhost:5000/api/config
```

## Các trường hợp test

### Test 1: Normal Traffic

- Hệ thống phải hiển thị "NORMAL"
- Không có alert nào

### Test 2: Low Rate Attack

- Rate < 200 packets/s
- Hệ thống có thể không phát hiện (tùy ngưỡng)

### Test 3: High Rate Attack

- Rate > 200 packets/s
- Hệ thống phải phát hiện và hiển thị alert
- Status phải thay đổi thành "UNDER ATTACK"

### Test 4: Multiple Attacks

- Nhiều IP tấn công cùng lúc
- Hệ thống phải hiển thị tất cả
- Phân loại theo severity

## Cấu hình test

### Debug Mode (đã bật)

```python
# Trong config.py
self.debug = True
```

### Ngưỡng thấp để dễ test

```python
# Trong config.py
self.confidence_threshold = 0.5
self.rate_threshold = 50
self.block_rate_threshold = 500
```

## Kết quả mong đợi

### Khi có tấn công:

1. **Status:** Thay đổi từ "NORMAL" thành "UNDER ATTACK"
2. **Alert:** Hiển thị thông tin tấn công với:
   - Thời gian
   - Loại tấn công
   - IP nguồn
   - Rate
   - Severity
3. **Dashboard:** Cập nhật real-time
4. **Log:** Ghi log chi tiết

### Khi không có tấn công:

1. **Status:** "NORMAL"
2. **Alert:** Không có hoặc alert cũ
3. **Dashboard:** Hiển thị traffic bình thường

## Troubleshooting

### Nếu không phát hiện tấn công:

1. Kiểm tra log: `tail -f ddos_detector.log`
2. Giảm ngưỡng trong config.py
3. Đảm bảo debug mode đã bật
4. Kiểm tra interface có đúng không

### Nếu dashboard không hiển thị:

1. Kiểm tra API: `curl http://localhost:5000/api/status`
2. Kiểm tra browser console
3. Kiểm tra log lỗi

### Nếu không có alert:

1. Kiểm tra detector logic
2. Kiểm tra queue processing
3. Kiểm tra alert storage

## Liên hệ hỗ trợ

Nếu vẫn gặp vấn đề, hãy cung cấp:

1. Output của các script test
2. Log từ `ddos_detector.log`
3. Screenshot dashboard
4. Mô tả chi tiết vấn đề
