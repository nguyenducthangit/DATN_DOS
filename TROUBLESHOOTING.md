# Hướng dẫn Khắc phục Sự cố

## Vấn đề 1: Interface 'en0' not found

### Nguyên nhân:

- Hệ thống không tìm thấy interface mạng 'en0'
- Interface mạng khác nhau trên các hệ điều hành khác nhau

### Giải pháp:

1. **Kiểm tra interface có sẵn:**

   ```bash
   python3 check_interface.py
   ```

2. **Chạy với quyền root (nếu cần):**

   ```bash
   sudo python3 app/app.py
   ```

3. **Chỉ định interface thủ công:**

   ```bash
   # Trên Linux
   sudo python3 app/app.py --interface eth0

   # Trên macOS
   sudo python3 app/app.py --interface en0

   # Trên Windows
   python3 app/app.py --interface Ethernet
   ```

## Vấn đề 2: Không phát hiện tấn công

### Nguyên nhân:

- Ngưỡng phát hiện quá cao
- Model không hoạt động
- Không có traffic thực sự

### Giải pháp:

1. **Bật debug mode (đã bật sẵn):**

   - Debug mode sẽ giả lập tấn công khi rate > 200 packets/s

2. **Test với script tấn công:**

   ```bash
   # Terminal 1: Chạy hệ thống
   sudo python3 app/app.py

   # Terminal 2: Chạy tấn công test
   python3 test_attack.py
   ```

3. **Kiểm tra log:**

   ```bash
   tail -f ddos_detector.log
   ```

4. **Điều chỉnh ngưỡng trong config.py:**
   ```python
   # Giảm ngưỡng để dễ phát hiện
   self.confidence_threshold = 0.3  # Giảm từ 0.5
   self.rate_threshold = 20         # Giảm từ 50
   ```

## Vấn đề 3: Permission denied

### Giải pháp:

```bash
# Chạy với quyền root
sudo python3 app/app.py

# Hoặc cấp quyền cho user
sudo setcap cap_net_raw=eip $(which python3)
```

## Vấn đề 4: Model không load được

### Giải pháp:

1. **Kiểm tra file model:**

   ```bash
   ls -la models/
   ```

2. **Chạy với debug mode (đã bật):**

   - Hệ thống sẽ hoạt động ngay cả khi không có model
   - Sẽ giả lập tấn công dựa trên rate

3. **Tạo model mới (nếu cần):**
   ```bash
   # Train model mới
   python3 train_model.py
   ```

## Các bước test cơ bản:

### Bước 1: Kiểm tra hệ thống

```bash
python3 check_interface.py
```

### Bước 2: Chạy hệ thống

```bash
sudo python3 app/app.py
```

### Bước 3: Test tấn công

```bash
python3 test_attack.py
```

### Bước 4: Kiểm tra dashboard

- Mở browser: http://localhost:5000
- Vào dashboard: http://localhost:5000/dashboard/

## Các lệnh hữu ích:

### Kiểm tra traffic mạng:

```bash
# Xem traffic real-time
sudo tcpdump -i any -c 10

# Xem interface
ip addr show

# Xem routing
ip route show
```

### Test kết nối:

```bash
# Test ping
ping 127.0.0.1

# Test port
nc -zv 127.0.0.1 80
```

## Debug tips:

1. **Xem log chi tiết:**

   ```bash
   tail -f ddos_detector.log | grep -E "(ERROR|WARNING|INFO)"
   ```

2. **Kiểm tra process:**

   ```bash
   ps aux | grep python
   ```

3. **Kiểm tra port:**
   ```bash
   netstat -tlnp | grep 5000
   ```

## Cấu hình nâng cao:

### Thay đổi interface trong config.py:

```python
class Config:
    def __init__(self):
        # Chỉ định interface thủ công
        self.interface = "eth0"  # Thay đổi theo hệ thống
```

### Thay đổi ngưỡng phát hiện:

```python
class Config:
    def __init__(self):
        # Ngưỡng thấp hơn = dễ phát hiện hơn
        self.confidence_threshold = 0.3
        self.rate_threshold = 20
        self.block_rate_threshold = 200
```

## Liên hệ hỗ trợ:

Nếu vẫn gặp vấn đề, hãy cung cấp:

1. Output của `python3 check_interface.py`
2. Log từ `ddos_detector.log`
3. Hệ điều hành và phiên bản Python
4. Mô tả chi tiết lỗi
