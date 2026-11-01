# fg_blocklist: nạp StevenBlack + domain TikTok vào FamilyGuard (không sửa dns_forwarder.cpp)

Script gửi lệnh `ADD_BLACKLIST` qua TCP/9000 (NDJSON) để đưa ~162.000 domain
(porn + gambling + fakenews của StevenBlack, cộng `extra_domains.txt`) vào blacklist đang chạy trong RAM của daemon.
Tra cứu vẫn do dns_forwarder lo (khớp domain và subdomain), script chỉ là bộ nạp.

## Chạy (trên VPS)
```bash
sudo mkdir -p /opt/fg_blocklist && sudo cp fg_blocklist.py extra_domains.txt allow.txt /opt/fg_blocklist/
cd /opt/fg_blocklist

# 0) xem trước, không động tới server (ghi domains.txt, in thống kê)
python3 fg_blocklist.py --dry-run

# 1) kiểm tra tên trường của ADD_BLACKLIST (mặc định script dùng "domain")
grep -n -A14 '"ADD_BLACKLIST"' /root/vps-deploy/dns_forwarder.cpp     # chỉ ĐỌC, không sửa

# 2) thử 200 domain trước (chạy thử xong có thể bỏ qua), rồi nạp thật
python3 fg_blocklist.py --max 200
python3 fg_blocklist.py
```
Nếu bước 2 báo "Server từ chối lệnh thăm dò", sửa `--field <tên>` theo handler, không cần đổi gì khác.
Nếu server bắt AUTH: `export FG_AUTH_JSON='{"action":"AUTH",...}'` (đúng gói JavaFX gửi; script không chứa mật khẩu).

## Sau khi nạp: kiểm tra
```bash
dig @127.0.0.1 tiktok.com A +time=3 +tries=1          # kỳ vọng REFUSED
dig @127.0.0.1 www.tiktok.com A +time=3 +tries=1      # subdomain cũng REFUSED
dig @127.0.0.1 google.com A +time=3 +tries=1          # kỳ vọng NOERROR (không bị chặn nhầm)
ps -o rss= -p $(systemctl show -p MainPID --value familyguard.service)   # RAM (KB) của dns_forwarder
```
Script cũng in `blacklist_count` trước/sau và mức tăng RSS nếu chạy trên VPS.

## Chạy nền: tự nạp lại khi restart (state chỉ nằm trong RAM)
```ini
# /etc/systemd/system/familyguard-blocklist.service  (unit mới, KHÔNG sửa unit cũ)
[Unit]
Description=FamilyGuard blocklist loader
After=familyguard.service
[Service]
WorkingDirectory=/opt/fg_blocklist
ExecStart=/usr/bin/python3 -u /opt/fg_blocklist/fg_blocklist.py --daemon
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
```
`sudo systemctl daemon-reload && sudo systemctl enable --now familyguard-blocklist`
Chế độ nền cứ 120 giây gọi `GET_STATUS`; nếu `blacklist_count` tụt dưới 90% danh sách
(daemon restart, hoặc app Parent đẩy `SYNC_RULES` ghi đè blacklist) thì nạp lại. Mỗi 24 giờ tải lại danh sách StevenBlack.

## Cần biết
- **Log có thể bị "ăn" nếu nạp quá lâu.** Mỗi kết nối TCP bị server đẩy `SYNC_LOGS` sau khoảng 60 giây và xóa log khỏi hàng đợi.
  Nạp trên VPS (127.0.0.1) để xong nhanh. Script sẽ cảnh báo nếu thấy server đẩy `SYNC_*` trên kết nối nạp.
  Bản thử với server giả bằng Python mất ~70 giây cho 162.000 domain; daemon C++ nhiều khả năng nhanh hơn nhưng chưa đo, hãy chạy lần đầu lúc ít log.
- **App Parent đẩy `SYNC_RULES` có thể ghi đè blacklist.** Chế độ nền xử lý việc này bằng cách nạp lại, nhưng sẽ có khoảng trống tối đa ~120 giây. Cần thử thực tế.
- **Chỉ thêm, không bớt.** Domain lỡ nạp chỉ mất sau khi restart familyguard.service. `allow.txt` chỉ có tác dụng ở lần nạp sau.
- **`--compress`** bỏ ~67.000 subdomain đã có domain cha (còn ~95.000 mục), giảm RAM và thời gian nạp, nhưng chỉ dùng nếu server thật sự khớp subdomain theo suffix.
  Kiểm tra bằng `dig @127.0.0.1 www.<domain gốc đã chặn>` trước khi bật.
- Domain có dấu gạch dưới `_` (6 mục trong StevenBlack) bị bỏ vì `is_valid_domain()` của server từ chối.
- **TikTok:** `extra_domains.txt` mới có 4 domain chắc chắn và vài dòng đoán. Mở app TikTok qua WireGuard, đọc DNS_QUERY trong journal để bổ sung. Chặn DNS không ngăn được app dùng IP cache, DoH hoặc Private DNS trên điện thoại.
