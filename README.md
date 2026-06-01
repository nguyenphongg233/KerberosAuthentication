# Mô phỏng giao thức xác thực Kerberos bằng Python

Dự án này mô phỏng giao thức Kerberos theo hướng học tập môn Nhập môn An toàn thông tin. Mục tiêu chính là làm rõ luồng hoạt động của Kerberos: cách Client xin TGT, dùng TGT để xin Service Ticket, rồi dùng Service Ticket để xác thực với dịch vụ.

Phiên bản hiện tại hỗ trợ hai cách chạy:

1. **Chạy local trong một tiến trình** bằng `main.py`.
2. **Chạy phân tán qua TCP/JSON** bằng `distributed.py`, có thể đặt KDC, Service Server và Client trên ba máy khác nhau trong cùng mạng lab.

> Lưu ý: Đây là mô phỏng giáo dục. Không dùng dự án này cho hệ thống thật.

## 1. Điểm mới trong phiên bản hiện tại

- Hoàn thiện đủ 3 pha Kerberos:
  - AS Exchange: xin TGT.
  - TGS Exchange: xin Service Ticket.
  - Application Exchange: xác thực với Service Server và nhận AP-REP.
- AS không nhận mật khẩu qua mạng. Nếu nhập sai mật khẩu, Client không giải mã được phần dành cho Client trong AS-REP.
- TGS và Service Server có replay cache để chặn Authenticator bị dùng lại.
- Crypto toy XOR đã được thay bằng **AES-GCM** qua thư viện `cryptography`.
- Có chế độ chạy phân tán:
  - Máy 1: KDC, gồm AS + TGS.
  - Máy 2: Service Server.
  - Máy 3: Client.

## 2. Cài đặt

Yêu cầu Python 3.10+.

```bash
pip install -r requirements.txt
```

Thư viện chính:

- `cryptography`: dùng AES-GCM để mã hóa và kiểm tra toàn vẹn bản mã.

Trong mô phỏng này, các khóa dạng chuỗi như `TGS_SECRET_KEY`, `MAIL_SERVICE_SECRET` hoặc session key sẽ được dẫn xuất thành khóa AES-256 bằng SHA-256. Cách này đơn giản hóa để phục vụ học tập; Kerberos thật có bộ quy tắc enctype và key derivation riêng.

## 3. Cấu trúc project

```text
KerberosAuthentication/
+-- KDC_database/
|   +-- database_entity.py       # Principal và KDC database
|   +-- database_engine.py       # Khởi tạo, tra cứu principal/key
|   +-- database_crypto.py       # Hash mật khẩu và khóa dài hạn
+-- as_server/
|   +-- as_entity.py             # Authentication Server entity
|   +-- as_engine.py             # Xử lý AS-REQ, cấp TGT
|   +-- as_crypto.py             # Wrapper AES-GCM của AS
+-- tgs_server/
|   +-- tgs_entity.py            # Ticket Granting Server entity
|   +-- tgs_engine.py            # Xử lý TGS-REQ, cấp Service Ticket
|   +-- tgs_crypto.py            # Wrapper AES-GCM của TGS
+-- client/
|   +-- client_entity.py         # Trạng thái Client: TGT, ST, session keys
|   +-- client_engine.py         # Tạo/xử lý AS, TGS, AP messages
|   +-- client_crypto.py         # Wrapper AES-GCM của Client
+-- service_server/
|   +-- service_entity.py        # Service Server entity
|   +-- service_engine.py        # Xử lý AP-REQ, AP-REP, replay cache
|   +-- service_crypto.py        # Wrapper AES-GCM của Service
+-- models.py                    # Ticket, Authenticator, AS/TGS/AP messages
+-- shared_crypto.py             # AES-GCM dùng chung
+-- wire.py                      # Serialize message và TCP/JSON helpers
+-- distributed.py               # Chạy KDC/Service/Client qua mạng
+-- main.py                      # Kịch bản chạy local
+-- requirements.txt             # Thư viện cần cài
```

## 4. Luồng hoạt động Kerberos trong dự án

### 4.1. Pha 1: AS Exchange

Mục tiêu: Client lấy TGT và khóa phiên `K_c,tgs`.

```text
Client -> AS:
  AS-REQ = ID_c, ID_tgs, TS1, Lifetime1, Nonce1, C_Address

AS:
  1. Kiểm tra principal Alice có tồn tại trong KDC database.
  2. Lấy khóa dài hạn Kc của Alice từ database.
  3. Sinh khóa phiên K_c,tgs.
  4. Tạo TGT:
     TGT = E_Ktgs[ID_c, C_Address, ID_tgs, TS2, Lifetime2, K_c,tgs]
  5. Tạo phần dành cho Client:
     Client_Portion = E_Kc[K_c,tgs, ID_tgs, TS2, Lifetime2, Nonce1]

AS -> Client:
  AS-REP = TGT, Client_Portion

Client:
  1. Tự băm mật khẩu người dùng nhập để sinh Kc.
  2. Dùng Kc giải mã Client_Portion.
  3. Kiểm tra Nonce1.
  4. Lưu TGT và K_c,tgs.
```

Điểm quan trọng: mật khẩu không được gửi qua mạng. Sai mật khẩu nghĩa là Client sinh sai Kc và không giải mã được AS-REP.

### 4.2. Pha 2: TGS Exchange

Mục tiêu: Client dùng TGT để xin Service Ticket cho `mail-service`.

```text
Client:
  Authenticator_c = E_Kc,tgs[ID_c, C_Address, TS3]

Client -> TGS:
  TGS-REQ = ID_v, TGT, Authenticator_c, Nonce2, Lifetime

TGS:
  1. Giải mã TGT bằng K_tgs.
  2. Kiểm tra TGT còn hạn và đúng loại TGT.
  3. Lấy K_c,tgs từ TGT.
  4. Giải mã Authenticator_c bằng K_c,tgs.
  5. Kiểm tra ID_c, C_Address, timestamp và replay cache.
  6. Lấy khóa dịch vụ K_v của mail-service.
  7. Sinh K_c,s.
  8. Tạo Service Ticket:
     ST = E_Kv[ID_c, C_Address, ID_v, TS4, Lifetime4, K_c,s]
  9. Tạo phần dành cho Client:
     Client_Portion = E_Kc,tgs[K_c,s, ID_v, TS4, Lifetime4, Nonce2]

TGS -> Client:
  TGS-REP = ST, Client_Portion

Client:
  1. Giải mã Client_Portion bằng K_c,tgs.
  2. Kiểm tra Nonce2.
  3. Lưu ST và K_c,s.
```

### 4.3. Pha 3: Application Exchange

Mục tiêu: Client chứng minh có Service Ticket hợp lệ; Service chứng minh nó là service thật.

```text
Client:
  Authenticator_c_v = E_Kc,s[ID_c, C_Address, TS5]

Client -> Service:
  AP-REQ = ST, Authenticator_c_v

Service:
  1. Giải mã ST bằng K_v.
  2. Lấy K_c,s từ ST.
  3. Giải mã Authenticator_c_v bằng K_c,s.
  4. Kiểm tra ID_c, C_Address, timestamp và replay cache.
  5. Tạo AP-REP:
     AP-REP = E_Kc,s[TS5 + 1, server_timestamp]

Service -> Client:
  AP-REP

Client:
  1. Giải mã AP-REP bằng K_c,s.
  2. Kiểm tra TS5 + 1.
  3. Nếu đúng, mutual authentication thành công.
```

## 5. Chạy local trên một máy

```bash
python main.py
```

Kết quả mong đợi:

- Pha 1 thành công: Client nhận TGT và `K_c,tgs`.
- Pha 2 thành công: Client nhận Service Ticket và `K_c,s`.
- Pha 3 thành công: Client và Service xác thực hai chiều.
- Replay test bị chặn.
- Wrong password test thất bại ở phía Client khi giải mã AS-REP.

## 6. Chạy phân tán trên ba máy

Giả sử ba máy nằm trong cùng mạng LAN:

- Máy KDC: `192.168.1.10`
- Máy Service: `192.168.1.20`
- Máy Client: `192.168.1.100`

Bạn cần mở firewall cho các port lab:

- KDC: TCP `8800`
- Service: TCP `8801`

### 6.1. Máy 1: chạy KDC

KDC trong demo gồm cả AS và TGS.

```bash
python distributed.py kdc --host 0.0.0.0 --port 8800
```

### 6.2. Máy 2: chạy Service Server

```bash
python distributed.py service --host 0.0.0.0 --port 8801
```

### 6.3. Máy 3: chạy Client

```bash
python distributed.py client ^
  --kdc-host 192.168.1.10 --kdc-port 8800 ^
  --service-host 192.168.1.20 --service-port 8801 ^
  --client-id alice ^
  --password alice_password_123 ^
  --client-address 192.168.1.100
```

Trên PowerShell có thể viết một dòng:

```powershell
python distributed.py client --kdc-host 192.168.1.10 --kdc-port 8800 --service-host 192.168.1.20 --service-port 8801 --client-id alice --password alice_password_123 --client-address 192.168.1.100
```

Nếu chạy tất cả trên cùng một máy để thử nhanh:

```bash
python distributed.py kdc --host 127.0.0.1 --port 8800
python distributed.py service --host 127.0.0.1 --port 8801
python distributed.py client --kdc-host 127.0.0.1 --service-host 127.0.0.1
```

Trong chế độ phân tán:

- Client gửi `AS-REQ` và `TGS-REQ` qua TCP/JSON đến KDC.
- Client gửi `AP-REQ` qua TCP/JSON đến Service Server.
- Ticket, Authenticator và encrypted payload được serialize thành JSON để truyền qua mạng.
- Phần mã hóa bên trong vẫn dùng AES-GCM.

## 7. Nên tập trung nghiên cứu phần nào?

Hướng tốt nhất cho bài này là: **Kerberos dưới góc nhìn tấn công và phòng thủ, nhưng mô phỏng an toàn trong lab**.

Không nên chỉ dừng ở “cài đặt lại 6 bước Kerberos”. Nên chứng minh giao thức này chống được gì, còn yếu ở đâu, và vì sao quản trị hệ thống Kerberos/AD phải cẩn thận.

### 7.1. Ưu tiên 1: Replay Attack và Replay Cache

Đây là phần nên tập trung đầu tiên vì sát với code hiện tại và dễ demo.

Ý chính:

- Timestamp giúp giới hạn thời gian hợp lệ của Authenticator.
- Nhưng nếu chỉ kiểm tra timestamp thì chưa đủ.
- Một gói AP-REQ bị bắt lại và gửi lại trong vòng 5 phút vẫn có timestamp hợp lệ.
- Replay cache giải quyết việc này bằng cách nhớ Authenticator đã dùng.

Demo nên có:

1. Gửi AP-REQ lần đầu: thành công.
2. Gửi lại đúng AP-REQ đó: bị Service Server từ chối.
3. Giải thích: timestamp còn hợp lệ nhưng Authenticator đã nằm trong replay cache.

### 7.2. Ưu tiên 2: Pass-the-Ticket mô phỏng

Đây là phần làm project có màu sắc an toàn thông tin rõ hơn.

Không cần dump RAM thật. Chỉ cần mô phỏng:

1. Alice đăng nhập thành công.
2. Trong object Client có TGT, ST, `K_c,tgs`, `K_c,s`.
3. Attacker copy ticket/session key từ object đó.
4. Attacker thử truy cập service.
5. Nếu ticket còn hạn và attacker có đủ session key, request có thể thành công.
6. Nếu thiếu session key hoặc replay cache phát hiện Authenticator cũ, request thất bại.

Kết luận cần nêu:

- Kerberos không gửi mật khẩu qua mạng.
- Nhưng ticket và session key trong RAM là tài sản rất nhạy cảm.
- Bảo vệ RAM, credential cache và tiến trình xác thực là yêu cầu quan trọng.

### 7.3. Ưu tiên 3: Tampering và Integrity

AES-GCM đã cung cấp kiểm tra toàn vẹn bản mã. Đây là điểm tốt để giải thích:

- Mã hóa không chỉ cần bí mật dữ liệu.
- Bên nhận còn phải phát hiện dữ liệu bị sửa.
- Nếu sửa một ký tự trong ciphertext, AES-GCM sẽ không giải mã được.

Demo nên có:

1. Tạo ST bình thường.
2. Sửa một ký tự trong `encrypted_data`.
3. Service thử giải mã.
4. Kết quả: thất bại vì authentication tag của AES-GCM không hợp lệ.

### 7.4. Ưu tiên 4: Vé hết hạn và lệch thời gian

Kerberos phụ thuộc mạnh vào thời gian.

Demo nên có:

- TGT hết hạn -> TGS từ chối.
- ST hết hạn -> Service từ chối.
- Authenticator lệch quá 5 phút -> bị từ chối.

Phần này nối trực tiếp với kiến thức về replay attack và rủi ro đồng bộ thời gian/NTP.

### 7.5. Không nên tập trung chính vào tự viết thuật toán mã hóa

Không nên tự viết AES/DES/RC4. Việc tự cài crypto dễ sai và không phải trọng tâm Kerberos.

Nên trình bày:

- Kerberos thật dùng các enctype như AES, RC4 cũ, DES cũ.
- Dự án dùng `cryptography` để có AES-GCM chuẩn thư viện.
- Trọng tâm của bài là thiết kế xác thực, phân phối khóa, ticket, replay defense và rủi ro quản trị.

### 7.6. Không nên đi sâu vào quét RAM/bắt gói thật

Có thể nhắc về mặt lý thuyết, nhưng không nên biến bài thành hướng dẫn thao tác trên hệ thống thật.

Cách an toàn hơn:

- “Quét RAM” -> mô phỏng bằng việc attacker đọc object/ticket cache trong chương trình.
- “Bắt gói tin” -> mô phỏng bằng log JSON của AS-REQ/TGS-REQ/AP-REQ.
- Nếu muốn bắt gói thật, chỉ chạy socket localhost hoặc mạng lab do nhóm kiểm soát.

## 8. Roadmap đề xuất

Nên làm theo thứ tự:

1. Giữ ổn định 3 pha hiện tại và chế độ chạy phân tán.
2. Thêm test replay cho cả TGS-REQ, không chỉ AP-REQ.
3. Thêm test tampering với AES-GCM.
4. Thêm test expired TGT/ST/Auth timestamp.
5. Thêm Pass-the-Ticket mô phỏng.
6. Thêm Kerberoasting mô phỏng với dictionary nhỏ và service password yếu.
7. Nếu còn thời gian, ghi packet trace JSON hoặc bắt traffic localhost trong lab.

## 9. Giới hạn và cảnh báo đạo đức

Dự án chỉ phục vụ học tập trong môi trường lab. Các nội dung như đọc RAM, bắt gói tin, Pass-the-Ticket, Kerberoasting chỉ nên được mô phỏng trên dữ liệu giả lập do nhóm tự tạo.

Không sử dụng dự án này để thử nghiệm trên máy, tài khoản, dịch vụ, domain hoặc mạng không thuộc quyền kiểm soát của bạn.

## 10. Tài liệu tham khảo

- RFC 4120: The Kerberos Network Authentication Service (V5)
- RFC 1510: The Kerberos Network Authentication Service (V5)
- William Stallings, Cryptography and Network Security
- Microsoft Kerberos Authentication Overview
