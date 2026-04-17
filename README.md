# Kerberos Authentication Protocol - Python Simulation

Đây là một mô phỏng lại giao thức xác thực Kerberos bằng Python, sử dụng kiến trúc OOP để minh họa cách các thực thể (Client, AS, TGS, Service Server, Database) tương tác với nhau.

## Cấu trúc Project

```
python_kerberos_v2/
├── database/                    # Thực thể: KDC Database
│   ├── database_entity.py       # Entity: Lớp biểu diễn Database
│   ├── database_engine.py       # Engine: Logic xử lý dữ liệu
│   └── database_crypto.py       # Crypto: Mã hóa/Giải mã của Database
│
├── as_server/                   # Thực thể: Authentication Server (AS)
│   ├── as_entity.py             # Entity: Lớp biểu diễn AS
│   ├── as_engine.py             # Engine: Xử lý AS-REQ, cấp TGT
│   └── as_crypto.py             # Crypto: Mã hóa/Giải mã của AS
│
├── tgs_server/                  # Thực thể: Ticket Granting Server (TGS)
│   ├── tgs_entity.py            # Entity: Lớp biểu diễn TGS
│   ├── tgs_engine.py            # Engine: Xử lý TGS-REQ, cấp Service Ticket
│   └── tgs_crypto.py            # Crypto: Mã hóa/Giải mã của TGS
│
├── client/                      # Thực thể: Client (Alice)
│   ├── client_entity.py         # Entity: Lớp biểu diễn Client
│   ├── client_engine.py         # Engine: Xử lý 3 pha giao tiếp
│   └── client_crypto.py         # Crypto: Mã hóa/Giải mã của Client
│
├── service_server/              # Thực thể: Service Server
│   ├── service_entity.py        # Entity: Lớp biểu diễn Service Server
│   ├── service_engine.py        # Engine: Xác thực Client, phát hành AP-REP
│   └── service_crypto.py        # Crypto: Mã hóa/Giải mã của Service Server
│
├── models.py                    # Các mô hình dữ liệu chung (Ticket, Authenticator, Messages)
├── main.py                      # Điểm vào chương trình - Mô phỏng quá trình truyền dữ liệu
└── README.md                    # Tài liệu này
```

## Kiến trúc Kerberos

```
┌──────────────┐
│   Client     │ (Máy khách - Alice)
│   (Alice)    │
└──────────────┘
       │
       │ 1. AS-REQ: Xin TGT
       ├──────────────────────────────────────────┐
       │                                          │
       │                                   ┌──────▼──────────────────┐
       │                                   │   KDC (Trung tâm KDC)  │
       │                                   │  ┌────────────────────┐ │
       │                                   │  │ Authentication     │ │
       │                                   │  │ Server (AS)        │ │
       │                                   │  │                    │ │
       │                                   │  └────────────────────┘ │
       │   2. AS-REP: TGT + K_c,tgs        │  ┌────────────────────┐ │
       │◄──────────────────────────────────┼──┤ Ticket Granting    │ │
       │                                   │  │ Server (TGS)       │ │
       │                                   │  │                    │ │
       │                                   │  └────────────────────┘ │
       │                                   │  ┌────────────────────┐ │
       │                                   │  │ KDC Database       │ │
       │                                   │  │ (Lưu Master Keys)  │ │
       │                                   │  │                    │ │
       │                                   │  └────────────────────┘ │
       │                                   └────────────────────────┘
       │
       │ 3. TGS-REQ: TGT + Authenticator
       ├──────────────────────────────────────────┐
       │                                          │
       │   4. TGS-REP: Service Ticket + K_c,s    │
       │◄──────────────────────────────────────────┤
       │
       │ 5. AP-REQ: Service Ticket + Authenticator
       │                              ┌──────────────────────────┐
       │─────────────────────────────►│  Service Server          │
       │                              │  (MailService)           │
       │                              └──────────────────────────┘
       │   6. AP-REP: Mutual Auth (TS + 1)
       │◄─────────────────────────────

```

## Các thành phần

### 1. **Database (KDC Database)**
- Lưu trữ thông tin của tất cả Principal (User, TGS, Service)
- Lưu trữ Master Key của mỗi Principal
- Cung cấp API để truy vấn thông tin

**Entity**: `database_entity.py` - Lớp `KDCDatabase`
**Engine**: `database_engine.py` - Logic lưu trữ và truy vấn
**Crypto**: `database_crypto.py` - Mã hóa/Giải mã dữ liệu

### 2. **Authentication Server (AS)**
- Xác thực người dùng dựa trên mật khẩu
- Cấp phát Ticket Granting Ticket (TGT)
- Xử lý bản tin AS-REQ, trả về AS-REP

**Entity**: `as_entity.py` - Lớp `AuthenticationServer`
**Engine**: `as_engine.py` - Xử lý AS-REQ, AS-REP
**Crypto**: `as_crypto.py` - Mã hóa/Giải mã của AS

### 3. **Ticket Granting Server (TGS)**
- Kiểm tra TGT và Authenticator từ Client
- Cấp phát Service Ticket
- Xử lý bản tin TGS-REQ, trả về TGS-REP

**Entity**: `tgs_entity.py` - Lớp `TicketGrantingServer`
**Engine**: `tgs_engine.py` - Xử lý TGS-REQ, TGS-REP
**Crypto**: `tgs_crypto.py` - Mã hóa/Giải mã của TGS

### 4. **Client**
- Gửi AS-REQ để xin TGT
- Gửi TGS-REQ để xin Service Ticket
- Gửi AP-REQ để truy cập dịch vụ
- Nhận AP-REP từ Service Server (Mutual Authentication)

**Entity**: `client_entity.py` - Lớp `KerberosClient`
**Engine**: `client_engine.py` - Thực hiện 3 pha giao tiếp
**Crypto**: `client_crypto.py` - Mã hóa/Giải mã của Client

### 5. **Service Server**
- Nhận AP-REQ từ Client
- Kiểm tra Service Ticket
- Xác thực Authenticator với Timestamp
- Phát hành AP-REP (Mutual Authentication)

**Entity**: `service_entity.py` - Lớp `ServiceServer`
**Engine**: `service_engine.py` - Xử lý AP-REQ, AP-REP
**Crypto**: `service_crypto.py` - Mã hóa/Giải mã của Service Server

### 6. **Models**
Định nghĩa các lớp dữ liệu chung:
- `Ticket`: Vé xác thực
- `Authenticator`: Bộ xác thực
- `Principal`: Thực thể (User, Service)
- `ASRequest`, `ASReply`
- `TGSRequest`, `TGSReply`
- `APRequest`, `APReply`

### 7. **Main.py**
Điểm vào chương trình, mô phỏng quá trình:
1. Khởi tạo các thực thể
2. AS Exchange (Client xin TGT)
3. TGS Exchange (Client xin Service Ticket)
4. Application Exchange (Client truy cập dịch vụ)

## Các pha giao tiếp

### **Pha 1: AS Exchange (Xin TGT)**
```
Client                    AS
  │                       │
  │ 1. AS-REQ            │
  ├──────────────────────>│
  │  (client_id, nonce)  │
  │                       │ Kiểm tra mật khẩu
  │                       │ Tạo TGT
  │                       │ Tạo K_c,tgs
  │                       │
  │ 2. AS-REP            │
  │<──────────────────────┤
  │  (TGT, K_c,tgs)      │
```

### **Pha 2: TGS Exchange (Xin Service Ticket)**
```
Client                    TGS
  │                       │
  │ 3. TGS-REQ           │
  ├──────────────────────>│
  │  (TGT, Authenticator)│
  │                       │ Kiểm tra TGT
  │                       │ Kiểm tra Authenticator
  │                       │ Tạo Service Ticket
  │                       │ Tạo K_c,s
  │                       │
  │ 4. TGS-REP           │
  │<──────────────────────┤
  │  (ST, K_c,s)         │
```

### **Pha 3: Application Exchange (Xác thực 2 chiều)**
```
Client                    Service
  │                       │
  │ 5. AP-REQ            │
  ├──────────────────────>│
  │  (ST, Authenticator) │
  │                       │ Kiểm tra ST
  │                       │ Kiểm tra Authenticator
  │                       │ Xác thực Client thành công
  │                       │
  │ 6. AP-REP            │
  │<──────────────────────┤
  │  (Timestamp + 1)     │ Mutual Authentication
```

## Cách chạy

```bash
python main.py
```

## Kịch bản thử nghiệm

**Scenario 1**: Đăng nhập thành công
- Alice cung cấp mật khẩu đúng
- Thực hiện thành công 3 pha
- Truy cập dịch vụ thành công

**Scenario 2**: Mật khẩu sai
- Alice cung cấp mật khẩu sai
- AS từ chối ở Pha 1
- Không thể tiếp tục

**Scenario 3**: Vé hết hạn
- Mô phỏng kiểm tra thời hạn vé
- Từ chối nếu vé hết hạn

## Lưu ý

- Mã hóa XOR Stream được sử dụng cho mục đích giáo dục. **Không dùng cho các ứng dụng thực tế.**
- Timestamp được sử dụng để chống Replay Attack.
- Authenticator chứa thông tin xác thực của Client.
- Mỗi thực thể có hệ thống mã hóa riêng (để sau này có thể thay đổi độc lập).

## Tài liệu tham khảo

- RFC 1510: The Kerberos Network Authentication Service (V5)
- RFC 4120: The Kerberos Network Authentication Service (V5) - Updated
- Microsoft Kerberos Authentication Overview
