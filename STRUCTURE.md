# Kerberos Authentication Project Structure

## Cấu trúc thư mục

```
python_kerberos_v2/
├── README.md                    # Hướng dẫn chính
├── STRUCTURE.md                 # File này
├── requirements.txt             # Các thư viện cần thiết (không có)
├── run.bat                      # Script chạy cho Windows
├── run.sh                       # Script chạy cho Linux/Mac
├── .gitignore                   # Git ignore file
│
├── models.py                    # ⭐ Các mô hình dữ liệu chung
│                               # (Ticket, Authenticator, ASRequest, ASReply, ...)
│
├── shared/                      # 🌍 Thư mục chung cho tất cả
│   ├── __init__.py
│   └── utils.py                 # Hàm tiện ích (log, nonce, timestamp, ...)
│
├── database/                    # 📦 Thực thể: KDC Database
│   ├── __init__.py
│   ├── database_entity.py       # Entity: Lớp biểu diễn Database
│   ├── database_engine.py       # Engine: Logic xử lý, khởi tạo dữ liệu
│   └── database_crypto.py       # Crypto: Mã hóa/Giải mã của Database
│
├── as_server/                   # 🔐 Thực thể: Authentication Server (AS)
│   ├── __init__.py
│   ├── as_entity.py             # Entity: Lớp biểu diễn AS
│   ├── as_engine.py             # Engine: Xử lý AS-REQ, cấp TGT
│   └── as_crypto.py             # Crypto: Mã hóa/Giải mã của AS
│
├── tgs_server/                  # 🎫 Thực thể: Ticket Granting Server (TGS)
│   ├── __init__.py
│   ├── tgs_entity.py            # Entity: Lớp biểu diễn TGS
│   ├── tgs_engine.py            # Engine: Xử lý TGS-REQ, cấp Service Ticket
│   └── tgs_crypto.py            # Crypto: Mã hóa/Giải mã của TGS
│
├── client/                      # 👤 Thực thể: Client (Alice)
│   ├── __init__.py
│   ├── client_entity.py         # Entity: Lớp biểu diễn Client
│   ├── client_engine.py         # Engine: Thực hiện 3 pha giao tiếp
│   └── client_crypto.py         # Crypto: Mã hóa/Giải mã của Client
│
├── service_server/              # 🌐 Thực thể: Service Server (Mail Service)
│   ├── __init__.py
│   ├── service_entity.py        # Entity: Lớp biểu diễn Service Server
│   ├── service_engine.py        # Engine: Xác thực Client, phát hành AP-REP
│   └── service_crypto.py        # Crypto: Mã hóa/Giải mã của Service Server
│
└── main.py                      # ⭐ Điểm vào chương trình
                                # Mô phỏng quá trình truyền dữ liệu 3 pha
```

## Cách tổ chức mỗi Thực thể

Mỗi thực thể (Entity) được tổ chức thành 3 file riêng:

### 1. **Entity File** (`*_entity.py`)
- Định nghĩa các lớp dữ liệu đại diện cho thực thể
- Chứa các thuộc tính và trạng thái
- Ví dụ: `AuthenticationServerEntity`, `KerberosClientEntity`

```python
# database/database_entity.py
@dataclass
class KDCDatabaseEntity:
    realm: str
    principals: Dict[str, Principal] = field(default_factory=dict)
```

### 2. **Engine File** (`*_engine.py`)
- Logic xử lý chính của thực thể
- Triển khai các thuật toán và quy tắc nghiệp vụ
- Tương tác với Database nếu cần
- Ví dụ: `ASEngine`, `ClientEngine`

```python
# as_server/as_engine.py
class ASEngine:
    def process_as_request(self, as_request: ASRequest, client_password: str) -> ASReply:
        # Logic xác thực, tạo TGT, ...
```

### 3. **Crypto File** (`*_crypto.py`)
- Hệ thống mã hóa/giải mã của thực thể
- **Hiện tại**: Tất cả dùng XOR Stream (giống nhau)
- **Tương lai**: Có thể thay đổi độc lập cho từng thực thể
- Ví dụ: `DatabaseCryptoEngine`, `ClientCryptoEngine`

```python
# client/client_crypto.py
class ClientCryptoEngine:
    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        # Triển khai mã hóa XOR Stream
```

## Models.py (Dữ liệu chung)

File `models.py` chứa các lớp dữ liệu được sử dụng bởi tất cả các thực thể:

```python
# models.py
@dataclass
class Ticket:              # Vé xác thực
@dataclass
class Authenticator:       # Bộ xác thực
@dataclass
class Principal:           # Thực thể (User/Service)
@dataclass
class ASRequest:           # Bản tin AS-REQ
@dataclass
class ASReply:             # Bản tin AS-REP
@dataclass
class TGSRequest:          # Bản tin TGS-REQ
@dataclass
class TGSReply:            # Bản tin TGS-REP
@dataclass
class APRequest:           # Bản tin AP-REQ
@dataclass
class APReply:             # Bản tin AP-REP
```

## Shared Utils (Hàm tiện ích)

File `shared/utils.py` cung cấp các hàm tiện ích cho tất cả các thực thể:

```python
# shared/utils.py
def get_current_timestamp() -> float         # Lấy timestamp hiện tại
def generate_nonce(length: int = 16) -> str # Sinh nonce
def generate_session_key(length: int = 32) -> str  # Sinh session key
def log_info(entity: str, message: str)     # In log
def log_success(entity: str, message: str)  # In log thành công
def log_error(entity: str, message: str)    # In log lỗi
def log_debug(entity: str, message: str)    # In log debug
```

## Main.py (Orchestrator)

File `main.py` là "dàn dựng viên" (orchestrator) điều phối toàn bộ quá trình:

1. **Khởi tạo** tất cả các thực thể
2. **Pha 1: AS Exchange**
   - Client gửi AS-REQ
   - AS xử lý, phát hành TGT
   - Client nhận AS-REP
3. **Pha 2: TGS Exchange**
   - Client gửi TGS-REQ
   - TGS xử lý, phát hành Service Ticket
   - Client nhận TGS-REP
4. **Pha 3: Application Exchange**
   - Client gửi AP-REQ
   - Service Server xử lý, phát hành AP-REP
   - Mutual Authentication thành công

## Lợi ích của kiến trúc này

✅ **Tách biệt mối quan tâm (Separation of Concerns)**
- Mỗi thực thể có Entity, Engine, Crypto riêng

✅ **Dễ test**
- Có thể test từng thực thể độc lập

✅ **Dễ mở rộng**
- Có thể thay đổi hệ mã hóa của từng thực thể mà không ảnh hưởng đến các thực thể khác

✅ **Minh họa giao thức rõ ràng**
- Main.py cho thấy rõ ràng luồng dữ liệu giữa các thực thể

✅ **Thực tế**
- Mô phỏng cách các hệ thống thực tế hoạt động

## Cách chạy

**Trên Windows:**
```bash
# Cách 1: Double-click run.bat
run.bat

# Cách 2: Chạy từ command line
python main.py
```

**Trên Linux/Mac:**
```bash
# Cách 1: Sử dụng script
chmod +x run.sh
./run.sh

# Cách 2: Chạy trực tiếp
python3 main.py
```

## Kịch bản thử nghiệm

### Scenario 1: Đăng nhập thành công (mặc định)
- Alice cung cấp mật khẩu đúng: `alice_password_123`
- Thực hiện 3 pha thành công
- Truy cập dịch vụ thành công

### Scenario 2: Mật khẩu sai (có thể sửa trong main.py)
- Thay đổi mật khẩu trong Client
- AS từ chối ở Pha 1

### Scenario 3: Vé hết hạn (có thể sửa trong main.py)
- Thay đổi lifetime = 0
- Hệ thống từ chối vé hết hạn

## Định hướng tương lai

1. **Thay đổi hệ mã hóa**: Từ XOR Stream sang AES cho từng thực thể
2. **Thêm Replay Cache**: Để phòng chống Replay Attack
3. **Thêm Cross-Realm Authentication**: Để mô phỏng nhiều Realm
4. **Thêm PAC (Privilege Attribute Certificate)**
5. **Thêm Unit Tests**: Để verify logic của từng thực thể
6. **Thêm Performance Analysis**: Đo lường thời gian xử lý

## Ghi chú

- Project này sử dụng **Python 3.8+**
- Không cần thư viện ngoài (chỉ dùng standard library)
- Mã hóa XOR Stream chỉ dùng cho **giáo dục**, không bảo mật thực tế
