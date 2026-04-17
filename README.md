# Kerberos Protocol Demo in C++ (for Intro Information Security)

Du an nay mo phong luong xac thuc Kerberos theo cach don gian, phu hop de lam bai tap lon hoc phan nhap mon an toan thong tin.

## Muc tieu hoc tap

- Hieu ro 3 buoc chinh cua Kerberos:
  - AS Exchange (AS-REQ/AS-REP)
  - TGS Exchange (TGS-REQ/TGS-REP)
  - Application Exchange (AP-REQ/AP-REP)
- Hieu vai tro cua TGT, Service Ticket, session key va authenticator.
- Biet cach trinh bay mot he thong xac thuc tap trung KDC trong bao cao do an.

## Canh bao hoc thuat

Day la mo phong phuc vu hoc tap. Ma hoa su dung XOR va hash don gian de de theo doi logic, KHONG duoc dung cho he thong thuc te.

## Cac doan mo phong phu hop khuon kho mon hoc

Muc nay giup phan biet ro giua "logic Kerberos can hoc" va "chi tiet ky thuat da don gian hoa de minh hoa".

- Mo phong ma hoa va ham bam don gian (phuc vu de theo doi luong ban tin):
  - src/crypto_utils.cpp
  - Giai thich: su dung XOR stream va std::hash, KHONG phai ma hoa Kerberos thuc te.

- Mo phong co so du lieu KDC toi gian:
  - include/kdc_database.h
  - src/kdc_database.cpp
  - Giai thich: luu tru principal va khoa theo cach rut gon cho bai tap lon.

- Mo phong AS Exchange (AS-REQ/AS-REP):
  - include/as_server.h
  - src/as_server.cpp
  - Giai thich: van giu y nghia cap K_C-TGS va TGT, nhung trien khai toi gian de de hoc.

- Mo phong TGS Exchange (TGS-REQ/TGS-REP):
  - include/tgs_server.h
  - src/tgs_server.cpp
  - Giai thich: giu dung y tuong dung TGT + Authenticator de xin Service Ticket.

- Mo phong Client/Server Exchange (AP-REQ/AP-REP):
  - include/service_server.h
  - src/service_server.cpp
  - Giai thich: co kiem tra timestamp, replay co ban, va AP-REP cho mutual auth.

- Mo phong luong tu phia client:
  - include/kerberos_client.h
  - src/kerberos_client.cpp
  - Giai thich: dong vai tro script hoa toan bo 3 pha de demo tren console.

- Chuong trinh demo kich ban hoc tap:
  - src/main.cpp
  - Giai thich: co 2 scenario mac dinh (dung mat khau, sai mat khau) de trinh bay ket qua.

### Pham vi "dung ly thuyet" va "mo phong"

- Dung ly thuyet Kerberos:
  - Co KDC tach logic AS/TGS.
  - Co TGT, Service Ticket, session key K_C-TGS va K_C-V.
  - Co Authenticator + timestamp + mutual authentication.

- Mo phong de phu hop mon hoc:
  - Ma hoa/Xac thuc thong diep duoc don gian hoa.
  - Khong tich hop MIT Kerberos, AD, JAAS/GSS-API.
  - Khong mo phong day du realm, keytab, ticket cache, PAC, chinh sach domain.

## Cau truc project

- include/: Header files
- src/: Source files
- docs/: Tai lieu goi y viet bao cao
- CMakeLists.txt: Cau hinh build CMake

## Yeu cau moi truong

- CMake >= 3.16
- Trinh bien dich ho tro C++17 (MSVC, GCC, Clang)

## Build va chay (PowerShell)

```powershell
cd d:\OneDrive-ntdxl\prj\kerberos
cmake -S . -B build
cmake --build build --config Release
.\build\Release\kerberos_demo.exe
```

Neu dung MinGW hoac Ninja, file thuc thi co the nam o:

```powershell
.\build\kerberos_demo.exe
```

## Cac kich ban co san

- Scenario 1: Dang nhap dung mat khau -> xac thuc thanh cong.
- Scenario 2: Sai mat khau -> bi tu choi tai AS.

## Tuy chinh kich ban khi chay

Ban co the chay theo tung kich ban de demo ro rang hon:

```powershell
.\build\kerberos_demo.exe --scenario success
.\build\kerberos_demo.exe --scenario wrong-password
.\build\kerberos_demo.exe --scenario unknown-service
.\build\kerberos_demo.exe --scenario all
```

Ban cung co the tu nhap thong so:

```powershell
.\build\kerberos_demo.exe --scenario custom --user alice --password alice_password_123 --service mail-service
```

Luu y: Log da duoc danh dau theo dung 3 pha/6 buoc de de map voi phan ly thuyet trong bao cao:

- [Phase 1][Step 1-2]: AS Exchange
- [Phase 2][Step 3-4]: TGS Exchange
- [Phase 3][Step 5-6]: AP Exchange

## Y tuong mo rong cho bai tap lon

- Them replay attack test co chu dong gui lai AP-REQ cu.
- Them timestamp skew test (dong ho client lech qua nguong).
- Thay co che ma hoa bang OpenSSL (AES-GCM) de nang muc ky thuat.
- Them logging va ve sequence diagram cho tung message.

## Goi y trinh bay bao cao

1. Dat van de va yeu cau xac thuc trong he thong client-server.
2. Co so ly thuyet Kerberos: KDC, AS, TGS, ticket, session key.
3. Thiet ke chuong trinh (class diagram + sequence diagram).
4. Mo ta luong message va du lieu trong tung ban tin.
5. Trinh bay ket qua chay va phan tich bao mat.
6. Han che va huong phat trien.
