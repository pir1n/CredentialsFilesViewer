# Credential Files View

Ứng dụng Windows theo giao diện tham khảo `TheUIDesign.jpg`: bảng credential, khung hex/ASCII và hộp thuộc tính. Hoạt động tại máy, không gửi dữ liệu qua mạng.

## Cài đặt

Yêu cầu Python 3.10+ trên Windows.

```powershell
python -m pip install -r requirements.txt
python app.py
```

Có thể mở `run.bat` sau khi đã cài thư viện.

## Online

Chọn **Quét online**. Ứng dụng dùng Windows `CredEnumerateW` để đọc credential mà phiên đăng nhập hiện tại được phép xem. Loại domain password có thể không cung cấp blob theo hạn chế của Windows API.

## Offline từ artifact Windows

Chọn **Mở offline**, sau đó cung cấp:

- Thư mục `C:\Users\<user>\AppData\Local\Microsoft\Credentials` đã sao chép từ máy cần phân tích.
- Thư mục `C:\Users\<user>\AppData\Roaming\Microsoft\Protect` đã sao chép, chứa thư mục con SID và các DPAPI master key.
- Mật khẩu Windows của tài khoản tương ứng tại thời điểm tạo master key, **hoặc** file JSON chứa master key đã giải mã theo định dạng `pypykatz dpapi masterkey -o`.

Chọn đúng SID bằng nút **Tìm SID**, rồi bấm **Giải mã**. Chương trình chỉ đọc artifact đầu vào. Bảng sẽ hiển thị credential giải mã được và tên file nguồn; hộp kết quả cho biết các file chưa giải mã được. Bí mật mặc định được che; bật **Hiện bí mật** để xem.

Hai thư mục artifact riêng lẻ không luôn đủ để giải mã: DPAPI master key còn được bảo vệ bởi thông tin tài khoản. Nếu mật khẩu đã thay đổi, có thể cần mật khẩu cũ hoặc master key đã giải mã. Bản hiện tại xử lý file Credential kiểu DPAPI trong thư mục được chọn; chưa xử lý Vault, Credential Guard hoặc mọi biến thể DPAPI-NG.

## Kiểm tra

```powershell
python -m pytest -q
```

Tham khảo: [Microsoft CredEnumerateW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew), [pypykatz DPAPI credential](https://github.com/skelsec/pypykatz/wiki/dpapi-credential-command), [pypykatz DPAPI masterkey](https://github.com/skelsec/pypykatz/wiki/dpapi-masterkey-command).
