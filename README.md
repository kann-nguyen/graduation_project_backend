# Hệ Thống Backend - Đồ Án Tốt Nghiệp

Hệ thống backend cho đồ án tốt nghiệp, tập trung vào việc quản lý lỗ hổng bảo mật, rủi ro và ticket. Hệ thống cung cấp các công cụ quét phát hiện lỗ hổng bảo mật trong  hình ảnh container.

## Cài Đặt

1. Cài đặt phiên bản mới nhất của [Node.js](https://nodejs.org/en/download)
2. Cài đặt [pnpm](https://pnpm.io/installation)
3. Chạy lệnh `pnpm install` để cài đặt các gói phụ thuộc
4. Chạy lệnh `npm run dev` để khởi động máy chủ API

## Cấu Trúc Dự Án

Dự án backend bao gồm các thành phần sau:
- **image-scanner**: Hệ thống quét hình ảnh container, phát hiện các lỗ hổng bảo mật trong Docker images
- **src**: Mã nguồn chính của ứng dụng, xử lý logic nghiệp vụ và API endpoints

## Kích Hoạt Quét Hình Ảnh Cho Các Artifact

1. Cài đặt [Docker](https://docs.docker.com/get-docker/)
2. Cài đặt [ngrok](https://ngrok.com/download)
3. Chạy lệnh `cd image-scanner`
4. Chạy lệnh `docker-compose up -d`
5. Bây giờ dịch vụ web đang chạy trên cổng 3000. Để cho phép truy cập từ internet, sử dụng ngrok: `ngrok http 3000`
6. Chạy lệnh `cd ..`
7. Thay đổi giá trị IMAGE_SCANNING_URL trong file `.env` thành URL được cung cấp bởi ngrok
8. Khởi động lại ứng dụng: Nhấn `CTRL+C` trên terminal đang chạy `npm run dev` và sau đó chạy lại `npm run dev`
9. Kiểm tra chức năng: Khi tạo artifact, bạn sẽ thấy thông báo trong terminal đang chạy `npm run dev` hiển thị "Image scanning triggered for artifact: (tên artifact)". Sau khi quá trình quét hoàn tất, terminal sẽ ghi lại một yêu cầu POST /webhook. Kiểm tra tab "Vulnerabilities" trong ứng dụng để xem kết quả.

## Yêu Cầu Hệ Thống

- Node.js v16 trở lên
- Docker (cho các chức năng quét container)
- Ít nhất 4GB RAM
- 10GB dung lượng đĩa trống

## Môi Trường Phát Triển

Dự án sử dụng TypeScript với các công nghệ sau:
- Express.js: Framework web
- Passport.js: Xác thực người dùng
- Docker: Quản lý container
- Vite: Công cụ build
- PostgreSQL: Cơ sở dữ liệu quan hệ để lưu trữ thông tin lỗ hổng, rủi ro và ticket
- Redis: Caching và quản lý hàng đợi

## Biến Môi Trường

Tạo file `.env` trong thư mục gốc với các biến sau:
```
PORT=8000
DATABASE_URL=...
JWT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
IMAGE_SCANNING_URL=...
TICKET_SYSTEM_API_KEY=...
```

## Chức Năng Hệ Thống

### 1. Quản Lý Lỗ Hổng Bảo Mật
Đây là chức năng cốt lõi của hệ thống, cho phép:
- Phát hiện, phân loại và theo dõi lỗ hổng bảo mật từ nhiều nguồn
- Đánh giá mức độ nghiêm trọng của từng lỗ hổng dựa trên thang điểm CVSS
- Cung cấp thông tin chi tiết về cách khắc phục các lỗ hổng
- Theo dõi trạng thái và quá trình xử lý của từng lỗ hổng

### 2. Quản Lý Rủi Ro
Hệ thống giúp đánh giá và kiểm soát rủi ro bảo mật:
- Phân tích mức độ rủi ro dựa trên lỗ hổng được phát hiện
- Tạo ma trận rủi ro để ưu tiên các vấn đề cần giải quyết
- Theo dõi các chỉ số rủi ro theo thời gian
- Đề xuất biện pháp giảm thiểu rủi ro

### 3. Quản Lý Ticket
Hệ thống cung cấp quy trình làm việc dựa trên ticket:
- Tự động tạo ticket cho lỗ hổng mới được phát hiện
- Phân công người phụ trách xử lý các vấn đề
- Theo dõi trạng thái và tiến độ xử lý
- Cung cấp tích hợp với các hệ thống ticket bên ngoài

### 4. Quét Lỗ Hổng Trong Container Images
Chức năng quét hình ảnh Docker container giúp:
- Phát hiện các gói phần mềm có lỗ hổng bảo mật đã biết
- Phân tích cấu hình container để tìm các điểm yếu
- Cung cấp báo cáo chi tiết về mức độ nghiêm trọng và cách khắc phục
- Tích hợp với quy trình CI/CD để tự động hóa quá trình quét

### 5. Quản Lý Artifacts
Hệ thống cho phép:
- Tải lên các artifact để quét (mã nguồn, hình ảnh, tài liệu)
- Theo dõi lịch sử quét và các kết quả
- Phân loại artifacts theo mức độ rủi ro
- Tạo báo cáo chi tiết về các lỗ hổng đã phát hiện

### 6. Tích Hợp GitHub, GitLab
Hệ thống cung cấp tích hợp với GitHub, GitLab để:
- Xác thực người dùng thông qua GitHub, GitLab
- Đồng bộ các repository được chỉ định

### 7. API Endpoints và Báo Cáo
Hệ thống cung cấp các API endpoints để:
- Quản lý người dùng và xác thực
- Tạo và quản lý ticket cho lỗ hổng bảo mật
- Tải lên và quản lý artifacts
- Kích hoạt quét bảo mật
- Truy xuất kết quả quét và báo cáo phân tích
