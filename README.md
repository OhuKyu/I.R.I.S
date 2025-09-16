# I.R.I.S - Intelligent Reliable Interactive Study Assistant

Chatbot AI hỗ trợ học tập với giao diện web Flask gọn nhẹ và cache kết quả thông minh.

## Tính năng

- 💬 **Chat thông minh**
- 📚 **Tạo Flashcards**
- 🧠 **Tạo Quiz**
- 📄 **Tóm tắt văn bản**
- 💻 **Giải thích Code**
- 📅 **Kế hoạch học tập**
- 🔐 **Upload an toàn**: hỗ trợ AES‑GCM để mã hóa nội dung trước khi gửi
- 🗂️ **Lưu lịch sử hội thoại**: SQLite tích hợp

## Cài đặt

1. Clone repository
2. Cài đặt dependencies: `pip install -r requirements.txt`
3. Tạo file `.env` và điền API keys (xem bên dưới)
4. Chạy server Flask: `python iris_flask.py`

Render deployment đã cấu hình sẵn trong `render.yaml`.

## API Keys

- `MONICA_API_KEY`: Monica.im (OpenAI-compatible)
- `GEMINI_API_KEY`: Google Gemini

Thiếu key sẽ không làm tiến trình dừng, nhưng gọi AI sẽ thất bại cho đến khi cung cấp key hợp lệ.

## Sử dụng

- Truy cập `http://localhost:5000`
- Endpoint sức khỏe: `GET /health`
- API chính: `/api/chat`, `/api/chat/stream`, `/api/summarize`, `/api/explain_code`, `/api/flashcards`, `/api/quiz`, `/api/study_plan`

Thư mục tĩnh: `css/`, template: `templates/`.
