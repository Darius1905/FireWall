# 🛡️ SIEM Sec Guardian

**SIEM Sec Guardian** 
- là một hệ thống giám sát
- phát hiện xâm nhập kết hợp học máy
- phân tích PCAP
- cập nhật tường lửa tự động
- Hệ thống hỗ trợ đa nền tảng: Linux, Windows, macOS.

---

## 📁 Cấu trúc thư mục
```
📁 siem-sec-guardian/
├── ai_engine/
│ ├── feature_engineering.py
│ ├── model_trainer.py
│ ├── model_predictor.py
│ └── model/
│ ├── network_model.joblib
│ └── scaler.joblib
├── pcap_analyzer/
│ ├── flow_extractor.py
│ ├── anomaly_detector.py
│ └── payload_scanner.py
├── fw_updater/
│ ├── rule_generator.py
│ └── fw_interface.py
├── logger/
│ └── log_manager.py
├── config/
│ └── settings.py
├── main.py
├── requirements.txt
└── README.md
```
#yêu cầu

- Python 3.8+
- Quyền `Administrator` (Windows) hoặc `sudo` (Linux/macOS) để áp dụng firewall

---

#bash
# Tạo và kích hoạt môi trường ảo (khuyên dùng)
python -m venv venv
source venv/bin/activate  # hoặc venv\Scripts\activate trên Windows

# Cài đặt thư viện
pip install -r requirements.txt

# Copyright by Duong Tien Huy Ryan