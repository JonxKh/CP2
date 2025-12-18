[README.md](https://github.com/user-attachments/files/24247429/README.md)
# IoT Intrusion Detection & Prevention System (IDS/IPS)

This repository contains a **real-time IoT Intrusion Detection and Prevention System** built using **Suricata**, a **TensorFlow Lite LSTM model**, and **nftables**.  
The system is designed for **edge deployment (e.g., Raspberry Pi)** and focuses on **low-latency attack detection and mitigation** for IoT networks.

---

## 📁 Repository Contents

- **`Inrference_code.py`**  
  Real-time inference and mitigation engine.
  - Monitors Suricata `eve.json`
  - Extracts flow-based features
  - Runs TensorFlow Lite inference
  - Applies heuristic-based detection
  - Automatically blocks malicious IPs using nftables
  - Logs predictions and sends alerts

- **`Lstm_converted2.tflite`**  
  Lightweight TensorFlow Lite LSTM model trained on the CIC IoT dataset 2023.  
  Optimized for low-resource edge devices.

---

## 🧠 System Architecture

Network Traffic  
→ Suricata IDS  
→ Inference Engine (Python)  
→ ML + Heuristics  
→ nftables (Auto Block)

---

## 🚀 Features

- Near real-time intrusion detection
- Edge-optimized LSTM model (TensorFlow Lite)
- Flow-based ML inference for TCP/UDP traffic
- Rule-based detection for SYN flood, HTTP flood, port scanning
- Automatic IP blocking with nftables timeout
- Telegram and Email alert support
- CSV logging for analysis and reporting

---

## 🛠 Requirements

### System
- Linux (Debian / Raspberry Pi OS recommended)
- Root privileges (required for nftables)
- Suricata installed and running

### Python
- Python 3.8+
- Required packages:
```
pip3 install numpy tensorflow pygtail requests
```
### tensorflow
- Tensorflow
-  Required packages:
```
pip install tensorflow==2.12.0
```

---

## ⚙️ Configuration

Edit the following parameters in `Inrference_code.py`:

### Paths
```
EVE = "/var/log/suricata/eve.json"
MODEL_PATH = "Lstm_converted2.tflite"
CSV_LOG = "/var/log/iot_ids_predictions_test.csv"
```

### Protected Host
```
PROTECTED_HOST = "192.168.0.XXX"
SAFE_IPS = {"192.168.0.1", PROTECTED_HOST}
```

### ML Blocking Threshold
```
ML_BLOCK_CONF = 0.60
ML_BLOCK_HITS = 2
ML_BLOCK_WINDOW = 60.0
```

---

## ▶️ Usage

1. Start Suricata:
```
sudo systemctl start suricata
```

2. Run the IDS:
```
sudo -E /opt/iot-ids/.venv/bin/python /opt/iot-ids/infer.py
```

---

## 📊 Output & Logging

- CSV prediction log
- Automatic nftables IP blocking with timeout

---

## ⚠️ Notes

- ICMP, DNS, and HTTP traffic is treated as benign
- ML inference applies only to TCP/UDP flow events
- Thresholds should be tuned per deployment

---

## 📚 Academic Context

Developed as a **Final Year Project (FYP)** focusing on edge-based IoT security and real-time intrusion prevention.

---

## ⚖️ Disclaimer

Use only in authorized environments. Misconfiguration may block legitimate traffic.
