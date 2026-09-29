# 🛡️ DrishtiGuard

## Low-Cost IoT Security Gateway with Blockchain Inspired Device Authentication

![ESP32](https://img.shields.io/badge/Hardware-ESP32-blue)
![Protocol](https://img.shields.io/badge/Communication-MQTT-green)
![Security](https://img.shields.io/badge/Security-BIP340%20Schnorr%20Signature-red)
![Language](https://img.shields.io/badge/Language-C%2B%2B-orange)

---

# 📌 Problem Statement

With the rapid growth of IoT devices, security has become a major challenge. Many low-cost IoT devices operate with weak authentication mechanisms, making them vulnerable to:

* Unauthorized device access
* Device impersonation attacks
* Data manipulation
* Malicious device injection into IoT networks
* Lack of real-time security monitoring

Traditional authentication methods often depend on passwords or static credentials, which can be compromised easily.

The objective of **DrishtiGuard** is to develop a **low-cost IoT security gateway** capable of monitoring connected devices, verifying their authenticity, detecting suspicious behavior, and isolating compromised devices.

---

# 💡 Our Solution: DrishtiGuard

DrishtiGuard is a lightweight IoT security framework consisting of:

* **ESP32 IoT Security Client**
* **Security Gateway**
* **MQTT Communication Layer**
* **BIP340 Schnorr Signature Authentication**
* **Real-time Security Status Monitoring**

The ESP32 acts as a trusted IoT device that proves its identity to the gateway using cryptographic authentication before joining the network.

Instead of sending passwords or static keys, the device generates a cryptographic signature that the gateway verifies.

---

# 🏗️ System Architecture

```
                 +----------------+
                 |     ESP32      |
                 | IoT Device     |
                 +----------------+
                         |
                         |
                  MQTT Communication
                         |
                         |
                 +----------------+
                 | Security       |
                 | Gateway        |
                 +----------------+
                         |
                         |
              Device Verification
              BIP340 Signature Check
                         |
                         |
                 Security Decision
                         |
        --------------------------------
        |              |               |
     SECURE       SUSPICIOUS      COMPROMISED
        |              |               |
    Green LED     Yellow LED       Red LED
```

---

# 🔐 Security Authentication Flow

The ESP32 follows a challenge-response authentication mechanism.

## Step 1: Authentication Request

ESP32 sends an authentication request:

```
Topic:
sih/auth/request
```

The gateway receives the request and generates a random challenge.

---

## Step 2: Gateway Challenge

Gateway sends:

```
Topic:
sih/auth/challenge
```

The challenge prevents replay attacks because every authentication session uses a new value.

---

## Step 3: Message Hash Generation

ESP32 creates a message:

```
SHA256(
"SIH-ZKP-v1"
+
DEVICE_ID
+
challenge
)
```

The generated hash becomes the message to be signed.

---

## Step 4: BIP340 Schnorr Signature

ESP32 signs the hash using:

* secp256k1 elliptic curve
* BIP340 Schnorr digital signature

The signature proves that the device owns the private key without revealing the private key.

The response is published:

```
Topic:
sih/auth/response
```

---

## Step 5: Gateway Verification

The gateway verifies:

```
Signature + Public Key + Message Hash
```

If verification succeeds:

```
Device = Trusted
```

Otherwise:

```
Device = Suspicious/Compromised
```

---

# ⚙️ ESP32 Code Explanation

## 1. Required Libraries

```cpp
#include <WiFi.h>
#include <WiFiClient.h>
#include <PubSubClient.h>

#include "ZkpSecp256k1.h"
#include "mbedtls/sha256.h"
```

### Purpose:

| Library          | Function                     |
| ---------------- | ---------------------------- |
| WiFi.h           | ESP32 WiFi connection        |
| PubSubClient.h   | MQTT communication           |
| ZkpSecp256k1.h   | BIP340 cryptographic signing |
| mbedtls/sha256.h | SHA256 hashing               |

---

# 🌐 Network Communication

The ESP32 communicates with the security gateway using MQTT.

## MQTT Topics

| Topic                  | Purpose                      |
| ---------------------- | ---------------------------- |
| `sih/auth/request`     | ESP32 authentication request |
| `sih/auth/challenge`   | Gateway challenge            |
| `sih/auth/response`    | ESP32 signed response        |
| `sih/security/status`  | Security state updates       |
| `sih/security/control` | Gateway control commands     |

---

# 🔑 Cryptographic Authentication

The ESP32 stores a private key:

```cpp
SECRET_HEX
```

This key is used only for generating signatures.

The private key is never transmitted.

Authentication uses:

```
Private Key
      |
      |
 BIP340 Sign
      |
      |
Signature
      |
      |
Gateway Verification
```

---

# 🚦 Security State Management

The ESP32 supports multiple security states:

## 1. SECURE

Device authentication successful.

Output:

```
Green LED ON
```

---

## 2. SUSPICIOUS

Authentication incomplete or abnormal behavior detected.

Output:

```
Yellow LED ON
```

---

## 3. COMPROMISED

Signature verification failed or attack detected.

Output:

```
Red LED ON
Buzzer Alert
```

---

## 4. RESTRICTED

Device access limited by gateway.

Output:

```
Yellow LED ON
```

---

## 5. ISOLATED

Device removed from trusted network.

Output:

```
Red LED ON
```

---

# 🔊 Attack Detection Alert

When an authentication failure occurs:

```cpp
triggerAttackAlert();
```

The ESP32 activates:

* Red LED
* Buzzer notification

This provides immediate physical indication of a possible attack.

---

# 🔌 Hardware Connections

| Component  | ESP32 Pin |
| ---------- | --------- |
| Green LED  | GPIO 23   |
| Yellow LED | GPIO 22   |
| Red LED    | GPIO 21   |
| Buzzer     | GPIO 19   |

---

# 🔄 Main Program Flow

The ESP32 continuously performs:

```
Start
 |
Connect WiFi
 |
Connect MQTT Broker
 |
Send Authentication Request
 |
Receive Challenge
 |
Generate SHA256 Hash
 |
Create BIP340 Signature
 |
Send Response
 |
Receive Security Status
 |
Update LED/Buzzer
 |
Repeat
```

---

# 🧪 Attack Simulation

The code includes attack testing:

```cpp
bool SIMULATE_ATTACK = false;
```

When enabled:

```cpp
SIMULATE_ATTACK = true;
```

The ESP32 intentionally sends an invalid signature.

Expected behavior:

```
Signature Verification Failed

        ↓

COMPROMISED State

        ↓

Red LED + Buzzer Alert
```

---

# 🚀 Features Implemented

✅ Lightweight IoT security authentication
✅ BIP340 Schnorr signature verification
✅ Challenge-response authentication
✅ MQTT based communication
✅ Real-time device status monitoring
✅ Attack simulation mode
✅ Hardware security indicators
✅ Low-cost ESP32 implementation

---

# 🔮 Future Improvements

* Add TLS encrypted MQTT communication
* Store keys inside secure hardware
* Add OTA firmware security verification
* Implement machine learning based anomaly detection
* Automatic device isolation through gateway
* Secure key provisioning system

---

# 👨‍💻 Project Team

**Project Name:** DrishtiGuard
**Domain:** IoT Security
**Hardware:** ESP32
**Security Algorithm:** BIP340 Schnorr Signature
**Communication:** MQTT

---

# 📜 License

This project is developed for educational and research purposes.
