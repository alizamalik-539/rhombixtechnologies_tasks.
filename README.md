# Mobile Application Security Assessment
## Project: Vulnerability Analysis of InsecureBankv2

### Overview
This project involves a manual security assessment of the **InsecureBankv2** Android application to identify critical security flaws.

### Vulnerabilities Identified
1. **Insecure Data Storage (M2):** - Sensitive user credentials (username/password) are stored in plaintext within the application's private filesystem (`/data/data/com.android.insecurebankv2/shared_prefs/mySharedPreferences.xml`).
   - **Impact:** An attacker with physical access or a malicious app with root privileges can easily extract user credentials.

### Tools Used
* **Genymotion:** Android Emulator.
* **ADB (Android Debug Bridge):** To interact with the device filesystem.
* **Linux Terminal:** For command-line exploitation.

### Proof of Concept (PoC)
I used `adb shell` to navigate to the app's internal storage and retrieved the credentials using the following commands:
`cd /data/data/com.android.insecurebankv2/shared_prefs/`
`cat mySharedPreferences.xml`

---
