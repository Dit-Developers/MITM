# SilentSnare Hidden Interceptor: MITM Attack

## Project Overview
**SilentSnare** is a controlled, simulation-based system that demonstrates **Man-in-the-Middle (MITM) attacks** in a safe lab environment. It is designed for educational purposes to help instructors, students, and ethical hacking trainees understand, detect, and prevent MITM attacks.

### Purpose
Provide a hands-on lab to demonstrate ARP spoofing and gateway spoofing. It shows how unencrypted traffic can be intercepted and modified, and highlights countermeasures like TLS/HTTPS and certificate validation.

### Key Features
- Simulates ARP spoofing and gateway spoofing scenarios.
- Captures, logs, and visualizes network traffic in real-time.
- Compares secure (HTTPS) and insecure (HTTP) traffic.
- Responsive dashboard for monitoring packets, alerts, and logs.
- Ethical usage in isolated lab environments.


### Install required tools in your isolated lab environment:

 - Wireshark.
 - tshark.
 - Burp Suite.
 - VS Code.

## Setup

Follow these steps to prepare the environment and dashboard:

1. **Create an isolated lab environment**  
   - Set up a virtual machine or isolated network.  
   - Example: Kali Linux running on VMware.

2. **Configure Firebase**  
   - Create a Firebase project.  
   - Add the following collections:
     - `users`
     - `logs`
     - `data_intercepts`  
   - Apply secure database rules to restrict access.

3. **Open the dashboard**  
   - Open `index.html` in your web browser.  
   - Connect the dashboard to Firebase to fetch and display live intercepted data.
