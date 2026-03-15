# Project Context and Instructions for Assistant

## Project Title
**Intelligent Real-Time Network Intrusion Detection and Traffic Analysis System**

## Project Context
This is a final-year BSc Computer Science major project focused on cybersecurity and network monitoring.

The system is a professional-level Python application with a PySide6 GUI. It extends a previously implemented packet sniffer into a full hybrid platform that combines:
- packet sniffing
- deep packet inspection
- rule-based intrusion detection
- machine-learning anomaly detection
- real-time analytics visualization

## Assistant Role
The assistant supports design, implementation, and integration of this system step by step.

When responding:
- explain concepts clearly before giving code
- describe architecture and design logic before implementation details
- justify technical decisions with practical reasoning
- provide clean, modular, maintainable Python code

## Main Objectives
1. Capture live network traffic.
2. Analyze packet contents and protocol information.
3. Detect malicious or suspicious activity in real time.
4. Use machine learning to identify abnormal traffic patterns.
5. Provide a visual dashboard showing live network analytics.
6. Generate alerts when potential attacks are detected.

## Core System Modules

### 1) Packet Capture Engine
Captures live packets from system network interfaces.

Responsibilities:
- continuously capture packets
- extract basic metadata: source IP, destination IP, protocol, ports, packet size
- forward packet data to analysis modules

Suggested tools:
- Scapy, PyShark, or equivalent Python libraries

### 2) Deep Packet Inspection (DPI)
Inspects packet contents beyond headers.

Responsibilities:
- inspect payloads
- extract protocol-specific data
- identify application-layer details

Examples of extracted data:
- HTTP methods and URLs
- DNS domain queries
- TCP flags (SYN, ACK, FIN)
- payload characteristics
- TLS handshake metadata

### 3) Real-Time Intrusion Detection System (Rule-Based IDS)
Applies security rules to streaming traffic.

Responsibilities:
- detect known suspicious behavior patterns
- trigger immediate alerts when rules are matched

Example rules:
- port scanning (single source probing many ports rapidly)
- SYN flood behavior
- ICMP flood behavior
- repeated failed connection attempts
- suspicious traffic bursts

### 4) AI-Based Anomaly Detection
Detects abnormal behavior using machine learning, not only static signatures.

Purpose:
- learn normal traffic patterns
- flag deviations as potential anomalies

Possible feature set:
- packet rate
- average packet size
- protocol distribution
- unique IP count
- SYN/ACK ratio
- DNS request frequency

Possible algorithms:
- Isolation Forest
- One-Class SVM
- Local Outlier Factor

### 5) Feature Extraction Layer
Transforms parsed packet streams into numerical features for ML.

Example features:
- `packets_per_second`
- `average_packet_size`
- `tcp_syn_ratio`
- `dns_requests_per_minute`
- `number_of_unique_ips`

### 6) Alert Management System
Normalizes and manages alerts from IDS and AI modules.

Responsibilities:
- store alert records
- assign severity levels
- expose alerts to GUI in real time

Severity levels:
- Low
- Medium
- High
- Critical

Required alert fields:
- timestamp
- source IP
- destination IP
- detected threat type
- severity

### 7) Live Traffic Analytics Dashboard (PySide6)
Provides real-time operational visibility.

Dashboard elements:
- packet rate graph (pps)
- bandwidth usage
- protocol distribution pie chart
- top traffic-generating IPs
- real-time alert panel
- system status indicators

## UI Design Requirements

### Sidebar Navigation
- Dashboard
- Packet Capture
- Intrusion Alerts
- Network Analysis
- Settings

### Required Pages
1. Dashboard page with key metrics and live charts.
2. Live Capture page with packet table and filters.
3. Alerts panel with real-time threat feed.
4. Visualization views with line, pie, and traffic statistics.

## Technology Stack
- Python
- PySide6 (GUI)
- Scapy or PyShark (packet capture)
- Scikit-learn (ML anomaly detection)
- Matplotlib or PyQtGraph (real-time charts)
- Pandas (data processing)

## End-to-End Workflow
Network Traffic  
-> Packet Capture Engine  
-> Deep Packet Inspection  
-> Feature Extraction  
-> Rule-Based Intrusion Detection  
-> AI Anomaly Detection  
-> Alert Generation  
-> Dashboard Visualization

## Development Guidelines for Assistant
- Prioritize modular architecture (separate capture, DPI, IDS, ML, alerts, GUI).
- Prefer clear interfaces between modules (data classes/schemas for packet events and alerts).
- Keep processing pipelines suitable for real-time execution (lightweight, non-blocking where possible).
- Recommend thread-safe or async-safe designs for capture and GUI updates.
- Include testable units for rules, feature extraction, and anomaly scoring.
- Keep prototype scope realistic while preserving extensibility.

## Expected Deliverable Direction
Build a functional prototype of an intelligent network monitoring and intrusion detection platform suitable for final-year cybersecurity project evaluation, with:
- live capture
- real-time detection and alerting
- ML-based anomaly insights
- professional dashboard visualization