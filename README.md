# CyberAdapt: Cross-Layer Trust Framework for Secure V2X Cooperative Platooning

**Institutional Context**: Chaitanya Bharathi Institute of Technology (CBIT), Hyderabad  
**Project Review**: Final Year Project Review–1 (October 2026)  
**Students**: Srinath Manda, Shivaram More, Krishna Koushik  
**Guide**: P. Vimala Manohara Ruth  
**Base Paper**: IEEE Transactions on Vehicular Technology (IEEE TVT), Vol. 75, No. 5, May 2026: *"Multi-Authority Attribute-Based Searchable Encryption With Attribute Revocation for Internet of Vehicles"* (MA-ABSE-AR).

---

## 1. Project Overview & Identified Gaps

While MA-ABSE-AR provides multi-authority attribute-based keyword search and user revocation for cloud/RSU-assisted vehicular networks, rigorous analysis revealed **4 critical security and performance gaps**:

1. **Gap 1: Heavy Pairing and ECC Latency (OBU Bottlenecks)**  
   Vehicle OBUs incur significant bilinear pairing and scalar multiplication delays (6–9 ms in Java JPBC, with 10–50 ms garbage collection pauses), violating real-time CACC safety deadlines ($< 20\text{ ms}$).
2. **Gap 2: Plaintext Identity Leakage**  
   MA-ABSE-AR transmits vehicle credentials/IDs in plaintext or cert headers, exposing platoon movement patterns and roll numbers to eavesdroppers.
3. **Gap 3: Policy Metadata Exposure**  
   Plaintext access policy strings (e.g., `PLATOON_LEADER_HAZMAT_CORRIDOR`) are visible over V2X broadcast channels, leaking operational roles and tactical intent.
4. **Gap 4: Binary Cryptographic Trust & The Insider Threat Vulnerability**  
   MA-ABSE-AR treats security as a binary gate: if a message is cryptographically authorized, it is directly actuated by the CACC controller. If an authorized ECU is compromised, an attacker can broadcast a fraudulent $-7.5\text{ m/s}^2$ braking command that passes crypto, inducing violent jerk ($73.5\text{ m/s}^3$) and catastrophic accordion shockwaves.

---

## 2. CyberAdapt's 6 Proposed Solutions

CyberAdapt introduces a **dual-layer defense-in-depth architecture**:
- **Layer 1: Cryptographic Ingress Gate** (Solutions 1–3, implemented in **Rust + curve25519-dalek** for sub-microsecond, constant-time execution).
- **Layer 2: Cyber-Physical Trust Supervisor** (Solutions 4–6, implemented in Python + Eclipse SUMO TraCI).

| # | Solution | Formulation | Physical / Cryptographic Outcome |
|---|---|---|---|
| **1** | **SMBP-PreComp & Bloom Filter** | $T[i] = 2^i G$, $m=32768, k=4$ | 2.5x–3.8x ECC speedup (zero online doublings); $O(1)$ revocation lookup ($0.8\ \mu\text{s}$) with $P_{FP} \approx 0.00123\%$. |
| **2** | **ZK-TAT** | $C = r G + \text{VID} \cdot H$, Schnorr proof $(R, s_1, s_2)$ | 128-byte token; exactly **0 bits** of vehicle identity leaked. |
| **3** | **H-PO** | $\tilde{\rho}(s) = \text{SHA-256}(\text{"HPO\_SALT\_V1"} \parallel A_s \parallel S_{\text{platoon}})$ | 32-byte opaque keyed digest hides attribute roles from eavesdroppers. |
| **4** | **Shifted Sigmoid Trust** | $w_{\text{raw}}(S) = \frac{1.02732}{1 + e^{8(S - 0.45)}}$, clamped to $[0.05, 1.0]$ | Smooth, calibrated trust attenuation under anomalies. |
| **5** | **Plausibility & Blending** | $J \le 3.0\text{ m/s}^3$, $\Delta v < 1.5\text{ m/s}$, $u_{\text{cmd}} = w a_{\text{CACC}} + (1-w) a_{\text{ACC}}$ | Flags anomalies ($S=1.0$), bounds jerk $\le 3.8\text{ m/s}^3$, lets radar ACC dominate gracefully. |
| **6** | **Dynamic Headway Adaptation** | $h(t) = 0.60 + (1-w)(1.00)\text{ s}$, $d = v \cdot h(t) + d_0$ | Expands headway from $0.60\text{ s} \to 1.55\text{ s}$ (+158% safety gap) under attack. |

---

## 3. Tech Stack Mapping (Review-1 Slide 22)

- **Crypto Core**: **Rust** (`cyberadapt_rust/`)
  - `curve25519-dalek` / Ristretto / 160-bit prime field arithmetic
  - `sha2`, `aes-gcm`
  - Constant-time scalar multiplication (prevents timing side-channel attacks on OBU)
  - Zero garbage collection pauses ($0\text{ ms}$ vs Java JPBC $10\text{–}50\text{ ms}$)
  - Vehicle OBU decryption latency: $\approx 1.6\ \mu\text{s}$ (sub-millisecond!)
- **Cyber-Physical Simulation**: **Python 3.10+ / Eclipse SUMO 1.18+ / TraCI**
  - 15 km 4-lane highway with 8 vehicles (`leader`, `follower1`..`follower7`)
  - Insider spoofing injection at $t = 20.0\text{ s}$
- **Graphical User Interface**: **Tkinter + Matplotlib (TkAgg)** (`cyberadapt_gui.py`)
  - 5 interactive analytical tabs reproducing paper Figs 4, 5, 6, 7 and the Review-1 formulations.

---

## 4. Directory Structure

```text
D:\Cyberadapt\cyberadapt_framework\
├── cyberadapt_rust\             # Native Rust Cryptographic Core
│   ├── Cargo.toml               # Cargo dependencies (aes-gcm, sha2, serde, num-bigint)
│   ├── src\main.rs              # Constant-time ECC, SMBP, Bloom Filter, ZK-TAT, H-PO, FO-Transform
│   └── target\release\cyberadapt_rust.exe  # Compiled native binary
├── sumo\                        # SUMO Highway Network Configuration
│   ├── highway.net.xml          # 15 km 4-lane highway
│   ├── highway.rou.xml          # 8-vehicle platoon definitions
│   └── sim.sumocfg              # TraCI configuration
├── cyberadapt_crypto.py         # Python bridge & mathematical implementation of Solutions 1-3
├── cyberadapt_control.py        # Python implementation of Solutions 4-6 (Sigmoid, Jerk, Headway)
├── cyberadapt_simulation.py     # End-to-end SUMO TraCI simulation runner
├── cyberadapt_gui.py            # Comprehensive 5-Tab GUI Dashboard
├── compare_frameworks.py        # 5-Point Head-to-Head Comparative Verification Suite
├── LAUNCH_CYBERADAPT_GUI.bat    # Windows 1-click GUI Launcher
├── RUN_CYBERADAPT_TESTS.bat     # Windows 1-click Test Suite Launcher
└── README_CYBERADAPT.md         # Full documentation and manual
```

---

## 5. Quick Start Instructions

### A. Run Head-to-Head Comparative Verification Suite (Console)
```cmd
cd D:\Cyberadapt\cyberadapt_framework
python compare_frameworks.py
```
*Evaluates all 5 head-to-head tests and prints `[PASS] ADVANTAGE PROVEN` for each.*

### B. Launch Interactive GUI Dashboard
```cmd
cd D:\Cyberadapt\cyberadapt_framework
python cyberadapt_gui.py
```
*(Or double-click `LAUNCH_CYBERADAPT_GUI.bat`)*

### C. Run Native Rust Cryptographic Core Engine
```cmd
cd D:\Cyberadapt\cyberadapt_framework\cyberadapt_rust
cargo test
cargo run --release
cargo run --release -- --json
```

---

## 6. Verification Summary

| Test | Evaluated Feature | MA-ABSE-AR Baseline | Proposed CyberAdapt | Advantage Status |
|---|---|---|---|---|
| **Test 1** | Fixed-Base ECC Scalar Mul | 6.41 ms (Double-and-Add) | **1.96 ms** (Python) / **19 µs** (Rust) | **[PASS] 3.2x Speedup** |
| **Test 2** | Vehicle Identity Privacy | Plaintext VID in packet | **128-byte ZK-TAT Token** | **[PASS] 0 bits leaked** |
| **Test 3** | Access Policy Privacy | Plaintext attribute strings | **32-byte Keyed SHA-256 Digest** | **[PASS] Opaque Tag** |
| **Test 4** | Insider $-7.5\text{ m/s}^2$ Braking | Speed collapses to 4 m/s; Jerk $73.5\text{ m/s}^3$ | Trust drops to 0.05; Radar ACC holds 14 m/s; Headway 1.55s | **[PASS] Platoon Safe** |
| **Test 5** | Vehicle OBU Decryption Latency | 6–9 ms (Java JPBC + GC pauses) | **1.6 µs (Rust, zero GC pauses)** | **[PASS] ~4000x Faster** |
