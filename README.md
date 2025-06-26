# Intel SGX Sample Setup on Azure DCsv3 VM

This repository contains the Intel SGX SDK samples compiled and tested on an **Azure Confidential Computing DCsv3 VM**. It includes working examples like `SampleEnclave`, `SampleEnclavePCL`, and other enclave-based trusted applications.

---

## ✅ System Setup

### 📦 Required Packages

Update system and install dependencies:

```bash
sudo apt update && sudo apt upgrade
sudo apt install build-essential ocaml automake autoconf libtool wget python3 libssl-dev dkms
