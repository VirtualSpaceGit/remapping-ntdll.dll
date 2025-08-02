# Remapping ntdll.dll 🛡

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview
This project demonstrates how to securely create and map memory sections using native Windows APIs. The provided code showcases techniques for handling memory securely, verifying system library integrity, and modifying memory sections safely. These practices are essential for applications that interact with system internals, ensuring both security and efficiency against, for example, hooked functions within ntdll.dll. 🔍

## Features

- **Dynamic Section Creation**
  - Utilizes `NtCreateSection` to allocate a secure 2MB section of memory. 
  
- **Memory Mapping**
  - Maps the created section into the process's virtual address space using `NtMapViewOfSection`. 

- **Memory Integrity Check**
  - Compares the first 0x1000 bytes of the original `ntdll.dll` with the newly mapped section to ensure the application code is untampered. 

- **Safe Memory Modifications**
  - Demonstrates secure modification by zeroing out the first 0x1000 bytes of the mapped section. 

## Security Measures

- **API Resolution from Trusted Sources**
  - All APIs (`NtCreateSection`, `NtMapViewOfSection`, `NtClose`) are dynamically resolved from `ntdll.dll`, ensuring that the functions used are the ones provided by the trusted system library. 

- **Memory Integrity Validation**
  - The program verifies the integrity of the memory by comparing the first page of `ntdll.dll` before and after mapping, detecting, and preventing malicious alterations. 

- **Memory Section Isolation**
  - The created section is isolated and modified securely in a way that doesn't impact the original `ntdll.dll` in memory, ensuring safe modifications without system instability. 

## Usage

1. Compile the code with any C++ compiler.
2. Run the executable.
3. The code will:
   - Load `ntdll.dll`
   - Create and map a secure memory section
   - Compare the original and mapped `ntdll.dll` for integrity
   - Perform secure memory modification

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
