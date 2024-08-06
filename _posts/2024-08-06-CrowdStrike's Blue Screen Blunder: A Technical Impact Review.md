---
title: CrowdStrike Blue Screen Blunder A Technical Impact Review
tags: reverse engineering IDA PRO Crowdstrike falcon windows kernel userland api sesnsor outage crash dump agent analysis BSOD Blue Screen
---

![BSOD](https://github.com/user-attachments/assets/7953d966-61da-4640-9102-821064c042c2)

## overall event background

Starting at 9:09 AM IST on July 19, 2024, India time, users in many places around the world began to report that computers running the Microsoft Windows operating system had a blue screen phenomenon. According to statistics from public reports, so far, this incident has affected banking, aviation, medical and other company services in at least more than 20 countries around the world. More than 21,000 flights around the world have been delayed, and a large number of hospitals have been forced to postpone operations. Business services and public services have been paralyzed. In terms of scope and degree of damage, the impact of this incident has far exceeded the system blue screen incident caused by Symantec in 2007, and has become the largest disaster caused by security products themselves in the past 15 years. event.

After analyzing multiple `Crash Dump` file generated when the blue screen incident occurred as soon as the incident occurred. The direct cause of the incident was the "CSAgent.sys" driver, which belongs to the American network security company CrowdStrike and is its Windows security The core kernel driver component of the product.

## Exclusive impact analysis

From a foreign perspective, relevant countries in Europe and America are the main influencing countries. We focused on statistics on the influence of Asian neighboring countries. details as follows:

## Exclusive impact analysis

From a foreign perspective, relevant countries in Europe and America are the main influencing countries. We focused on statistics on the influence of Asian neighboring countries. details as follows:

![2](https://github.com/user-attachments/assets/71e6ade2-6d17-4eb2-a1f0-87de57c1b223)

## Restoration of technical details

Nearly two weeks have passed since the incident occurred, and CrowdStrike, other domestic and foreign security manufacturers and research institutions have not provided detailed technical analysis. After the incident, we collected multiple `Crash Dumps` and Agent exe perspective to obtain first-hand comprehensive information, conduct in-depth analysis, and restore the details of the entire incident. We are disclosing some technical details to make a modest contribution to avoid the recurrence of similar accidents and promote the development of the domestic safety industry.

### 1.Crash scene information

We observed that multiple versions of the CrowdStrike probe driver caused crashes. Judging from the monitored crash data, 75% of the crash increments are concentrated at the offset 0xe14ed of the CrowdStrike Windows version probe 7.15.18513.0.

![3](https://github.com/user-attachments/assets/e7dd49e8-cbf3-400c-a742-fe78593c5305)

But this crash exists in 7.16.18605.0 and even newer versions. It can be seen that it is not caused by the upgrade of the CSAgent.sys driver file itself.

Judging from a DUMP file related to 7.15.18513.0, the direct cause of the crash is an invalid address access at the CSAgent+0xe14ed offset. It can be seen that the memory pointed to by the r8 register is invalid at this time.

![4](https://github.com/user-attachments/assets/9a1ea3b1-a4f0-44ab-9c81-4dd8da0e2c5e)

By reading the disassembly code at the CSAgent(7.15.18513.0)+0xe14ed offset, as shown in the figure below.

![5](https://github.com/user-attachments/assets/7e7751ee-2b80-4c68-a973-a2c10fe50dad)


As you can see, the previous instruction is to determine whether the address pointed to by r8 is empty. The direct cause of this blue screen is actually an index out-of-bounds access (OOB Read) caused by `mov r8 qword[rax+r11*8]`.

### 2. Introduction to the CrowdStrike Directory

CrowdStrike files are mainly located in the two directories `C:\Program Files\CrowdStrike` and `C:\Windows\System32\drivers\CrowdStrike`. Among them, `C:\Program Files\CrowdStrike` contains user mode components, background services, scanning tools and tray components.

![6](https://github.com/user-attachments/assets/92a62152-6d48-4cc6-8229-ed316c8eff42)

The `\SystemRoot\Drivers\CrowdeStrike` directory contains CrowdeStrike's kernel driver and rule files.

![7](https://github.com/user-attachments/assets/a4ee78ac-9723-4d1e-b22e-00f67fbd5cb5)

### 3. Core component analysis

CSAgent.sys is the core component of the CrowdStrike Windows version probe. It is a very large driver and can be regarded as a collection of multiple protection drivers. Taking version 7.16.18605.0 as an example, the compiled file size reaches 4.28 MB, and IDAPro automatically recognizes 10816 functions, which shows the complexity of its functions. Its main functions include:

(1) Implemented a rule engine based on a custom virtual machine;
(2) Kernel network communication based on kernel socket;
(3) Implemented the encryption algorithm of the commonly used TLS protocol;
(4) Based on 2 and 3, complete HTTPS protocol communication is implemented;
(5) Implemented HTTP proxy protocol;
(6) Implemented complete X509 certificate format analysis;
(7) Implemented online query of certificate revocation list to check the validity of certificates and CAs;
(8) File filtering based on minifilter is implemented. The 291 rule of this blue screen is to handle named pipe events;
(9) Implemented WFP-based network event filtering, DNS redirection and RPC interception;
(10) In the kernel, 15 iocp-based queues are created to implement asynchronous processing of events;
(11) Implemented three sets of trace mechanisms based on ETW, WMI, and Clfs, and supported HTTPS transmission of telemetry logs;
(12) Implemented performance monitoring based on CPU performance counters.

### 4. Kernel dynamically loads driver

`CSAgent.sys` calls `nt!ZwSetSystemInformation` to realize the kernel's ability to load and unload drivers.

![8](https://github.com/user-attachments/assets/440a6578-a324-49fc-948c-9fff96865408)

It is worth mentioning that there are two uses of `nt!ZwSetSystemInformation` in `CSAgent.sys`. Although they are both loaded into the kernel, their purposes are different.

In `csagent+0x5a468`, it is to dynamically load new function modules. After loading, the `DriverEntry` of the loaded module is directly called. For files such as `Osfm-00000001.bin`, although they are also loaded into the kernel, their entry points are not called. Instead, the content at the entry is parsed as rule data. The format will be explained in detail later.

### 5. Firmware check

Osfm represents operating system firmware, and takes the format of `Osfm-%08U.bin` as the file name, where Osfm represents operating system firmware. Describes the path to the key file (what CrowdStrike calls firmware) that needs to be checked.

Although the file appears to be a data configuration file, when opened with a binary editor, it can be seen that it is a PE file.

![9](https://github.com/user-attachments/assets/5000fc63-c78e-4370-93b7-e952037282de)

Through subsequent analysis, it was found that the content of the drive entry point is rule data. The developer of CrowdStrike has an interesting approach: it looks like a driver, but it is actually a rule, such as `C-00000001-00000000-00000025.sys`; it looks like a data file, but it is actually a driver, such as `Osfm-00000001.bin `. Its format is as follows:

![10](https://github.com/user-attachments/assets/0941a207-59c2-4c6a-8a80-47aa4313ca36)

The main body of the Osfm file is a standard PE file, but the OEP points to rule data instead of code.

(1) `string_count` in the rule header indicates the number of strings in the attached string table;

(2) `string_array` in the rule body indicates the location of the string table. Note that the value of `string_array` in the file here is not the file offset, but the virtual address.  

After being loaded into memory, it will be automatically corrected to the actual address by Image Loader due to the existence of the relocation table. When parsing in a file, just calculate its actual file offset by RVA2FOA. Each element in the string table is also a virtual address, and the actual string can be read by calculating the actual file offset. Each string is the path to a key file that needs to be checked.

`CSAgent.sys` will automatically find the latest `Osfm-*.bin` file in the CrowdStrike directory, read its version information in the `OSFM-%08u.bin` format, load the latest one, and automatically delete the previous file. Old files whose modification time was 1 day ago.

### 6. Key file analysis (C-%08U-%08U-%08U.sys file format)

Although the file named `C-00000001-00000000-00000025.sys` has a `.sys` extension, it is not actually a kernel driver file, but a rule file used by `CSAgent.sys`. As shown in the figure, there are no MZ and PE headers required for the executable file.

![11](https://github.com/user-attachments/assets/4e0f55fe-5ce2-45c3-bd79-07e1354e9b39)

Its file format is divided into three layers. The first layer is a fixed file header with the following format.

![12](https://github.com/user-attachments/assets/f941e698-6330-495b-93ab-373b21846a5c)

Among them, `magic` is fixed to `0xAAAAAAA`, `channel`, `part2` and `part3` are the three numbers in `C-00000291-00000000-00000009`, indicating the channel and version of the application. `kind` is regular Subtype.

The format of the second layer is that the file skips the remaining part of the first layer file header. The second layer format of the rules is block-based, with each block header occupying 8 bytes. File format and memory format share the same data structure.

![13](https://github.com/user-attachments/assets/60ecdcd1-011c-4bf9-83ba-ec367b584d47)

When in the file, the `next_block_data_offset` of the block header indicates the offset of the next block, `block_size` is the total size of the current block, if `block_size` is 0, it means this is the last block. The data area of ​​the current block needs to contain `nBlockSize` minus 8 bytes, which is the size of the block header. After being loaded into memory, the 8 bytes of the block header will be modified into a pointer directly pointing to the next block data area, forming a one-way linked list. The Layer 3 format is built on this logically continuous singly linked list.

The format of the third layer varies according to the rule subtype in the first layer file header, and contains the actual rule data.

In addition to loading rules from files, `CSAgent.sys` also reads and writes rule data from the registry. For example, after downloading a new device control rule file from `CSAgent.sys` and reading and parsing it, the rule data after removing the first layer of rule headers will be rewritten into the registry, and then read out from the registry again. Do the rest of the parsing. Why do we need to write a registry here? It is because it can be used by the device management `CSDeviceControl.sys` when the system is restarted.

We re-examined the cause of the blue screen. `CSAgent.sys` implements a custom virtual machine engine, similar to the ebpf of the Linux kernel, and its entry is `CSAgent+0xbfd48`. Load the third-layer rule data of the rules obtained through each channel. In addition to the necessary headers, the main body is the virtual bytecode to be executed.

After analyzing the rule format and virtual machine instructions, you can understand what the blue screen point `CSAgent+0xe3b58` is doing. The processing of the blue screen is actually to interpret the error opcode contained in the execution of `C-00000291-00000000-00000009.sys`.

## Re-examining the causes of blue screens

It is worth mentioning that recently there is an analysis circulating on foreign websites that this incident was just a denial of service caused by zero address access. The analysis received hundreds of thousands of likes and comments, but the claim is factually incorrect.

Through the analysis, the direct cause of the blue screen is actually the OOB Read during opcode verification. Although it seems that the memory cannot be directly controlled here, the virtual machine engine of `CSAgent.sys` is actually Turing-complete. , just like the Dequ virus that uses the font virtual machine in atmfd.dll, it can use specific exploitation techniques to completely control the external (i.e., operating system kernel) memory, and then obtain code execution permissions. **Therefore, after in-depth analysis, we found that the conditions for LPE or RCE vulnerabilities are actually met here.**

(1) The source of its input content is the `C-00000291-00000000-00000009.sys` file, and there is no signature mechanism;

(2) `CrowdStrike` lacks a self-protection mechanism and can read and write the `C-00000291-00000000-00000009.sys` file at will;

(3) `C-00000291-00000000-00000009.sys` itself is directly downloaded from the Internet by `CSAgent.sys`;

(4) `CSAgent.sys` supports reading the proxy from IE AutoProxy out of the network.

Therefore, if you have gateway permissions, or modify the proxy settings of IE, and hijack the distribution of `C-00000291-00000000-00000009.sys`, you can obtain the host kernel permissions, thereby causing deeper harm.







