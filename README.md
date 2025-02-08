# WannaCry Analysis Report
## Table of Contents
### Executive Summary
### High-Level Technical Summary
### Malware Composition
### First Denotation
### Basic Static Analysis
### Basic Dynamic Analysis
### Advanced Static Analysis
### Advanced Dynamic Analysis
#### 7.1 Analysis of WannaCry.exe
#### 7.2 Analysis of tasksche.exe
### Indicators of Compromise
#### 8.1 Network Indicators
#### 8.2 Host-Based Indicators
### Rules & Signatures
### Appendices
#### 10.1 A. Yara Rules
#### 10.2 B. Callback URLs
#### 10.3 C. Decompiled Code Snippets

## 1.Executive Summary
WannaCry is a notorious ransomware that gained global attention due to its widespread impact. It targets systems by encrypting files with specific extensions, rendering them inaccessible to users. The malware operates in two stages:

Stage One : The initial dropper (wannacry.exe) serves as the entry point. Upon execution, it attempts to connect to a hardcoded domain (http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/). If the connection fails, the malware proceeds to execute its payload.
Stage Two : The secondary component (tasksche.exe) performs the encryption process using a combination of RSA and AES encryption algorithms. This ensures that encrypted files can only be decrypted with a unique private key held by the attackers.
High-Level Technical Summary
Ransomware consists of the following components:

wannacry.exe: The main dropper executable.
tasksche.exe: An executable that generates the encryptor, decryptor.exe, and the encryption keys (e.g., 00000000.pky).
decryptor.exe: An executable that demands payment and prompts the user to enter the key to decrypt files.
00000000.pky: Contains the RSA key, which is itself encrypted.

## 2.Malware Composition
wannacry.exe
None
tasksche.exe
None
decryptor.exe
None
00000000.pky
None

## 3.First Denotation
The wannacry.exe encrypts all data and creates decryptor.exe along with a .txt file to communicate with the user, informing them how to pay.

## 4.Basic Static Analysis
\
#### Strings : The malware contains strings related to file extensions it targets for encryption (e.g., .doc, .pdf, .jpg) and DLLs it uses (e.g., kernel32.dll, USER32.dll).
#### Domains : http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
#### Mutex : "GlobalMsWinZonesCacheCounterMutexA" is used to ensure single-instance execution.
#### IAT Preview : The Import Address Table (IAT) reveals critical APIs used by WannaCry for its functionality:
###### ADVAPI32.dll:
StartServiceCtrlDispatcherA: Registers the malware as a service.
RegisterServiceCtrlHandlerA: Handles service control requests.
OpenSCManagerA: Opens the Service Control Manager (SCM) to create or modify services.
CreateServiceA: Creates a new service for persistence.
StartServiceA: Starts the created service.
###### KERNEL32.dll:
CreateFileA: Opens or creates files for encryption.
ReadFile: Reads data from files.
WriteFile: Writes encrypted data back to files.
GetFileSize: Retrieves the size of files for encryption.
CreateThread: Creates threads for parallel execution of tasks.
TerminateProcess: Terminates processes to evade detection.
GetTickCount: Used for timing checks to detect debugging.
QueryPerformanceCounter: Another timing check for anti-debugging.
###### USER32.dll:
MessageBoxA: Displays ransom notes to the user.
###### CRYPT32.dll:
CryptGenRandom: Generates random numbers for cryptographic operations.
CryptAcquireContextA: Acquires a cryptographic context for encryption.
###### WS2_32.dll:
socket: Creates network sockets for communication.
connect: Connects to remote servers (e.g., for the kill switch domain).
send: Sends data over the network.
recv: Receives data from the network.
## Entropy and Packing : The malware exhibits high entropy, indicating that it is likely packed or obfuscated to evade detection.
Entropy: Overall entropy of the file is 7.96 , which is very high (close to the maximum of 8).
Packed Sections:
.text section has an entropy of 7.96 , indicating it is packed.
.rsrc section has an entropy of 7.27 , suggesting it contains encrypted or compressed resources.

## CAPA Detection : CAPA analysis reveals the following capabilities in the WannaCry malware:
#### Anti-Analysis:
Debugger Detection: Uses GetTickCount and QueryPerformanceCounter to detect debugging environments.
Obfuscated Stack Strings: Employs obfuscated strings to hinder static analysis.
#### Persistence:
Create or Modify System Process: Creates a Windows service for persistence.
Service Execution: Executes malicious code as a service.
#### Execution:
Shared Modules: Loads additional modules for functionality.
Create Thread: Creates threads for parallel execution of tasks.
File System:
Read File: Reads files for encryption.
Move File: Moves files during the encryption process.
Network Communication:
HTTP Communication: Connects to the kill switch domain (http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com).
Socket Communication: Creates TCP/UDP sockets for network communication.
Cryptography:
Generate Pseudo-random Sequence: Uses CryptGenRandom for cryptographic operations.
Encrypt Data: Encrypts files using RSA and AES algorithms.
Basic Dynamic Analysis
Network Activity : The malware attempts to connect to the domain http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com. If the connection fails, it proceeds with the encryption process.
File System Changes : The malware creates files like tasksche.exe and modifies registry keys to bypass proxy settings and treat UNC paths as part of the Local Intranet zone.
Commands Executed :
icacls . /grant Everyone:F /T /C /Q: Grants full control to "Everyone" on the current directory and subdirectories.
attrib +h .: Hides files or directories by setting the hidden attribute.
Advanced Static Analysis
Disassembled Code Analysis : The disassembled code of the main function reveals the malware’s initialization and network communication logic.
Key Observations:
The function starts by initializing variables and setting up the stack.
It loads the hardcoded domain string: http://www.iuqerfsodp9ifjaposdfjhgpsurijfaewrwergwea.com.
The malware uses the InternetOpenA and InternetOpenUrlA functions from the WinINet library to establish a connection to the domain.
If the connection fails, the malware proceeds to execute its payload (encryption routine).
The code includes anti-debugging checks, such as timing delays using GetTickCount and QueryPerformanceCounter.
## Advanced Dynamic Analysis
7.1 Analysis of WannaCry.exe
Process Injection : The malware injects code into processes to evade detection.
File Creation : The malware creates a file named tasksche.exe.
Service Creation : It creates and modifies Windows services for persistence.
Worm Capabilities : The malware exhibits worm-like behavior, enabling it to spread across networks and infect other systems.
7.2 Analysis of tasksche.exe
Generates Two Other Executables : tasksche.exe generates two additional executables as part of its payload.
Generates .wnry Files : It creates multiple files with the .wnry extension, which are used in subsequent stages of the payload.
Encrypts Data and Generates Decryptor.exe : It encrypts the victim’s data, generates decryptor.exe, and changes the desktop wallpaper to display the ransom note.
Indicators of Compromise
8.1 Network Indicators
Domains: http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
8.2 Host-Based Indicators
Registry Changes :
Bypass proxy settings: Modifies proxy settings to bypass restrictions.
Intranet settings: Sets Intranet and UNCAsIntranet to 1, treating UNC paths as part of the Local Intranet zone.
File Creation :
tasksche.exe: Responsible for encryption and generating other .exe and files.
00000000.pky: Contains the encrypted RSA key.
decryptor.exe: Responsible for displaying the Bitcoin wallet address and decrypting files after payment.
Rules & Signatures
A full set of YARA rules is included in Appendix A.

## Appendices
### 10.1 A. Yara Rules

rule Milicious_Domain {
    meta:
        description = "This Rule For detecting the Malicious Domain and IPs In wannacary Rans"
        author = "Salim ABDOUNE"
        date = "2025-02-03"

    strings:
        $domain = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii

    condition:
        $domain

##### 10.1.2 Second Rule

rule DetectAsInvoker {
    meta:
        description = "Detects requestedExecutionLevel set to asInvoker"
        author = "Salim ABDOUNE"
        date = "2025-02-03"

    strings:
        $asInvoker = "<requestedExecutionLevel level=\"asInvoker\" />"

    condition:
        $asInvoker
}
##### 10.1.3 Third Rule

rule ProofOfWannacry {
    meta:
        description = "Detects Wannacry-related file extensions"
        author = "Salim ABDOUNE"
        date = "2025-02-03"

    strings:
        $prof1 = ".wnryO"
        $prof2 = ".wnry"
        $prof3 = ".pky"
        $prof4 = ".eky"

    condition:
        any of ($prof1, $prof2, $prof3, $prof4)
}

### 10.2 B. Callback URLs
http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
80

### 10.3 C. Decompiled Code Snippets
Figure 21: Killswitch Routine in Cutter
