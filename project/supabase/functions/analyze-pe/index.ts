import { createClient } from "npm:@supabase/supabase-js@2.111.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

// ---------------------------------------------------------------------------
// Suspicious API database — each entry maps an import name to a category and
// short description explaining why it is interesting from a malware-analysis
// perspective.
// ---------------------------------------------------------------------------
const SUSPICIOUS_APIS: Record<string, { category: string; description: string; weight: number }> = {
  // Process / memory
  "CreateProcess": { category: "Process Injection", description: "Spawns or injects into another process.", weight: 8 },
  "CreateProcessA": { category: "Process Injection", description: "Spawns or injects into another process.", weight: 8 },
  "CreateProcessW": { category: "Process Injection", description: "Spawns or injects into another process.", weight: 8 },
  "CreateRemoteThread": { category: "Process Injection", description: "Executes code in the context of another process.", weight: 10 },
  "CreateRemoteThreadEx": { category: "Process Injection", description: "Executes code in the context of another process.", weight: 10 },
  "VirtualAllocEx": { category: "Memory Manipulation", description: "Allocates memory in a remote process — classic injection primitive.", weight: 9 },
  "WriteProcessMemory": { category: "Memory Manipulation", description: "Writes data into a remote process's memory.", weight: 10 },
  "ReadProcessMemory": { category: "Memory Manipulation", description: "Reads memory from another process — credential theft.", weight: 8 },
  "OpenProcess": { category: "Process Manipulation", description: "Obtains a handle to another process.", weight: 5 },
  "NtUnmapViewOfSection": { category: "Process Hollowing", description: "Unmaps a section — used in process hollowing.", weight: 9 },
  "ZwUnmapViewOfSection": { category: "Process Hollowing", description: "Unmaps a section — used in process hollowing.", weight: 9 },
  "SetThreadContext": { category: "Process Manipulation", description: "Modifies thread context — injection / hollowing.", weight: 8 },
  "GetThreadContext": { category: "Process Manipulation", description: "Reads thread context — injection / hollowing.", weight: 6 },
  "ResumeThread": { category: "Process Manipulation", description: "Resumes a suspended thread — injection completion.", weight: 6 },
  "SuspendThread": { category: "Process Manipulation", description: "Suspends a thread — process hollowing setup.", weight: 5 },
  // DLL loading
  "LoadLibrary": { category: "DLL Loading", description: "Dynamically loads a DLL.", weight: 4 },
  "LoadLibraryA": { category: "DLL Loading", description: "Dynamically loads a DLL.", weight: 4 },
  "LoadLibraryW": { category: "DLL Loading", description: "Dynamically loads a DLL.", weight: 4 },
  "LoadLibraryEx": { category: "DLL Loading", description: "Dynamically loads a DLL with flags.", weight: 4 },
  "LoadLibraryExA": { category: "DLL Loading", description: "Dynamically loads a DLL with flags.", weight: 4 },
  "LoadLibraryExW": { category: "DLL Loading", description: "Dynamically loads a DLL with flags.", weight: 4 },
  "GetProcAddress": { category: "API Resolution", description: "Resolves function addresses — often used to hide imports.", weight: 5 },
  "LdrLoadDll": { category: "DLL Loading", description: "Low-level DLL loading — ntdll primitive.", weight: 7 },
  // Hooking / injection
  "SetWindowsHookEx": { category: "Hooking", description: "Installs a global hook — DLL injection vector.", weight: 8 },
  "SetWindowsHookExA": { category: "Hooking", description: "Installs a global hook — DLL injection vector.", weight: 8 },
  "SetWindowsHookExW": { category: "Hooking", description: "Installs a global hook — DLL injection vector.", weight: 8 },
  // Networking
  "WSAStartup": { category: "Networking", description: "Initializes Winsock — network communication.", weight: 3 },
  "socket": { category: "Networking", description: "Creates a network socket.", weight: 3 },
  "connect": { category: "Networking", description: "Connects to a remote host — possible C2.", weight: 4 },
  "send": { category: "Networking", description: "Sends data over a socket.", weight: 3 },
  "recv": { category: "Networking", description: "Receives data over a socket.", weight: 3 },
  "InternetOpen": { category: "Networking", description: "Initializes WinINet — HTTP/FTP communication.", weight: 4 },
  "InternetOpenA": { category: "Networking", description: "Initializes WinINet — HTTP/FTP communication.", weight: 4 },
  "InternetOpenW": { category: "Networking", description: "Initializes WinINet — HTTP/FTP communication.", weight: 4 },
  "InternetOpenUrl": { category: "Networking", description: "Opens a URL — downloader behavior.", weight: 6 },
  "InternetOpenUrlA": { category: "Networking", description: "Opens a URL — downloader behavior.", weight: 6 },
  "InternetOpenUrlW": { category: "Networking", description: "Opens a URL — downloader behavior.", weight: 6 },
  "URLDownloadToFile": { category: "Networking", description: "Downloads a file from a URL — downloader/dropper.", weight: 9 },
  "URLDownloadToFileA": { category: "Networking", description: "Downloads a file from a URL — downloader/dropper.", weight: 9 },
  "URLDownloadToFileW": { category: "Networking", description: "Downloads a file from a URL — downloader/dropper.", weight: 9 },
  "WinHttpOpen": { category: "Networking", description: "Initializes WinHTTP — modern C2 transport.", weight: 5 },
  "WinHttpConnect": { category: "Networking", description: "Connects to a remote server over WinHTTP.", weight: 5 },
  "WinHttpSendRequest": { category: "Networking", description: "Sends an HTTP request — C2 beaconing.", weight: 5 },
  // File system
  "CreateFile": { category: "File System", description: "Opens or creates a file.", weight: 2 },
  "CreateFileA": { category: "File System", description: "Opens or creates a file.", weight: 2 },
  "CreateFileW": { category: "File System", description: "Opens or creates a file.", weight: 2 },
  "WriteFile": { category: "File System", description: "Writes data to a file — dropper payload.", weight: 3 },
  "DeleteFile": { category: "File System", description: "Deletes a file — cleanup / anti-forensics.", weight: 3 },
  "DeleteFileA": { category: "File System", description: "Deletes a file — cleanup / anti-forensics.", weight: 3 },
  "DeleteFileW": { category: "File System", description: "Deletes a file — cleanup / anti-forensics.", weight: 3 },
  "MoveFile": { category: "File System", description: "Moves or renames a file.", weight: 2 },
  "MoveFileA": { category: "File System", description: "Moves or renames a file.", weight: 2 },
  "MoveFileW": { category: "File System", description: "Moves or renames a file.", weight: 2 },
  "CopyFile": { category: "File System", description: "Copies a file — propagation.", weight: 2 },
  "CopyFileA": { category: "File System", description: "Copies a file — propagation.", weight: 2 },
  "CopyFileW": { category: "File System", description: "Copies a file — propagation.", weight: 2 },
  "SetFileAttributes": { category: "File System", description: "Changes file attributes — stealth (hidden/system).", weight: 4 },
  "SetFileAttributesA": { category: "File System", description: "Changes file attributes — stealth (hidden/system).", weight: 4 },
  "SetFileAttributesW": { category: "File System", description: "Changes file attributes — stealth (hidden/system).", weight: 4 },
  "FindFirstFile": { category: "File System", description: "Enumerates files — ransomware / worm propagation.", weight: 3 },
  "FindFirstFileA": { category: "File System", description: "Enumerates files — ransomware / worm propagation.", weight: 3 },
  "FindFirstFileW": { category: "File System", description: "Enumerates files — ransomware / worm propagation.", weight: 3 },
  "FindNextFile": { category: "File System", description: "Continues file enumeration.", weight: 2 },
  "FindNextFileA": { category: "File System", description: "Continues file enumeration.", weight: 2 },
  "FindNextFileW": { category: "File System", description: "Continues file enumeration.", weight: 2 },
  // Registry
  "RegCreateKey": { category: "Registry", description: "Creates a registry key — persistence.", weight: 5 },
  "RegCreateKeyA": { category: "Registry", description: "Creates a registry key — persistence.", weight: 5 },
  "RegCreateKeyW": { category: "Registry", description: "Creates a registry key — persistence.", weight: 5 },
  "RegSetValue": { category: "Registry", description: "Sets a registry value — persistence / config.", weight: 5 },
  "RegSetValueA": { category: "Registry", description: "Sets a registry value — persistence / config.", weight: 5 },
  "RegSetValueW": { category: "Registry", description: "Sets a registry value — persistence / config.", weight: 5 },
  "RegSetValueEx": { category: "Registry", description: "Sets a registry value — persistence / config.", weight: 5 },
  "RegSetValueExA": { category: "Registry", description: "Sets a registry value — persistence / config.", weight: 5 },
  "RegSetValueExW": { category: "Registry", description: "Sets a registry value — persistence / config.", weight: 5 },
  "RegOpenKey": { category: "Registry", description: "Opens a registry key.", weight: 3 },
  "RegOpenKeyA": { category: "Registry", description: "Opens a registry key.", weight: 3 },
  "RegOpenKeyW": { category: "Registry", description: "Opens a registry key.", weight: 3 },
  "RegDeleteKey": { category: "Registry", description: "Deletes a registry key — cleanup.", weight: 3 },
  "RegDeleteValue": { category: "Registry", description: "Deletes a registry value — cleanup.", weight: 3 },
  // Service / privilege
  "OpenSCManager": { category: "Service", description: "Connects to the service control manager — service persistence.", weight: 6 },
  "CreateService": { category: "Service", description: "Creates a Windows service — persistence.", weight: 7 },
  "CreateServiceA": { category: "Service", description: "Creates a Windows service — persistence.", weight: 7 },
  "CreateServiceW": { category: "Service", description: "Creates a Windows service — persistence.", weight: 7 },
  "StartService": { category: "Service", description: "Starts a service.", weight: 4 },
  "StartServiceA": { category: "Service", description: "Starts a service.", weight: 4 },
  "StartServiceW": { category: "Service", description: "Starts a service.", weight: 4 },
  "AdjustTokenPrivileges": { category: "Privilege Escalation", description: "Enables privileges — privilege escalation.", weight: 7 },
  "LookupPrivilegeValue": { category: "Privilege Escalation", description: "Looks up privilege LUID — privilege escalation.", weight: 5 },
  "OpenProcessToken": { category: "Privilege Escalation", description: "Opens a process token — privilege manipulation.", weight: 5 },
  "ImpersonateLoggedOnUser": { category: "Privilege Escalation", description: "Impersonates a user — token impersonation.", weight: 7 },
  "DuplicateTokenEx": { category: "Privilege Escalation", description: "Duplicates a token — privilege escalation.", weight: 7 },
  // Crypto
  "CryptAcquireContext": { category: "Cryptography", description: "Acquires a crypto context — encryption / ransomware.", weight: 5 },
  "CryptAcquireContextA": { category: "Cryptography", description: "Acquires a crypto context — encryption / ransomware.", weight: 5 },
  "CryptAcquireContextW": { category: "Cryptography", description: "Acquires a crypto context — encryption / ransomware.", weight: 5 },
  "CryptEncrypt": { category: "Cryptography", description: "Encrypts data — ransomware payload.", weight: 7 },
  "CryptDecrypt": { category: "Cryptography", description: "Decrypts data — payload decryption.", weight: 6 },
  "CryptDeriveKey": { category: "Cryptography", description: "Derives a key from a password.", weight: 5 },
  "BCryptEncrypt": { category: "Cryptography", description: "CNG encryption — ransomware payload.", weight: 7 },
  "BCryptDecrypt": { category: "Cryptography", description: "CNG decryption — payload decryption.", weight: 6 },
  // Anti-analysis
  "IsDebuggerPresent": { category: "Anti-Analysis", description: "Checks for an attached debugger.", weight: 7 },
  "CheckRemoteDebuggerPresent": { category: "Anti-Analysis", description: "Checks for a remote debugger.", weight: 7 },
  "OutputDebugString": { category: "Anti-Analysis", description: "Used in debugger detection timing tricks.", weight: 4 },
  "NtSetInformationThread": { category: "Anti-Analysis", description: "Hides a thread from debuggers.", weight: 7 },
  "NtQueryInformationProcess": { category: "Anti-Analysis", description: "Queries process debug flags.", weight: 6 },
  "NtQuerySystemInformation": { category: "Anti-Analysis", description: "Queries system info — debug / sandbox detection.", weight: 5 },
  // Shellcode / execution
  "VirtualAlloc": { category: "Memory Manipulation", description: "Allocates executable memory — shellcode staging.", weight: 6 },
  "VirtualProtect": { category: "Memory Manipulation", description: "Changes memory protection — W^X bypass / shellcode.", weight: 7 },
  "VirtualProtectEx": { category: "Memory Manipulation", description: "Changes protection in a remote process.", weight: 8 },
  "HeapCreate": { category: "Memory Manipulation", description: "Creates a heap — heap-based payload staging.", weight: 3 },
  // Misc
  "ShellExecute": { category: "Execution", description: "Executes a command via the shell.", weight: 5 },
  "ShellExecuteA": { category: "Execution", description: "Executes a command via the shell.", weight: 5 },
  "ShellExecuteW": { category: "Execution", description: "Executes a command via the shell.", weight: 5 },
  "WinExec": { category: "Execution", description: "Runs a command — legacy execution primitive.", weight: 6 },
  "system": { category: "Execution", description: "Runs a shell command — command execution.", weight: 7 },
  "CreateThread": { category: "Thread Creation", description: "Creates a thread — shellcode / payload execution.", weight: 5 },
  "ExitProcess": { category: "Process Control", description: "Terminates the process.", weight: 2 },
  "TerminateProcess": { category: "Process Control", description: "Terminates a process — anti-analysis / sabotage.", weight: 4 },
  "Sleep": { category: "Anti-Analysis", description: "Delays execution — sandbox evasion via long sleeps.", weight: 4 },
  "GetTickCount": { category: "Anti-Analysis", description: "Timing-based sandbox detection.", weight: 4 },
  "QueryPerformanceCounter": { category: "Anti-Analysis", description: "High-resolution timing — sandbox detection.", weight: 4 },
  "GetModuleHandle": { category: "API Resolution", description: "Gets a loaded module handle.", weight: 3 },
  "GetModuleHandleA": { category: "API Resolution", description: "Gets a loaded module handle.", weight: 3 },
  "GetModuleHandleW": { category: "API Resolution", description: "Gets a loaded module handle.", weight: 3 },
};

// ---------------------------------------------------------------------------
// PE constant tables
// ---------------------------------------------------------------------------
const MACHINE_TYPES: Record<number, string> = {
  0x014c: "x86 (32-bit)",
  0x0200: "Intel Itanium",
  0x8664: "x64 (64-bit)",
  0x01c0: "ARM (32-bit)",
  0xaa64: "ARM64 (64-bit)",
  0x01d3: "AM33",
  0x0284: "Alpha",
  0x0366: "Alpha 64",
  0x0ebc: "EFI Byte Code",
  0x9041: "M32R",
  0x1c2: "Thumb",
  0x169: "MIPS16",
  0x266: "MIPS FPU",
  0x366: "MIPS16 FPU",
  0x466: "PowerPC",
  0xebc: "EFI Byte Code",
};

const SUBSYSTEMS: Record<number, string> = {
  0: "Unknown",
  1: "Native",
  2: "Windows GUI",
  3: "Windows Console",
  5: "OS/2 Character",
  7: "Posix Character",
  8: "Native Windows",
  9: "Windows CE GUI",
  10: "EFI Application",
  11: "EFI Boot Service Driver",
  12: "EFI Runtime Driver",
  13: "EFI ROM",
  14: "XBOX",
  16: "Windows Boot Application",
};

const SECTION_FLAGS: Record<number, string> = {
  0x00000020: "CODE",
  0x00000040: "INITIALIZED_DATA",
  0x00000080: "UNINITIALIZED_DATA",
  0x02000000: "DISCARDABLE",
  0x10000000: "SHARED",
  0x20000000: "EXECUTE",
  0x40000000: "READ",
  0x80000000: "WRITE",
};

const DLL_CHARACTERISTICS_FLAGS: Record<number, string> = {
  0x0020: "HIGH_ENTROPY_VA",
  0x0040: "DYNAMIC_BASE (ASLR)",
  0x0080: "FORCE_INTEGRITY",
  0x0100: "NX_COMPAT (DEP)",
  0x0200: "NO_ISOLATION",
  0x0400: "NO_SEH",
  0x0800: "NO_BIND",
  0x1000: "APPCONTAINER",
  0x2000: "WDM_DRIVER",
  0x4000: "GUARD_CF",
  0x8000: "TERMINAL_SERVER_AWARE",
};

const PE_CHARACTERISTICS_FLAGS: Record<number, string> = {
  0x0001: "RELOCS_STRIPPED",
  0x0002: "EXECUTABLE_IMAGE",
  0x0004: "LINE_NUMS_STRIPPED",
  0x0008: "LOCAL_SYMS_STRIPPED",
  0x0010: "AGGRESSIVE_WS_TRIM",
  0x0020: "LARGE_ADDRESS_AWARE",
  0x0080: "BYTES_REVERSED_LO",
  0x0100: "32BIT_MACHINE",
  0x0200: "DEBUG_STRIPPED",
  0x0400: "REMOVABLE_RUN_FROM_SWAP",
  0x0800: "NET_RUN_FROM_SWAP",
  0x1000: "SYSTEM",
  0x2000: "DLL",
  0x4000: "UP_SYSTEM_ONLY",
  0x8000: "BYTES_REVERSED_HI",
};

// ---------------------------------------------------------------------------
// Binary helpers
// ---------------------------------------------------------------------------
function readU16(buf: Uint8Array, off: number, le = true): number {
  const dv = new DataView(buf.buffer, buf.byteOffset + off, 2);
  return le ? dv.getUint16(0, true) : dv.getUint16(0, false);
}
function readU32(buf: Uint8Array, off: number, le = true): number {
  const dv = new DataView(buf.buffer, buf.byteOffset + off, 4);
  return le ? dv.getUint32(0, true) : dv.getUint32(0, false);
}

function flagsToList(flags: number, table: Record<number, string>): string[] {
  const out: string[] = [];
  for (const [bit, name] of Object.entries(table)) {
    if (flags & Number(bit)) out.push(name);
  }
  return out;
}

function decodeAscii(buf: Uint8Array, start: number, maxLen: number): string {
  let s = "";
  for (let i = 0; i < maxLen; i++) {
    const b = buf[start + i];
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s;
}

function decodeUtf16LE(buf: Uint8Array, start: number, maxBytes: number): string {
  let s = "";
  for (let i = 0; i + 1 < maxBytes; i += 2) {
    const code = buf[start + i] | (buf[start + i + 1] << 8);
    if (code === 0) break;
    s += String.fromCharCode(code);
  }
  return s;
}

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------
function shannonEntropy(buf: Uint8Array, start: number, end: number): number {
  const len = end - start;
  if (len <= 0) return 0;
  const counts = new Array(256).fill(0);
  for (let i = start; i < end; i++) counts[buf[i]]++;
  let entropy = 0;
  for (let c = 0; c < 256; c++) {
    if (counts[c] === 0) continue;
    const p = counts[c] / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

// ---------------------------------------------------------------------------
// PE parsing
// ---------------------------------------------------------------------------
interface ParsedImport {
  dll: string;
  functions: string[];
}
interface SuspiciousApi {
  name: string;
  dll: string;
  category: string;
  description: string;
  weight: number;
}
interface PeSection {
  name: string;
  virtual_size: number;
  virtual_address: number;
  raw_size: number;
  raw_offset: number;
  entropy: number;
  flags: string[];
}
interface PeMetadata {
  machine: string;
  machine_raw: number;
  number_of_sections: number;
  timestamp: number;
  timestamp_human: string | null;
  entry_point: number;
  image_base: number;
  subsystem: string;
  subsystem_raw: number;
  characteristics: string[];
  dll_characteristics: string[];
  is_dll: boolean;
  is_64bit: boolean;
  size_of_image: number;
  size_of_headers: number;
}
interface CfgNode {
  id: string;
  label: string;
  type: string;
}
interface CfgEdge {
  from: string;
  to: string;
}
interface CfgData {
  nodes: CfgNode[];
  edges: CfgEdge[];
  node_count: number;
  edge_count: number;
  density: number;
  entry: string | null;
}

interface AnalysisResult {
  metadata: PeMetadata;
  imports: ParsedImport[];
  suspicious_apis: SuspiciousApi[];
  strings: { value: string; length: number; category: string }[];
  sections: PeSection[];
  cfg: CfgData;
  risk_score: number;
  risk_level: string;
}

function parsePE(buf: Uint8Array): AnalysisResult {
  // DOS header
  if (buf.length < 0x40 || readU16(buf, 0) !== 0x5a4d) {
    throw new Error("Not a valid PE file (missing MZ signature).");
  }
  const e_lfanew = readU32(buf, 0x3c);
  if (e_lfanew + 24 > buf.length) throw new Error("Invalid PE header offset.");

  // PE signature
  if (readU32(buf, e_lfanew) !== 0x00004550) {
    throw new Error("Not a valid PE file (missing PE signature).");
  }

  const coffOff = e_lfanew + 4;
  const machine = readU16(buf, coffOff);
  const numberOfSections = readU16(buf, coffOff + 2);
  const timestamp = readU32(buf, coffOff + 4);
  const sizeOfOptionalHeader = readU16(buf, coffOff + 16);
  const characteristics = readU16(buf, coffOff + 18);
  const optOff = coffOff + 20;

  const magic = readU16(buf, optOff);
  const is64 = magic === 0x20b;
  const isDll = (characteristics & 0x2000) !== 0;

  // Optional header fields
  const entryPoint = readU32(buf, optOff + 16);
  const imageBase = is64 ? Number(readU32(buf, optOff + 24)) /* low 32 */ : readU32(buf, optOff + 28);
  const sizeOfImage = readU32(buf, optOff + 56);
  const sizeOfHeaders = readU32(buf, optOff + 60);
  const subsystem = readU16(buf, optOff + 68);
  const dllCharacteristics = readU16(buf, optOff + 70);

  const timestampDate = timestamp ? new Date(timestamp * 1000).toISOString() : null;

  const metadata: PeMetadata = {
    machine: MACHINE_TYPES[machine] || `Unknown (0x${machine.toString(16)})`,
    machine_raw: machine,
    number_of_sections: numberOfSections,
    timestamp,
    timestamp_human: timestampDate,
    entry_point: entryPoint,
    image_base: imageBase,
    subsystem: SUBSYSTEMS[subsystem] || `Unknown (${subsystem})`,
    subsystem_raw: subsystem,
    characteristics: flagsToList(characteristics, PE_CHARACTERISTICS_FLAGS),
    dll_characteristics: flagsToList(dllCharacteristics, DLL_CHARACTERISTICS_FLAGS),
    is_dll: isDll,
    is_64bit: is64,
    size_of_image: sizeOfImage,
    size_of_headers: sizeOfHeaders,
  };

  // Section headers
  const sectionTableOff = optOff + sizeOfOptionalHeader;
  const sections: PeSection[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const off = sectionTableOff + i * 40;
    if (off + 40 > buf.length) break;
    const name = decodeAscii(buf, off, 8).replace(/\u0000/g, "").trim();
    const virtualSize = readU32(buf, off + 8);
    const virtualAddress = readU32(buf, off + 12);
    const rawSize = readU32(buf, off + 16);
    const rawOffset = readU32(buf, off + 20);
    const flags = readU32(buf, off + 36);
    const secStart = rawOffset;
    const secEnd = Math.min(rawOffset + rawSize, buf.length);
    const entropy = shannonEntropy(buf, secStart, secEnd);
    sections.push({
      name: name || `.sec${i}`,
      virtual_size: virtualSize,
      virtual_address: virtualAddress,
      raw_size: rawSize,
      raw_offset: rawOffset,
      entropy,
      flags: flagsToList(flags, SECTION_FLAGS),
    });
  }

  // Import table (ILT/IAT walk)
  const imports: ParsedImport[] = [];
  const suspicious: SuspiciousApi[] = [];

  // Data directories: import dir is index 1
  const dataDirOff = optOff + (is64 ? 112 : 96);
  const importDirRva = readU32(buf, dataDirOff + 8);
  const importDirSize = readU32(buf, dataDirOff + 12);

  if (importDirRva !== 0 && importDirSize !== 0) {
    const importDescOff = rvaToOffset(importDirRva, sections);
    if (importDescOff !== -1) {
      let descIdx = 0;
      while (true) {
        const descOff = importDescOff + descIdx * 20;
        if (descOff + 20 > buf.length) break;
        const oftRva = readU32(buf, descOff); // OriginalFirstThunk (ILT)
        const nameRva = readU32(buf, descOff + 12);
        const ftRva = readU32(buf, descOff + 16); // FirstThunk (IAT)
        if (oftRva === 0 && nameRva === 0 && ftRva === 0) break;

        const nameOff = rvaToOffset(nameRva, sections);
        let dllName = "unknown";
        if (nameOff !== -1) dllName = decodeAscii(buf, nameOff, 256).toLowerCase();

        const thunkBase = oftRva !== 0 ? oftRva : ftRva;
        const thunkOff = rvaToOffset(thunkBase, sections);
        const funcs: string[] = [];
        if (thunkOff !== -1) {
          let t = 0;
          const thunkSize = is64 ? 8 : 4;
          while (true) {
            const tOff = thunkOff + t * thunkSize;
            if (tOff + thunkSize > buf.length) break;
            let val: number;
            let ordinalFlag: number;
            if (is64) {
              // Can't read full 64-bit with DataView; read low 32 — enough for RVA.
              val = readU32(buf, tOff);
              ordinalFlag = 0x80000000;
            } else {
              val = readU32(buf, tOff);
              ordinalFlag = 0x80000000;
            }
            if (val === 0) break;
            if (val & ordinalFlag) {
              funcs.push(`Ordinal_${val & 0xffff}`);
            } else {
              const hintOff = rvaToOffset(val, sections);
              if (hintOff !== -1) {
                const fname = decodeAscii(buf, hintOff + 2, 256).replace(/\u0000/g, "");
                if (fname) funcs.push(fname);
              }
            }
            t++;
          }
        }
        imports.push({ dll: dllName, functions: funcs });

        for (const fn of funcs) {
          const entry = SUSPICIOUS_APIS[fn];
          if (entry) {
            suspicious.push({
              name: fn,
              dll: dllName,
              category: entry.category,
              description: entry.description,
              weight: entry.weight,
            });
          }
        }
        descIdx++;
      }
    }
  }

  // String extraction
  const strings = extractStrings(buf);

  // Build a simplified CFG from the section + import structure
  const cfg = buildCfg(sections, imports, suspicious, entryPoint);

  // Risk score
  const { risk_score, risk_level } = computeRisk({
    suspicious,
    sections,
    metadata,
    strings,
    imports,
  });

  return {
    metadata,
    imports,
    suspicious_apis: suspicious,
    strings,
    sections,
    cfg,
    risk_score,
    risk_level,
  };
}

function rvaToOffset(rva: number, sections: PeSection[]): number {
  for (const s of sections) {
    if (rva >= s.virtual_address && rva < s.virtual_address + Math.max(s.virtual_size, s.raw_size)) {
      return s.raw_offset + (rva - s.virtual_address);
    }
  }
  return -1;
}

interface StringResult {
  value: string;
  length: number;
  category: string;
}

function extractStrings(buf: Uint8Array): StringResult[] {
  const results: StringResult[] = [];
  const minLen = 5;
  const maxResults = 400;

  // ASCII strings
  let start = 0;
  for (let i = 0; i < buf.length && results.length < maxResults; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) continue;
    if (b === 0x09 || b === 0x0a || b === 0x0d) continue;
    const len = i - start;
    if (len >= minLen) {
      const s = decodeAscii(buf, start, len);
      const cat = classifyString(s);
      if (cat !== "junk") {
        results.push({ value: s, length: s.length, category: cat });
      }
    }
    start = i + 1;
  }

  // UTF-16LE strings (lightweight)
  let uStart = 0;
  for (let i = 0; i + 1 < buf.length && results.length < maxResults; i += 2) {
    const lo = buf[i];
    const hi = buf[i + 1];
    if (lo >= 0x20 && lo < 0x7f && hi === 0) continue;
    const len = i - uStart;
    if (len >= 10) {
      const s = decodeUtf16LE(buf, uStart, len);
      if (s.length >= minLen) {
        const cat = classifyString(s);
        if (cat !== "junk") {
          results.push({ value: s, length: s.length, category: cat });
        }
      }
    }
    uStart = i + 2;
  }

  // Deduplicate and sort by length desc
  const seen = new Set<string>();
  const deduped: StringResult[] = [];
  for (const r of results) {
    if (seen.has(r.value)) continue;
    seen.add(r.value);
    deduped.push(r);
  }
  deduped.sort((a, b) => b.length - a.length);
  return deduped.slice(0, 300);
}

function classifyString(s: string): string {
  if (/https?:\/\//i.test(s)) return "URL";
  if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/i.test(s)) return "Email";
  if (/\.(exe|dll|sys|bat|ps1|vbs|js|jar|scr|pif|com|cmd|msi|ocx|cpl)$/i.test(s)) return "File Reference";
  if (/\\Software\\|\\System32\\|\\CurrentVersion\\Run|\\Microsoft\\Windows/i.test(s)) return "Registry Path";
  if (/^[A-Z]:\\/i.test(s)) return "File Path";
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(s)) return "IP Address";
  if (/cmd\.exe|powershell|netsh|wmic|schtasks|rundll32|regsvr32|mshta|certutil|bitsadmin/i.test(s)) return "Command";
  if (/HKEY_|HKLM|HKCU|HKCR/i.test(s)) return "Registry Path";
  if (/^[A-Za-z][A-Za-z0-9_]{3,40}$/.test(s) && !/^[a-z]+$$/i.test(s)) return "Symbol";
  if (/^[a-z ]+$/i.test(s) && s.length >= 8) return "Text";
  return "junk";
}

function buildCfg(
  sections: PeSection[],
  imports: ParsedImport[],
  suspicious: SuspiciousApi[],
  entryPoint: number,
): CfgData {
  const nodes: CfgNode[] = [];
  const edges: CfgEdge[] = [];

  // Entry node
  let entrySectionName: string | null = null;
  for (const s of sections) {
    if (entryPoint >= s.virtual_address && entryPoint < s.virtual_address + s.virtual_size) {
      entrySectionName = s.name;
      break;
    }
  }
  const entryId = "entry";
  nodes.push({ id: entryId, label: "Entry Point", type: "entry" });

  // Section nodes
  for (const s of sections) {
    nodes.push({ id: `sec:${s.name}`, label: s.name, type: "section" });
    if (entrySectionName === s.name) {
      edges.push({ from: entryId, to: `sec:${s.name}` });
    }
  }

  // Import / API call nodes
  const dllSet = new Set<string>();
  for (const imp of imports) {
    if (!dllSet.has(imp.dll)) {
      dllSet.add(imp.dll);
      nodes.push({ id: `dll:${imp.dll}`, label: imp.dll, type: "dll" });
    }
  }
  // Link executable sections to DLLs they import
  const execSections = sections.filter((s) => s.flags.includes("EXECUTE") || s.flags.includes("CODE"));
  const linkSections = execSections.length > 0 ? execSections : sections;
  for (const imp of imports) {
    const dllNode = `dll:${imp.dll}`;
    for (const s of linkSections) {
      edges.push({ from: `sec:${s.name}`, to: dllNode });
    }
  }

  // Suspicious API nodes (linked from their DLL)
  const susSet = new Set<string>();
  for (const api of suspicious) {
    const apiId = `api:${api.name}`;
    if (!susSet.has(apiId)) {
      susSet.add(apiId);
      nodes.push({ id: apiId, label: api.name, type: "suspicious" });
      edges.push({ from: `dll:${api.dll}`, to: apiId });
    }
  }

  const nodeCount = nodes.length;
  const edgeCount = edges.length;
  const maxEdges = (nodeCount * (nodeCount - 1)) / 2;
  const density = maxEdges > 0 ? Math.round((edgeCount / maxEdges) * 100) / 100 : 0;

  return { nodes, edges, node_count: nodeCount, edge_count: edgeCount, density, entry: entrySectionName };
}

function computeRisk(args: {
  suspicious: SuspiciousApi[];
  sections: PeSection[];
  metadata: PeMetadata;
  strings: StringResult[];
  imports: ParsedImport[];
}): { risk_score: number; risk_level: string } {
  let score = 0;

  // Suspicious API weights
  const apiScore = args.suspicious.reduce((sum, s) => sum + s.weight, 0);
  score += Math.min(apiScore, 45);

  // High-entropy section (packed)
  for (const s of args.sections) {
    if (s.entropy >= 7.2 && (s.flags.includes("EXECUTE") || s.flags.includes("CODE"))) {
      score += 12;
    } else if (s.entropy >= 7.0) {
      score += 6;
    }
  }

  // No ASLR / DEP
  if (!args.metadata.dll_characteristics.includes("DYNAMIC_BASE (ASLR)")) score += 5;
  if (!args.metadata.dll_characteristics.includes("NX_COMPAT (DEP)")) score += 5;
  if (!args.metadata.dll_characteristics.includes("GUARD_CF")) score += 4;

  // Suspicious strings
  const susStrings = args.strings.filter(
    (s) =>
      s.category === "URL" ||
      s.category === "Command" ||
      s.category === "IP Address" ||
      s.category === "Registry Path",
  );
  score += Math.min(susStrings.length * 2, 14);

  // Many imports from networking DLLs
  const netDlls = ["ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll"];
  const netImports = args.imports
    .filter((i) => netDlls.includes(i.dll))
    .reduce((sum, i) => sum + i.functions.length, 0);
  score += Math.min(netImports, 8);

  // Very few imports (packed / hollowed)
  const totalImports = args.imports.reduce((sum, i) => sum + i.functions.length, 0);
  if (totalImports > 0 && totalImports < 10) score += 6;

  score = Math.min(score, 100);
  let level = "low";
  if (score >= 75) level = "critical";
  else if (score >= 50) level = "high";
  else if (score >= 25) level = "medium";
  return { risk_score: score, risk_level: level };
}

// ---------------------------------------------------------------------------
// AI explanation generator (heuristic, rule-based)
// ---------------------------------------------------------------------------
function generateExplanation(res: AnalysisResult): string {
  const lines: string[] = [];

  lines.push(
    `This binary is a ${res.metadata.is_64bit ? "64-bit" : "32-bit"} ${res.metadata.is_dll ? "DLL" : "executable"} targeting ${res.metadata.machine}. It was compiled with a build timestamp of ${res.metadata.timestamp_human || "unknown"} and uses the ${res.metadata.subsystem} subsystem.`,
  );

  // Risk
  lines.push(
    `The overall risk score is ${res.risk_score}/100 (${res.risk_level.toUpperCase()}).`,
  );

  // Suspicious APIs
  if (res.suspicious_apis.length > 0) {
    const categories = [...new Set(res.suspicious_apis.map((a) => a.category))];
    lines.push(
      `The file imports ${res.suspicious_apis.length} API functions known to be associated with malicious behavior, spanning ${categories.length} categories: ${categories.join(", ")}.`,
    );
    const top = res.suspicious_apis.slice().sort((a, b) => b.weight - a.weight).slice(0, 5);
    lines.push(
      `The most concerning imports are: ${top.map((a) => a.name).join(", ")}. These are commonly observed in ${top[0].category.toLowerCase()} techniques.`,
    );
  } else {
    lines.push(`No individually-suspicious API calls were identified in the import table.`);
  }

  // Sections / packing
  const packed = res.sections.filter((s) => s.entropy >= 7.2);
  if (packed.length > 0) {
    lines.push(
      `Section(s) ${packed.map((s) => s.name).join(", ")} exhibit high entropy (>= 7.2), which strongly suggests the presence of packed or encrypted code. Legitimate compilers rarely produce sections this dense.`,
    );
  } else {
    lines.push(`No sections exhibit entropy levels consistent with packing or encryption.`);
  }

  // Mitigations
  const missing: string[] = [];
  if (!res.metadata.dll_characteristics.includes("DYNAMIC_BASE (ASLR)")) missing.push("ASLR");
  if (!res.metadata.dll_characteristics.includes("NX_COMPAT (DEP)")) missing.push("DEP");
  if (!res.metadata.dll_characteristics.includes("GUARD_CF")) missing.push("Control Flow Guard");
  if (missing.length > 0) {
    lines.push(
      `Several exploit mitigations are absent: ${missing.join(", ")}. Their absence increases the likelihood that the binary was hand-built or deliberately stripped of modern protections.`,
    );
  } else {
    lines.push(`Standard exploit mitigations (ASLR, DEP, Control Flow Guard) are present.`);
  }

  // Strings
  const urls = res.strings.filter((s) => s.category === "URL");
  const cmds = res.strings.filter((s) => s.category === "Command");
  const reg = res.strings.filter((s) => s.category === "Registry Path");
  if (urls.length > 0) {
    lines.push(
      `Embedded URLs were found (${urls.slice(0, 3).map((s) => s.value).join(", ")}), indicating the binary may attempt network communication — a potential command-and-control or download indicator.`,
    );
  }
  if (cmds.length > 0) {
    lines.push(
      `Command-line references such as ${cmds.slice(0, 2).map((s) => s.value).join(", ")} suggest the binary may spawn shell processes or use living-off-the-land binaries.`,
    );
  }
  if (reg.length > 0) {
    lines.push(
      `Registry paths were extracted, which is a strong indicator of persistence mechanisms (${reg.slice(0, 2).map((s) => s.value).join(", ")}).`,
    );
  }

  // CFG summary
  lines.push(
    `The reconstructed control-flow graph contains ${res.cfg.node_count} nodes and ${res.cfg.edge_count} edges (density ${res.cfg.density}). Entry point resides in section ${res.cfg.entry || "unknown"}.`,
  );

  // Conclusion
  if (res.risk_level === "critical" || res.risk_level === "high") {
    lines.push(
      `Conclusion: This binary exhibits multiple characteristics commonly associated with malicious software. It is recommended to treat this file as suspicious and avoid executing it outside a controlled sandbox environment. Further dynamic analysis is advised.`,
    );
  } else if (res.risk_level === "medium") {
    lines.push(
      `Conclusion: This binary shows some potentially suspicious traits. Manual review is recommended before execution. While not definitively malicious, the combination of indicators warrants caution.`,
    );
  } else {
    lines.push(
      `Conclusion: This binary does not exhibit strong indicators of malicious behavior based on static analysis alone. However, static analysis cannot detect all threats — dynamic analysis may still be warranted depending on context.`,
    );
  }

  return lines.join("\n\n");
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed. Use POST." }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const formData = await req.formData();
    const file = formData.get("file");
    if (!file || !(file instanceof File)) {
      return new Response(JSON.stringify({ error: "No file uploaded. Provide a file in the 'file' field." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);

    if (bytes.length > 16 * 1024 * 1024) {
      return new Response(JSON.stringify({ error: "File too large. Maximum 16 MB." }), {
        status: 413,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // SHA-256
    const hashBuf = await crypto.subtle.digest("SHA-256", arrayBuffer);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    const sha256 = hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");

    // Parse PE
    const result = parsePE(bytes);
    const aiExplanation = generateExplanation(result);

    // Persist to Supabase
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, serviceKey);

    const row = {
      file_name: file.name,
      file_size: bytes.length,
      file_hash: sha256,
      risk_score: result.risk_score,
      risk_level: result.risk_level,
      metadata: result.metadata,
      imports: result.imports,
      suspicious_apis: result.suspicious_apis,
      strings: result.strings,
      sections: result.sections,
      cfg: result.cfg,
      ai_explanation: aiExplanation,
    };

    const { data, error } = await supabase
      .from("analyses")
      .insert(row)
      .select("id, created_at")
      .single();

    if (error) {
      return new Response(JSON.stringify({ error: `Database error: ${error.message}` }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(
      JSON.stringify({
        id: data.id,
        created_at: data.created_at,
        file_name: file.name,
        file_size: bytes.length,
        file_hash: sha256,
        risk_score: result.risk_score,
        risk_level: result.risk_level,
        metadata: result.metadata,
        imports: result.imports,
        suspicious_apis: result.suspicious_apis,
        strings: result.strings,
        sections: result.sections,
        cfg: result.cfg,
        ai_explanation: aiExplanation,
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
