# dincvoke_rs

A powerful Rust library for dynamic Windows API invocation, PE manipulation, and advanced red team operations. dincvoke_rs provides comprehensive capabilities for bypassing EDR hooks, executing indirect syscalls, manual PE mapping, memory section overloading, and more.

## Features

- **Dynamic API Resolution & Invocation**: Dynamically resolve and invoke undocumented Windows APIs from Rust. Bypass Win32 API hooks without leaving IAT traces.
- **Indirect Syscalls**: Execute NT syscalls without triggering inline hooks. Dynamically allocates and executes syscall shellcode at runtime (x64 only).
- **Manual PE Mapping**: Map PE modules from disk or directly from memory with full relocations, IAT rewriting, and section permission handling. Optionally clean DOS headers to remove PE artifacts.
- **PE Parsing**: Comprehensive PE header parsing for both 32-bit and 64-bit modules.
- **Memory Section Overloading**: Create file-backed memory sections using legitimate System32 DLLs, then overload them with your payload. Makes mapped modules appear file-backed (Not OPSEC safe).
- **Module Fluctuation**: Hide mapped PEs when not in use by swapping between payload and decoy content. Supports concurrent operations (Not OPSEC safe).
- **Shellcode Stomping**: Stomp shellcode into legitimate module .text sections. Works with the fluctuation manager for on-demand execution.
- **Template Stomping**: Generate DLL templates with neutralized entry points, then inject your payload while handling relocations automatically.
- **Syscall Parameter Spoofing**: Use hardware breakpoints with exception handlers to spoof the first 4 syscall parameters. EDR sees benign parameters, original parameters used before syscall (x64 only).
- **TLS Callback Support**: Execute TLS callbacks during manual PE mapping when needed.
- **API Set Resolution**: Automatic resolution of Windows API Set (api-*, ext-*) mappings for Windows 10+ compatibility.

## Architecture

dincvoke_rs consists of multiple specialized crates:

| Crate | Description |
|-------|-------------|
| `dyncvoke_core` | Core functionality: dynamic invocation, syscalls, module enumeration |
| `manualmap` | Manual PE mapping with IAT rewriting and relocations |
| `overload` | Memory section overloading, module stomping, template stomping |
| `dmanager` | Module fluctuation manager for hiding mapped PEs |
| `data` | Shared data structures and type definitions |

> Note: The crate is in early stage of building. Make sure to test the featues before deployment. 

## Installation

Add via crates

cargo add dincvoke

```toml
[dependencies]
dyncvoke = "0.1.0"
```

Add dincvoke_rs to your `Cargo.toml`:

```toml
[dependencies]
dincvoke_rs = { path = "path/to/dincvoke_rs" }
```

Or for the core library only:

```toml
[dependencies]
dyncvoke_core = { path = "path/to/dincvoke_rs/dyncvoke_core" }
```

## Usage Examples

### Dynamic API Resolution

Resolve and call NT functions without triggering hooks:

```rust
use dyncvoke::dyncvoke_core;


fn main() {

    // Dynamically obtain ntdll.dll's base address. 
    let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        println!("ntdll.dll base address is 0x{:X}", ntdll);
        
        // Dynamically obtain the address of a function by name.
        let nt_create_thread = dinvoke_rs::dinvoke::get_function_address(ntdll, "NtCreateThread");
        if nt_create_thread != 0
        {
            println!("NtCreateThread is at address 0x{:X}", nt_create_thread);
        }

        // Dynamically obtain the address of a function by ordinal.
        let ordinal_8 = dinvoke_rs::dinvoke::get_function_address_by_ordinal(ntdll, 8);
        if ordinal_8 != 0 
        {
            println!("The function with ordinal 8 is located at addresss 0x{:X}", ordinal_8);
        }
    }   
}
```

### Indirect Syscalls

Execute syscalls without triggering ntdll hooks:

```rust
use dyncvoke::dyncvoke_core::{execute_syscall, GetCurrentProcess, PROCESS_BASIC_INFORMATION};
use dyncvoke::data::{NtQueryInformationProcess, PVOID};
use std::mem::size_of;

fn main() {
    unsafe {
        let function_type: NtQueryInformationProcess;
        let mut ret: Option<i32> = None;
        let handle = GetCurrentProcess();
        let p = PROCESS_BASIC_INFORMATION::default();
        let process_information: PVOID = std::mem::transmute(&p);
        let mut return_length: u32 = 0;

        execute_syscall!(
            "NtQueryInformationProcess",
            function_type,
            ret,
            handle,
            0,
            process_information,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        );
    }
}
```

### Manual PE Mapping

Map a clean copy of ntdll without EDR hooks:

```rust
use dyncvoke::manualmap;
use dyncvoke::data::PeMetadata;

fn main() {
    unsafe {
        // Map ntdll from disk, clean headers, don't run TLS callbacks
        let ntdll: (PeMetadata, usize) = manualmap::read_and_map_module(
            r"C:\Windows\System32\ntdll.dll",
            true,  // clean DOS header
            false  // no TLS callbacks
        ).unwrap();

        // Use the mapped ntdll for unhooked operations
    }
}
```

### Memory Section Overloading

Create file-backed sections using legitimate DLLs:

```rust
use dyncvoke::overload;

fn main() {
    unsafe {
        let payload = your_download_function();

        // Overload with auto-selected decoy
        let result: (dyncvoke::data::PeMetadata, usize) =
            overload::overload_module(&payload, "").unwrap();
    }
}
```

### Module Fluctuation

Hide mapped modules when not in use:

```rust
use dyncvoke::{overload, dmanager::Manager};

fn main() {
    unsafe {
        let mut manager = Manager::new();

        // Create fluctuated module
        let overload = overload::managed_read_and_overload(
            r"c:\windows\system32\payload.dll",
            r"c:\windows\system32\cdp.dll"  // decoy
        ).unwrap();

        manager.new_module(overload.1, overload.0.0, overload.0.1).unwrap();

        // Map (show) the payload
        manager.map_module(overload.1);

        // ... use the payload ...

        // Hide it again
        manager.hide_module(overload.1);
    }
}
```

### Syscall Parameter Spoofing

Spoof syscall parameters using hardware breakpoints:

```rust
use dyncvoke::dyncvoke_core::{use_hardware_breakpoints, add_vectored_exception_handler, nt_open_process};
use dyncvoke::data::{HANDLE, OBJECT_ATTRIBUTES, ClientId, THREAD_ALL_ACCESS};

fn main() {
    unsafe {
        // Enable hardware breakpoint spoofing
        use_hardware_breakpoints(true);

        // Add VEH handler
        let handler = dyncvoke_core::breakpoint_handler as usize;
        add_vectored_exception_handler(1, handler);

        // Call with spoofable parameters
        let mut handle: HANDLE = 0;
        let attrs = OBJECT_ATTRIBUTES::default();
        let client_id = ClientId { unique_process: target_pid as HANDLE, unique_thread: 0 };

        let ret = nt_open_process(
            &mut handle,
            THREAD_ALL_ACCESS,
            &attrs,
            &client_id
        );

        use_hardware_breakpoints(false);
    }
}
```

## License

MIT 
## Credits & Resources...

The project was inspired by [DInvoke_rs](https://github.com/Kudaes/DInvoke_rs/tree/main) by [Kudaes](https://x.com/_Kudaes_) that was built using windows crate...

The project then modified and rewritten in windows_sys create for better compactibility and made major OPSEC & Debug improvements to the crates.