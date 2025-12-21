# DirectHW - Enhanced Direct Hardware Access Library for macOS

DirectHW is an advanced hardware access library and kernel extension for macOS, providing comprehensive low-level hardware control interfaces. This enhanced fork extends the standard DirectHW with advanced physical memory management, DMA buffer allocation, and sophisticated hardware control capabilities.

## Enhanced Features

This fork provides significantly more control interfaces than standard DirectHW:

<details>
<summary>🚀 <strong>Advanced Memory Management</strong></summary>

- **Physical Memory Allocation** - Allocate physically contiguous memory buffers
- **DMA Buffer Management** - Create DMA-capable buffers with specific constraints  
- **Memory Mapping Control** - Fine-grained control over memory mapping options
- **32-bit Address Space** - Support for legacy hardware requiring 32-bit addresses
- **Cache Control** - Inhibit, write-through, or copyback caching per mapping
</details>

<details>
<summary>🔧 <strong>Enhanced Hardware Control</strong></summary>

- **MSR Operations** - Read/write Model Specific Registers on specific CPU cores *(Intel only)*
- **CPUID Instructions** - Execute CPUID with full control over input registers *(Intel only)*
- **Multi-Core Support** - Target specific CPU cores for operations *(Intel only)*
- **Cross-Endian Compatibility** - Rosetta translation layer support
- **Physical Address Translation** - Direct physical memory access with virtual mapping
</details>

<details>
<summary>⚡ <strong>Advanced I/O Capabilities</strong></summary>

- **Port I/O (8/16/32/64-bit)** - Enhanced port access with 64-bit support *(Intel only)*
- **Memory-Mapped I/O** - Sophisticated MMIO with configurable caching policies
- **PCI Configuration Space** - Complete PCI config access with bus/device/function addressing
- **Physical Memory Reading** - Direct physical memory access with safety controls
</details>

## Technical Architecture

<details>
<summary><strong>Kernel Extension Methods</strong></summary>

The kernel component implements 11 distinct hardware control methods:

| Method | Function | Enhanced Capabilities |
|--------|----------|----------------------|
| **kReadIO/kWriteIO** | Port I/O operations | 64-bit port support, multi-width access |
| **kPrepareMap** | Memory mapping setup | Advanced caching control, alignment options |
| **kReadMSR/kWriteMSR** | MSR operations | Per-core targeting, validation checks |
| **kReadCpuId** | CPUID instruction | Full register control, core selection |
| **kReadMem** | Physical memory access | Safe direct physical memory reading |
| **kRead/kWrite** | Generic hardware access | Unified interface for all address spaces |
| **kAllocatePhysicalMemory** | Memory allocation | DMA buffers, contiguous allocation, constraints |
| **kUnallocatePhysicalMemory** | Memory cleanup | Automatic resource tracking and cleanup |
</details>

<details>
<summary><strong>Memory Allocation Types & Options</strong></summary>

### Memory Allocation Types
```c
enum {
    kMemoryTypeUser             = 10000000,  // User-space accessible
    kMemoryTypeKernel           = 20000000,  // Kernel-space only  
    kMemoryTypeKernelMalloc     = 30000000,  // Kernel malloc'd
    kMemoryTypeSegments         = 40000000,  // Segmented allocation
    kMemoryTypeSegmentsKernel   = 50000000   // Kernel segmented
};
```

### Advanced Allocation Options
```c
enum {
    kPhysContig    = 0,  // Physically contiguous allocation
    kUseVirt       = 1,  // Use existing virtual address  
    kUsePhys       = 2,  // Use existing physical address
    kMapKernel     = 16  // Create kernel mapping
};
```
</details>

## Use Cases & Examples

<details>
<summary><strong>Hardware Driver Development</strong></summary>

```c
// Allocate DMA buffer for hardware communication
uint32_t physAddr;
void* userAddr; 
uint32_t bufferType;

// Create 32-bit physically contiguous DMA buffer
allocate_physically_contiguous_32(65536, &physAddr, &userAddr, &bufferType);

// Hardware can now use physAddr for DMA operations
// User code can access buffer via userAddr
```
</details>

<details>
<summary><strong>Low-Level System Analysis</strong></summary>

```c
// Read MSR on specific CPU core
logical_cpu_select(2);  // Select CPU core 2
msr_t msr = rdmsr(0x1A0);  // Read IA32_MISC_ENABLE
printf("MSR 0x1A0 = 0x%08x%08x\n", msr.hi, msr.lo);

// Execute CPUID with full control
uint32_t cpudata[4];
rdcpuid(0x80000008, 0, cpudata);  // Get physical address size info
```
</details>

<details>
<summary><strong>Memory-Mapped Hardware Access</strong></summary>

```c
// Map hardware registers with inhibited cache
void* hwRegs = map_physical(0xFED00000, 4096);  // Map hardware region
if (hwRegs != MAP_FAILED) {
    // Direct hardware register access
    uint32_t status = *(volatile uint32_t*)(hwRegs + 0x100);
    *(volatile uint32_t*)(hwRegs + 0x104) = 0x12345678;
    unmap_physical(hwRegs, 4096);
}
```
</details>

## Enhanced API Reference

<details>
<summary><strong>Memory Management APIs</strong></summary>

```c
// Advanced memory allocation with constraints
int allocate_physically_contiguous_32(size_t len, uint32_t *phys, void **user, uint32_t *type);
int unallocate_mem(uint32_t type);
void* map_physical(uint64_t phys_addr, size_t len);
void unmap_physical(void *virt_addr, size_t len);
```
</details>

<details>
<summary><strong>CPU Control APIs</strong></summary>

```c
// MSR operations with core selection  
int logical_cpu_select(int cpu);
msr_t rdmsr(int addr);
int wrmsr(int addr, msr_t msr);

// Enhanced CPUID with input control
int rdcpuid(uint32_t eax, uint32_t ecx, uint32_t cpudata[4]);
```
</details>

<details>
<summary><strong>Memory Access APIs</strong></summary>

```c
// Direct physical memory reading
int readmem32(uint64_t addr, uint32_t* data);

// Enhanced port I/O (including 64-bit on supported systems)
unsigned char inb(unsigned short addr);
unsigned short inw(unsigned short addr);
unsigned int inl(unsigned short addr);
#ifdef __EA64__
unsigned long inq(unsigned short addr);
#endif
```
</details>

## Integration Examples

<details>
<summary><strong>dmidecode Integration</strong></summary>

This fork includes patches for dmidecode integration, allowing:
```bash
# Standard dmidecode with DirectHW backend
dmidecode -t memory    # Memory information via DirectHW
biosdecode            # BIOS analysis via DirectHW  
vpddecode             # VPD decoding via DirectHW
```
</details>

<details>
<summary><strong>Framework Integration (Objective-C/Swift)</strong></summary>

```objc
#import <DirectHW/DirectHW.h>

@implementation HardwareController
- (void)readHardwareInfo {
    if (iopl(3) == 0) {
        // Hardware access available
        uint32_t data;
        if (readmem32(0xE0000, &data) == 0) {
            NSLog(@"BIOS signature: 0x%08x", data);
        }
    }
}
@end
```
</details>

## Platform Support

| Platform | Kernel Extension | Memory Management | MSR Support | Multi-Core | Port I/O | Notes |
|----------|------------------|-------------------|-------------|------------|----------|-------|
| **macOS 13+ (Ventura+) Intel** | ✅ Universal | ✅ Full DMA | ✅ All MSRs | ✅ Per-Core | ✅ Full | Complete x86_64 support |
| **macOS 13+ (Ventura+) Apple Silicon** | ✅ Universal | ✅ Full DMA | ❌ No MSRs | ⚠️ Limited | ❌ No Port I/O | ARM64 limitations |
| **macOS 10.15-12 Intel** | ✅ Intel/Universal | ✅ Full DMA | ✅ All MSRs | ✅ Per-Core | ✅ Full | Complete Intel support |
| **macOS 10.15-12 Apple Silicon** | ✅ Universal | ✅ Full DMA | ❌ No MSRs | ⚠️ Limited | ❌ No Port I/O | ARM64 limitations |
| **macOS 10.9-14 Intel** | ✅ Intel 64-bit | ✅ Full DMA | ✅ All MSRs | ✅ Per-Core | ✅ Full | Complete Intel support |
| **Mac OS X 10.4-10.8** | ✅ Intel/PPC | ✅ Basic DMA | ✅ Limited | ⚠️ Basic | ✅ Legacy | Vintage system support |

<details>
<summary><strong>⚠️ Apple Silicon Limitations</strong></summary>

### What Works on Apple Silicon (ARM64)
- ✅ **Memory Management** - Full DMA buffer allocation and physical memory mapping
- ✅ **Memory-Mapped I/O** - Direct hardware register access via memory mapping
- ✅ **Physical Memory Access** - Direct physical memory reading with `readmem32()`
- ✅ **Universal Binary Support** - Native ARM64 execution

### What Doesn't Work on Apple Silicon
- ❌ **Port I/O Operations** - `inb()`, `inw()`, `inl()`, `outb()`, `outw()`, `outl()` are x86-specific
- ❌ **MSR Access** - Model Specific Registers don't exist on ARM architecture
- ❌ **CPUID Instructions** - x86-specific instruction not available on ARM
- ❌ **Multi-Core CPU Targeting** - Limited to single-core operations

### ARM64 Code Behavior
```c
// On Apple Silicon, these operations return zero/no-op:
msr_t msr = rdmsr(0x1A0);          // Returns { .hi = 0, .lo = 0 }
rdcpuid(0x80000008, 0, cpudata);   // Returns cpudata[0-3] = 0
outb(0x80, 0xFF);                  // No operation performed
```

### Recommended Apple Silicon Usage
```c
// Focus on memory management and MMIO operations
void* hwRegs = map_physical(0x100000000ULL, 4096);  // Works on ARM64
if (hwRegs != MAP_FAILED) {
    uint32_t value = *(volatile uint32_t*)hwRegs;
    *(volatile uint32_t*)(hwRegs + 4) = 0x12345678;
    unmap_physical(hwRegs, 4096);
}

// DMA buffer allocation works fully on ARM64
uint32_t physAddr;
void* userAddr;
uint32_t bufferType;
if (allocate_physically_contiguous_32(65536, &physAddr, &userAddr, &bufferType) == 0) {
    // Use DMA buffer...
    unallocate_mem(bufferType);
}
```
</details>

## Installation & Usage

<details>
<summary><strong>Installation Options</strong></summary>

### Prerequisites
⚠️ **System Integrity Protection (SIP) Configuration Required**

DirectHW requires loading a kernel extension, which requires SIP modification on modern macOS:

1. **Boot into Recovery Mode** (⌘+R during startup)
2. **Open Terminal** from Utilities menu
3. **Configure SIP** for kernel extension loading:
   ```bash
   # Allow kernel extension loading while keeping other SIP protections
   csrutil enable --without kext
   
   # Or disable SIP entirely (less secure)
   csrutil disable
   ```
4. **Reboot** into normal macOS

### Option 1: Installer Package (Recommended)
1. Download the latest DMG from [Releases](../../releases)
2. Mount the DMG and run `Install DirectHW.pkg`
3. **Approve kernel extension** in System Preferences → Security & Privacy
4. Restart your system to load the kernel extension
5. Verify installation: `kextstat | grep DirectHW`

### Option 2: Manual Installation
```bash
# Install kernel extension
sudo cp -R DirectHW.kext /Library/Extensions/
sudo chmod -R 755 /Library/Extensions/DirectHW.kext
sudo chown -R root:wheel /Library/Extensions/DirectHW.kext

# Install framework
sudo cp -R DirectHW.framework /Library/Frameworks/

# Install libraries
sudo cp libDirectHW.* /usr/local/lib/

# Load kernel extension (may require approval in System Preferences)
sudo kextload /Library/Extensions/DirectHW.kext
```

### Verification Steps
```bash
# Check if DirectHW kernel extension loaded successfully
kextstat | grep DirectHW

# Check SIP status
csrutil status

# Test DirectHW functionality (requires root)
sudo -s
cd /path/to/directhw/examples
./simple_test
```

### Advanced Debugging
For kernel extension development and debugging:
```bash
# Check current boot args first
nvram boot-args

# Add kernel debugging to existing boot args (preserves other settings)
CURRENT_ARGS=$(nvram boot-args 2>/dev/null | cut -d$'\t' -f2)
sudo nvram boot-args="$CURRENT_ARGS debug=0x144"

# Alternative: Add multiple debug flags to existing args
CURRENT_ARGS=$(nvram boot-args 2>/dev/null | cut -d$'\t' -f2)
sudo nvram boot-args="$CURRENT_ARGS debug=0x14e kext-dev-mode=1"

# View kernel messages in real-time
sudo dmesg -w | grep DirectHW

# Remove only debug flags (preserves other boot args)
CURRENT_ARGS=$(nvram boot-args 2>/dev/null | cut -d$'\t' -f2)
CLEAN_ARGS=$(echo "$CURRENT_ARGS" | sed -E 's/debug=[^ ]*//g; s/kext-dev-mode=[^ ]*//g; s/  +/ /g; s/^ //; s/ $//')
sudo nvram boot-args="$CLEAN_ARGS"
```

**Debug Flag Meanings:**
- `debug=0x144` = Basic kernel debugging + panic debugging
- `debug=0x14e` = Enhanced debugging with detailed kernel messages
- `kext-dev-mode=1` = Enable development mode for unsigned kernel extensions
</details>

<details>
<summary><strong>Building from Source</strong></summary>

### Prerequisites
- Xcode Command Line Tools
- macOS SDK (10.9 or later recommended)
- Valid code signing certificate (for kernel extensions)

### Build Instructions
```bash
# Clone the repository
git clone https://github.com/startergo/directhw.git
cd directhw

# Build all components
xcodebuild -project DirectHW.xcodeproj -configuration Release

# Build artifacts will be in:
# - build/Release/DirectHW.kext
# - build/Release/DirectHW.framework  
# - build/Release/libDirectHW.a
# - build/Release/libDirectHW.dylib
```

### Creating Distribution DMG
```bash
# Build universal AppleScript runner (for multi-architecture support)
cd create-dmg/support
make clean && make

# Create DMG with proper layout
./create-dmg/create-dmg \
    --volname "DirectHW v1.5.1" \
    --window-size 700 400 \
    --icon-size 96 \
    --icon "Install DirectHW.pkg" 200 200 \
    --icon "DirectHW.framework" 350 200 \
    --icon "DirectHW.kext" 500 200 \
    DirectHW-v1.5.1.dmg \
    /path/to/distribution/contents
```

### Compilation & Integration
```bash
# Build with enhanced features
xcodebuild -project DirectHW.xcodeproj \
           -configuration Release \
           -arch x86_64 -arch arm64

# Integration with external projects
gcc -framework DirectHW -framework IOKit myapp.c -o myapp
```

### Makefile Integration
```makefile
# Enhanced DirectHW support
OS_ARCH = $(shell uname)
ifeq ($(OS_ARCH), Darwin)
    LDFLAGS += -framework IOKit -framework DirectHW
    CFLAGS += -DUSE_DIRECTHW
endif
```
</details>

## Security & Safety

<details>
<summary><strong>Built-in Protections & Safe Usage</strong></summary>

### Built-in Protections
- **Root Privilege Enforcement** - All operations require administrator access
- **Memory Validation** - Kernel validates all memory operations for safety
- **Resource Tracking** - Automatic cleanup prevents resource leaks
- **Cross-Endian Safety** - Proper byte ordering for Rosetta compatibility

### ⚠️ System Integrity Protection (SIP) Requirements
DirectHW requires loading a third-party kernel extension, which has **significant restrictions** under SIP:

**macOS 10.13+ (High Sierra and later):**
- **SIP must be partially disabled** for kernel extension loading
- Requires `csrutil enable --without kext` or `csrutil disable`  
- User must approve kernel extension in System Preferences → Security & Privacy
- May require reboot into Recovery Mode to modify SIP settings

**macOS 10.15+ (Catalina and later):**
- **Additional notarization requirements** for kernel extensions
- Apple is phasing out third-party kernel extensions
- May require developer-signed kernel extensions
- SystemExtensions framework is preferred for new development

**Recommended SIP Configuration:**
```bash
# Check current SIP status
csrutil status

# Disable only kernel extension protection (requires Recovery Mode)
csrutil enable --without kext

# Or disable SIP entirely (NOT recommended for production)
csrutil disable
```

### Safe Usage Patterns  
```c
// Always check return values and initialization
if (darwin_init() != 0) {
    fprintf(stderr, "DirectHW initialization failed\n");
    fprintf(stderr, "Check that DirectHW.kext is loaded and SIP allows kernel extensions\n");
    return -1;
}

// Clean up allocated resources
uint32_t bufferType;
if (allocate_physically_contiguous_32(size, &phys, &user, &bufferType) == 0) {
    // Use the buffer...
    unallocate_mem(bufferType);  // Always clean up
}
```
</details>

<details>
<summary><strong>Troubleshooting</strong></summary>

### Common Issues

**Kernel Extension Won't Load**
```bash
# Check system logs for errors
sudo dmesg | grep DirectHW

# Enable detailed kernel debugging (requires reboot)
CURRENT_ARGS=$(nvram boot-args 2>/dev/null | cut -d$'\t' -f2)
sudo nvram boot-args="$CURRENT_ARGS debug=0x144"

# Check SIP status (most common issue)
csrutil status

# If SIP blocks kernel extensions:
# 1. Reboot into Recovery Mode (⌘+R)
# 2. csrutil enable --without kext
# 3. Reboot normally

# Verify permissions
ls -la /Library/Extensions/DirectHW.kext

# Force reload with verbose output
sudo kextload -v /Library/Extensions/DirectHW.kext

# Watch kernel messages in real-time during load
sudo dmesg -w | grep -E "(DirectHW|kext)"
```

**"Operation not permitted" Errors**
- Most likely caused by SIP blocking kernel extension loading
- Check `csrutil status` - should show "Kernel Extension Signing: disabled"
- Modify SIP in Recovery Mode as described in installation section

**"DirectHW.kext not loaded" Error**
```bash
# Check if kext is present but not loaded
ls -la /Library/Extensions/DirectHW.kext

# Try manual load with verbose output
sudo kextload -v /Library/Extensions/DirectHW.kext

# Enable kernel debugging for detailed load information
sudo nvram boot-args="debug=0x144 kext-dev-mode=1"
# Reboot, then try loading again

# Check system preferences for kernel extension approval
open "/System/Library/PreferencePanes/Security.prefPane"

# Monitor kernel messages during load attempt
sudo dmesg -w &
sudo kextload /Library/Extensions/DirectHW.kext
```

**Permission Denied in User Code**
- Ensure application runs with root privileges: `sudo ./your_app`
- Check that DirectHW.kext is properly loaded: `kextstat | grep DirectHW`
- Verify SIP allows kernel extension communication

**Framework Not Found**
```bash
# Verify framework installation
ls -la /Library/Frameworks/DirectHW.framework

# Check search paths in Xcode project settings
# Add /Library/Frameworks to Framework Search Paths
```

**Apple Silicon Specific Issues**
- Port I/O operations fail silently (expected - not supported on ARM64)
- MSR operations return zero (expected - no MSRs on ARM architecture)  
- Focus on memory management features which work fully on Apple Silicon
</details>

## Project Information

<details>
<summary><strong>Contributing & Support</strong></summary>

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Submit a pull request with detailed description

### Support
For issues, questions, or contributions:
- **GitHub Issues**: [Report bugs or request features](../../issues)
- **Discussions**: [Community support and questions](../../discussions)
- **Wiki**: [Additional documentation and guides](../../wiki)

### License & Version History
DirectHW is released under the BSD 3-Clause License. See `LICENSE.txt` for details.

| Version | Date | Changes |
|---------|------|---------|
| **1.5.1** | 2025-08-26 | Universal binary support, Apple Silicon compatibility, Enhanced CI/CD |
| **1.5.0** | 2024-xx-xx | macOS Ventura support, Security improvements |
| **1.4.x** | 2023-xx-xx | Big Sur/Monterey compatibility |
</details>

---

**⚠️ Advanced Hardware Interface**: This enhanced DirectHW provides powerful DMA buffer management and direct hardware control. Ensure proper resource cleanup and validate all hardware operations to prevent system instability.
