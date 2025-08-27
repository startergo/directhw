# DirectHW - Enhanced Direct Hardware Access Library for macOS

DirectHW is an advanced hardware access library and kernel extension for macOS, providing comprehensive low-level hardware control interfaces. This enhanced fork extends the standard DirectHW with advanced physical memory management, DMA buffer allocation, and sophisticated hardware control capabilities.

## Enhanced Features

This fork provides significantly more control interfaces than standard DirectHW:

### 🚀 **Advanced Memory Management**
- **Physical Memory Allocation** - Allocate physically contiguous memory buffers
- **DMA Buffer Management** - Create DMA-capable buffers with specific constraints  
- **Memory Mapping Control** - Fine-grained control over memory mapping options
- **32-bit Address Space** - Support for legacy hardware requiring 32-bit addresses
- **Cache Control** - Inhibit, write-through, or copyback caching per mapping

### 🔧 **Enhanced Hardware Control**
- **MSR Operations** - Read/write Model Specific Registers on specific CPU cores
- **CPUID Instructions** - Execute CPUID with full control over input registers
- **Multi-Core Support** - Target specific CPU cores for operations
- **Cross-Endian Compatibility** - Rosetta translation layer support
- **Physical Address Translation** - Direct physical memory access with virtual mapping

### ⚡ **Advanced I/O Capabilities**  
- **Port I/O (8/16/32/64-bit)** - Enhanced port access with 64-bit support on capable systems
- **Memory-Mapped I/O** - Sophisticated MMIO with configurable caching policies
- **PCI Configuration Space** - Complete PCI config access with bus/device/function addressing
- **Physical Memory Reading** - Direct physical memory access with safety controls

## Technical Architecture

### Kernel Extension (`DirectHW.kext`)
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

## Use Cases

### Hardware Driver Development
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

### Low-Level System Analysis
```c
// Read MSR on specific CPU core
logical_cpu_select(2);  // Select CPU core 2
msr_t msr = rdmsr(0x1A0);  // Read IA32_MISC_ENABLE
printf("MSR 0x1A0 = 0x%08x%08x\n", msr.hi, msr.lo);

// Execute CPUID with full control
uint32_t cpudata[4];
rdcpuid(0x80000008, 0, cpudata);  // Get physical address size info
```

### Memory-Mapped Hardware Access
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

## Enhanced API Reference

### Memory Management
```c
// Advanced memory allocation with constraints
int allocate_physically_contiguous_32(size_t len, uint32_t *phys, void **user, uint32_t *type);
int unallocate_mem(uint32_t type);
void* map_physical(uint64_t phys_addr, size_t len);
void unmap_physical(void *virt_addr, size_t len);
```

### CPU Control
```c
// MSR operations with core selection  
int logical_cpu_select(int cpu);
msr_t rdmsr(int addr);
int wrmsr(int addr, msr_t msr);

// Enhanced CPUID with input control
int rdcpuid(uint32_t eax, uint32_t ecx, uint32_t cpudata[4]);
```

### Memory Access
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

## Integration Examples

### dmidecode Integration
This fork includes patches for dmidecode integration, allowing:
```bash
# Standard dmidecode with DirectHW backend
dmidecode -t memory    # Memory information via DirectHW
biosdecode            # BIOS analysis via DirectHW  
vpddecode             # VPD decoding via DirectHW
```

### Framework Integration
```objc
#import <DirectHW/DirectHW.h>

// Objective-C/Swift integration
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

## Platform Support

| Platform | Kernel Extension | Memory Management | MSR Support | Multi-Core |
|----------|------------------|-------------------|-------------|------------|
| **macOS 13+ (Ventura+)** | ✅ Universal | ✅ Full DMA | ✅ All MSRs | ✅ Per-Core |
| **macOS 10.15-12** | ✅ Intel/Universal | ✅ Full DMA | ✅ All MSRs | ✅ Per-Core |
| **macOS 10.9-14** | ✅ Intel 64-bit | ✅ Full DMA | ✅ All MSRs | ✅ Per-Core |
| **Mac OS X 10.4-10.8** | ✅ Intel/PPC | ✅ Basic DMA | ✅ Limited | ⚠️ Basic |

## Security & Safety

### Built-in Protections
- **Root Privilege Enforcement** - All operations require administrator access
- **Memory Validation** - Kernel validates all memory operations for safety
- **Resource Tracking** - Automatic cleanup prevents resource leaks
- **Cross-Endian Safety** - Proper byte ordering for Rosetta compatibility
- **SIP Integration** - Works with System Integrity Protection enabled

### Safe Usage Patterns  
```c
// Always check return values
if (darwin_init() != 0) {
    fprintf(stderr, "DirectHW initialization failed\n");
    return -1;
}

// Clean up allocated resources
uint32_t bufferType;
if (allocate_physically_contiguous_32(size, &phys, &user, &bufferType) == 0) {
    // Use the buffer...
    unallocate_mem(bufferType);  // Always clean up
}
```

## Compilation & Integration

### Building Enhanced DirectHW
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

This enhanced DirectHW fork provides professional-grade hardware access capabilities essential for system-level development, hardware debugging, and low-level system analysis on macOS platforms.

---

**⚠️ Advanced Hardware Interface**: This enhanced DirectHW provides powerful DMA buffer management and direct hardware control. Ensure proper resource cleanup and validate all hardware operations to prevent system instability.
