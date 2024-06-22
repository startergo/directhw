enum {
    kReadIO,
    kWriteIO,
    kPrepareMap,
    kReadMSR,
    kWriteMSR,
    kReadCpuId,
    kReadMem,
    kRead,
    kWrite,
    kAllocatePhysicalMemory,
    kUnallocatePhysicalMemory,
    kNumberOfMethods
};

typedef struct {
    UInt64 offset;
    UInt64 width;
    UInt64 data; // this field is always little endian // is 1 or 2 or 4 or 8 bytes starting at the lowest address
} iomem64_t;

typedef struct {
    UInt32 offset;
    UInt32 width;
    UInt32 data; // this field is always little endian // is 1 or 2 or 4 bytes starting at the lowest address
} iomem_t;

typedef struct {
    UInt64 addr;
    UInt64 size;
} map_t;

typedef struct {
    UInt32 addr;
    UInt32 size;
} map32_t;

typedef struct {
    UInt32 core;
    UInt32 index;
    UInt32 hi;
    UInt32 lo;
} msrcmd_t;

typedef struct {
    uint32_t core;
    uint32_t eax;
    uint32_t ecx;
    uint32_t cpudata[4];
} cpuid_t;

typedef struct {
    uint32_t core;
    uint64_t addr;
    uint32_t data;
} readmem_t;

// ==============
// Read, Write

/* Space definitions */
enum {
    kConfigSpace           = 0,
    kIOSpace               = 1,
    k32BitMemorySpace      = 2,
    k64BitMemorySpace      = 3
};

union Address {
    uint64_t addr64;
    struct {
        unsigned int offset     :16;
        unsigned int function   :3;
        unsigned int device     :5;
        unsigned int bus        :8;
        unsigned int segment    :16;
        unsigned int reserved   :16;
    } pci;
    struct {
        unsigned int reserved   :16;
        unsigned int segment    :16;
        unsigned int bus        :8;
        unsigned int device     :5;
        unsigned int function   :3;
        unsigned int offset     :16;
    } pciswapped;
};
typedef union Address Address;

struct Parameters {
    uint32_t options;
    uint32_t spaceType;
    uint32_t bitWidth;
    uint32_t _resv;
    uint64_t value;
    Address  address;
};
typedef struct Parameters Parameters;

// ==============
// AllocatePhysicalMemory

enum {
    kMemoryTypeMax              = 10000000,
    kMemoryTypeUser             = 10000000,
    kMemoryTypeKernel           = 20000000,
    kMemoryTypeKernelMalloc     = 30000000,
    kMemoryTypeSegments         = 40000000, // this is added to the other memory types and should only be used by the kext
    kMemoryTypeSegmentsKernel   = 50000000
};

enum {
    kPhysContig             = 0,
    kUseVirt                = 1,
    kUsePhys                = 2,
    kAllocTypeMask          = 15,
    kMapKernel              = 1 << 4,
};

typedef struct IOPhysicalSegment {
    UInt64 location;
    UInt64 length;
} IOPhysicalSegment;

typedef struct MemParams {
    UInt32 memoryType;
    UInt32 allocOptions;
    UInt32 mapOptions;
        #if 0
            kUsePhys:
                kernel:
                    kIOMapAnywhere is always set.
                    kIOMapDefaultCache to inhibit the cache in I/O areas, kIOMapCopybackCache in general purpose RAM.<br>
                    kIOMapInhibitCache, kIOMapWriteThruCache, kIOMapCopybackCache to set the appropriate caching.<br>
                    kIOMapReadOnly to allow only read only accesses to the memory - writes will cause and access fault.<br>
                    kIOMapReference will only succeed if the mapping already exists, and the IOMemoryMap object is just an extra reference, ie. no new mapping will be created.<br>
                    kIOMapUnique allows a special kind of mapping to be created that may be used with the IOMemoryMap::redirect() API. These mappings will not be shared as is the default - there will always be a unique mapping created for the caller, not an existing mapping with an extra reference.<br>
                    kIOMapPrefault will try to prefault the pages corresponding to the mapping. This must not be done on the kernel task, and the memory must have been wired via prepare(). Otherwise, the function will fail.<br>
                user:
                    same as kUsePhys/kernel
            kUseVirt:
                kernel:
                    same as kUsePhys/kernel
                user:
                    mapping was created by user task
            physContig:
                kernel:
                    same as kUsePhys/kernel
                user:
                    same as kUsePhys/kernel
        #endif
    UInt64 physMask;
    UInt64 size;
    UInt64 userAddr;
    UInt64 physAddr;
    UInt64 kernAddr;
    UInt64 segments;
} MemParams;

// ==============
