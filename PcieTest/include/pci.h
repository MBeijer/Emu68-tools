/*
 * PCI
 */
typedef unsigned long long uintpci;

#define BUSUNKNOWN	(-1)

enum {
	BusCBUS		= 0,		/* Corollary CBUS */
	BusCBUSII,			/* Corollary CBUS II */
	BusEISA,			/* Extended ISA */
	BusFUTURE,			/* IEEE Futurebus */
	BusINTERN,			/* Internal bus */
	BusISA,				/* Industry Standard Architecture */
	BusMBI,				/* Multibus I */
	BusMBII,			/* Multibus II */
	BusMCA,				/* Micro Channel Architecture */
	BusMPI,				/* MPI */
	BusMPSA,			/* MPSA */
	BusNUBUS,			/* Apple Macintosh NuBus */
	BusPCI,				/* Peripheral Component Interconnect */
	BusPCMCIA,			/* PC Memory Card International Association */
	BusTC,				/* DEC TurboChannel */
	BusVL,				/* VESA Local bus */
	BusVME,				/* VMEbus */
	BusXPRESS,			/* Express System Bus */
};
static inline uint64_t LE64(uint64_t x) { return __builtin_bswap64(x); }
static inline uint32_t LE32(uint32_t x) { return __builtin_bswap32(x); }
static inline uint16_t LE16(uint16_t x) { return __builtin_bswap16(x); }


/* bcmstb PCIe controller registers */
enum{
	RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1	= 0x0188/4,
	RC_CFG_PRIV1_ID_VAL3			= 0x043c/4,
	RC_DL_MDIO_ADDR				= 0x1100/4,
	RC_DL_MDIO_WR_DATA			= 0x1104/4,
	RC_DL_MDIO_RD_DATA			= 0x1108/4,
	MISC_MISC_CTRL				= 0x4008/4,
	MISC_CPU_2_PCIE_MEM_WIN0_LO		= 0x400c/4,
	MISC_CPU_2_PCIE_MEM_WIN0_HI		= 0x4010/4,
	MISC_RC_BAR1_CONFIG_LO			= 0x402c/4,
	MISC_RC_BAR2_CONFIG_LO			= 0x4034/4,
	MISC_RC_BAR2_CONFIG_HI			= 0x4038/4,
	MISC_RC_BAR3_CONFIG_LO			= 0x403c/4,
	MISC_MSI_BAR_CONFIG_LO			= 0x4044/4,
	MISC_MSI_BAR_CONFIG_HI			= 0x4048/4,
	MISC_MSI_DATA_CONFIG			= 0x404c/4,
	MISC_EOI_CTRL				= 0x4060/4,
	MISC_PCIE_CTRL				= 0x4064/4,
	MISC_PCIE_STATUS			= 0x4068/4,
	MISC_REVISION				= 0x406c/4,
	MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT	= 0x4070/4,
	MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI	= 0x4080/4,
	MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI	= 0x4084/4,
	MISC_HARD_PCIE_HARD_DEBUG		= 0x4204/4,

	INTR2_CPU_BASE				= 0x4300/4,
	MSI_INTR2_BASE				= 0x4500/4,
	INTR_STATUS = 0,
	INTR_SET,
	INTR_CLR,
	INTR_MASK_STATUS,
	INTR_MASK_SET,
	INTR_MASK_CLR,

	EXT_CFG_INDEX				= 0x9000/4,
	RGR1_SW_INIT_1				= 0x9210/4,
	EXT_CFG_DATA				= 0x8000/4,

};
typedef unsigned long long uintpci;

/*
 * Sizes
 */
#define	BI2BY		8			/* bits per byte */
#define	BI2WD		32			/* bits per word */
#define	BY2WD		4			/* bytes per word */
#define	BY2PG		4096			/* bytes per page */
#define	WD2PG		(BY2PG/BY2WD)		/* words per page */
#define	PGSHIFT		12			/* log(BY2PG) */
#define	PGROUND(s)	(((s)+(BY2PG-1))&~(BY2PG-1))
enum {
	IRQtimer0	= 0,
	IRQtimer1	= 1,
	IRQtimer2	= 2,
	IRQtimer3	= 3,
	IRQclock	= IRQtimer3,
	IRQusb		= 9,
	IRQdma0		= 16,
#define IRQDMA(chan)	(IRQdma0+(chan))
	IRQaux		= 29,
	IRQi2c		= 53,
	IRQspi		= 54,
	IRQsdhost	= 56,
	IRQmmc		= 62,

	IRQbasic	= 64,
	IRQtimerArm	= IRQbasic + 0,

	IRQpci		= 84,
	IRQether	= 93,

	IRQlocal	= 96,
	IRQcntps	= IRQlocal + 0,
	IRQcntpns	= IRQlocal + 1,
	IRQmbox0	= IRQlocal + 4,
	IRQmbox1	= IRQlocal + 5,
	IRQmbox2	= IRQlocal + 6,
	IRQmbox3	= IRQlocal + 7,
	IRQlocaltmr	= IRQlocal + 11,

	IRQfiq		= IRQusb,	/* only one source can be FIQ */

	DmaD2M		= 0,		/* device to memory */
	DmaM2D		= 1,		/* memory to device */
	DmaM2M		= 2,		/* memory to memory */

	DmaChanEmmc	= 4,		/* can only use 2-5, maybe 0 */
	DmaChanSdhost	= 5,
	DmaChanSpiTx= 2,
	DmaChanSpiRx= 0,

	DmaDevSpiTx	= 6,
	DmaDevSpiRx	= 7,
	DmaDevEmmc	= 11,
	DmaDevSdhost	= 13,

	PowerSd		= 0,
	PowerUart0,
	PowerUart1,
	PowerUsb,
	PowerI2c0,
	PowerI2c1,
	PowerI2c2,
	PowerSpi,
	PowerCcp2tx,

	ClkEmmc		= 1,
	ClkUart,
	ClkArm,
	ClkCore,
	ClkV3d,
	ClkH264,
	ClkIsp,
	ClkSdram,
	ClkPixel,
	ClkPwm,
};
enum {
	Debug_ = 0,

	Intrdist = 0x41000,
	Intrcpu = 0x42000,

	Nvec = 8,		/* # of vectors at start of lexception.s */
	Bi2long = BI2BY * sizeof(long),
	Nirqs = 1024,
	Nsgi =	16,		/* software-generated (inter-processor) intrs */
	Nppi =	32,		/* sgis + other private peripheral intrs */
};
#define nelem(x) (sizeof(x)/sizeof(*(x)))

#define IRQLOCAL(irq)	((irq) - IRQlocal + 13 + 16)
#define IRQGLOBAL(irq)	((irq) + 64 + 32)

#define ISSGI(irq)	((uint32_t)(irq) < Nppi)
/*
 * Memory and machine-specific definitions.  Used in C and assembler.
 */
#define KiB		1024u			/* Kibi 0x0000000000000400 */
#define MiB		1048576u		/* Mebi 0x0000000000100000 */
#define GiB		1073741824u		/* Gibi 000000000040000000 */
#define VIRTIO		0xFE000000		/* i/o registers */
#define	IOSIZE		(10*MiB)
#define	ARMLOCAL	(VIRTIO+IOSIZE)		/* armv7 only */
typedef struct Intrcpuregs Intrcpuregs;
typedef struct Intrdistregs Intrdistregs;
/* each cpu sees its own registers at the same base address ((ARMLOCAL+Intrcpu)) */
struct Intrcpuregs {
	uint32_t	ctl;
	uint32_t	primask;

	uint32_t	binpt;			/* group pri vs subpri split */
	uint32_t	ack;
	uint32_t	end;
	uint32_t	runpri;
	uint32_t	hipripend;

	/* aliased regs (secure, for group 1) */
	uint32_t	alibinpt;
	uint32_t	aliack;			/* (v2 only) */
	uint32_t	aliend;			/* (v2 only) */
	uint32_t	alihipripend;		/* (v2 only) */

	char	_pad0[0xd0 - 0x2c];
	uint32_t	actpri[4];		/* (v2 only) */
	uint32_t	nsactpri[4];		/* (v2 only) */

	char	_pad1[0xfc - 0xf0];
	uint32_t	ifid;			/* ro */

	char	_pad2[0x1000 - 0x100];
	uint32_t	deact;			/* wo (v2 only) */
};
struct Intrdistregs {			/* distributor */
	uint32_t	ctl;
	uint32_t	ctlrtype;
	uint32_t	distid;
	uint8_t 	_pad0[0x80 - 0xc];

	/* botch: *[0] are banked per-cpu from here */
	/* bit maps */
	uint32_t	grp[32];		/* in group 1 (non-secure) */
	uint32_t	setena[32];		/* forward to cpu interfaces */
	uint32_t	clrena[32];
	uint32_t	setpend[32];
	uint32_t	clrpend[32];
	uint32_t	setact[32];		/* active? */
	uint32_t	clract[32];
	/* botch: *[0] are banked per-cpu until here */

	uint8_t	pri[1020];	/* botch: pri[0] — pri[7] are banked per-cpu */
	uint32_t	_rsrvd1;
	/* botch: targ[0] through targ[7] are banked per-cpu and RO */
	uint8_t	targ[1020];	/* byte bit maps: cpu targets indexed by intr */
	uint32_t	_rsrvd2;
	/* botch: cfg[1] is banked per-cpu */
	uint32_t	cfg[64];		/* bit pairs: edge? 1-N? */
	uint32_t	_pad1[64];
	uint32_t	nsac[64];		/* bit pairs (v2 only) */

	/* software-generated intrs (a.k.a. sgi) */
	uint32_t	swgen;			/* intr targets */
	uint8_t	_pad2[0xf10 - 0xf04];
	uint8_t	clrsgipend[16];		/* bit map (v2 only) */
	uint8_t	setsgipend[16];		/* bit map (v2 only) */
};

#define intrenable(i, f, a, b, n) irqenable((i), (f), (a))

//#define MKBUS(t,b,d,f)	(((t)<<24)|(((b)&0xFF)<<16)|(((d)&0x1F)<<11)|(((f)&0x07)<<8))
#define MKBUS(f,d,b,t)	(((t)<<24)|(((b)&0xFF)<<16)|(((d)&0x1F)<<11)|(((f)&0x07)<<8))
#define BUSFNO(tbdf)	(((tbdf)>>8)&0x07)
#define BUSDNO(tbdf)	(((tbdf)>>11)&0x1F)
#define BUSBNO(tbdf)	(((tbdf)>>16)&0xFF)
#define BUSTYPE(tbdf)	((tbdf)>>24)
#define BUSBDF(tbdf)	((tbdf)&0x00FFFF00)

enum {					/* type 0 & type 1 pre-defined header */
	PciVID		= 0x00,		/* vendor ID */
	PciDID		= 0x02,		/* device ID */
	PciPCR		= 0x04,		/* command */
	PciPSR		= 0x06,		/* status */
	PciRID		= 0x08,		/* revision ID */
	PciCCRp		= 0x09,		/* programming interface class code */
	PciCCRu		= 0x0A,		/* sub-class code */
	PciCCRb		= 0x0B,		/* base class code */
	PciCLS		= 0x0C,		/* cache line size */
	PciLTR		= 0x0D,		/* latency timer */
	PciHDT		= 0x0E,		/* header type */
	PciBST		= 0x0F,		/* BIST */

	PciBAR0		= 0x10,		/* base address */
	PciBAR1		= 0x14,

	PciCAP		= 0x34,		/* capabilities pointer */
	PciINTL		= 0x3C,		/* interrupt line */
	PciINTP		= 0x3D,		/* interrupt pin */
};

/* ccrb (base class code) values; controller types */
enum {
	Pcibcpci1	= 0,		/* pci 1.0; no class codes defined */
	Pcibcstore	= 1,		/* mass storage */
	Pcibcnet	= 2,		/* network */
	Pcibcdisp	= 3,		/* display */
	Pcibcmmedia	= 4,		/* multimedia */
	Pcibcmem	= 5,		/* memory */
	Pcibcbridge	= 6,		/* bridge */
	Pcibccomm	= 7,		/* simple comms (e.g., serial) */
	Pcibcbasesys	= 8,		/* base system */
	Pcibcinput	= 9,		/* input */
	Pcibcdock	= 0xa,		/* docking stations */
	Pcibcproc	= 0xb,		/* processors */
	Pcibcserial	= 0xc,		/* serial bus (e.g., USB) */
	Pcibcwireless	= 0xd,		/* wireless */
	Pcibcintell	= 0xe,		/* intelligent i/o */
	Pcibcsatcom	= 0xf,		/* satellite comms */
	Pcibccrypto	= 0x10,		/* encryption/decryption */
	Pcibcdacq	= 0x11,		/* data acquisition & signal proc. */
};

/* ccru (sub-class code) values; common cases only */
enum {
	/* mass storage */
	Pciscscsi	= 0,		/* SCSI */
	Pciscide	= 1,		/* IDE (ATA) */
	Pciscsata	= 6,		/* SATA */

	/* network */
	Pciscether	= 0,		/* Ethernet */

	/* display */
	Pciscvga	= 0,		/* VGA */
	Pciscxga	= 1,		/* XGA */
	Pcisc3d		= 2,		/* 3D */

	/* bridges */
	Pcischostpci	= 0,		/* host/pci */
	Pciscpcicpci	= 1,		/* pci/pci */

	/* simple comms */
	Pciscserial	= 0,		/* 16450, etc. */
	Pciscmultiser	= 1,		/* multiport serial */

	/* serial bus */
	Pciscusb	= 3,		/* USB */
};

enum {					/* type 0 pre-defined header */
	PciCIS		= 0x28,		/* cardbus CIS pointer */
	PciSVID		= 0x2C,		/* subsystem vendor ID */
	PciSID		= 0x2E,		/* subsystem ID */
	PciEBAR0	= 0x30,		/* expansion ROM base address */
	PciMGNT		= 0x3E,		/* burst period length */
	PciMLT		= 0x3F,		/* maximum latency between bursts */
};

enum {					/* type 1 pre-defined header */
	PciPBN		= 0x18,		/* primary bus number */
	PciSBN		= 0x19,		/* secondary bus number */
	PciUBN		= 0x1A,		/* subordinate bus number */
	PciSLTR		= 0x1B,		/* secondary latency timer */
	PciIBR		= 0x1C,		/* I/O base */
	PciILR		= 0x1D,		/* I/O limit */
	PciSPSR		= 0x1E,		/* secondary status */
	PciMBR		= 0x20,		/* memory base */
	PciMLR		= 0x22,		/* memory limit */
	PciPMBR		= 0x24,		/* prefetchable memory base */
	PciPMLR		= 0x26,		/* prefetchable memory limit */
	PciPUBR		= 0x28,		/* prefetchable base upper 32 bits */
	PciPULR		= 0x2C,		/* prefetchable limit upper 32 bits */
	PciIUBR		= 0x30,		/* I/O base upper 16 bits */
	PciIULR		= 0x32,		/* I/O limit upper 16 bits */
	PciEBAR1	= 0x28,		/* expansion ROM base address */
	PciBCR		= 0x3E,		/* bridge control register */
};

enum {					/* type 2 pre-defined header */
	PciCBExCA	= 0x10,
	PciCBSPSR	= 0x16,
	PciCBPBN	= 0x18,		/* primary bus number */
	PciCBSBN	= 0x19,		/* secondary bus number */
	PciCBUBN	= 0x1A,		/* subordinate bus number */
	PciCBSLTR	= 0x1B,		/* secondary latency timer */
	PciCBMBR0	= 0x1C,
	PciCBMLR0	= 0x20,
	PciCBMBR1	= 0x24,
	PciCBMLR1	= 0x28,
	PciCBIBR0	= 0x2C,		/* I/O base */
	PciCBILR0	= 0x30,		/* I/O limit */
	PciCBIBR1	= 0x34,		/* I/O base */
	PciCBILR1	= 0x38,		/* I/O limit */
	PciCBSVID	= 0x40,		/* subsystem vendor ID */
	PciCBSID	= 0x42,		/* subsystem ID */
	PciCBLMBAR	= 0x44,		/* legacy mode base address */
};

enum {
	/* bar bits */
	Barioaddr	= 1<<0,		/* vs. memory addr */
	Barwidthshift	= 1,
	Barwidthmask	= 3,
	Barwidth32	= 0,
	Barwidth64	= 2,
	Barprefetch	= 1<<3,
};

enum
{					/* command register */
	IOen		= (1<<0),
	MEMen		= (1<<1),
	MASen		= (1<<2),
	MemWrInv	= (1<<4),
	PErrEn		= (1<<6),
	SErrEn		= (1<<8),
};

/* capabilities */
enum {
	PciCapPMG       = 0x01,         /* power management */
	PciCapAGP       = 0x02,
	PciCapVPD       = 0x03,         /* vital product data */
	PciCapSID       = 0x04,         /* slot id */
	PciCapMSI       = 0x05,
	PciCapCHS       = 0x06,         /* compact pci hot swap */
	PciCapPCIX      = 0x07,
	PciCapHTC       = 0x08,         /* hypertransport irq conf */
	PciCapVND       = 0x09,         /* vendor specific information */
	PciCapPCIe      = 0x10,
	PciCapMSIX      = 0x11,
	PciCapSATA      = 0x12,
	PciCapHSW       = 0x0c,         /* hot swap */
};

typedef struct Pcidev Pcidev;
struct Pcidev
{
	int	tbdf;			/* type+bus+device+function */
	uint16_t	vid;			/* vendor ID */
	uint16_t	did;			/* device ID */

	uint16_t	pcr;

	uint8_t	rid;
	uint8_t	ccrp;
	uint8_t	ccru;
	uint8_t	ccrb;
	uint8_t	cls;
	uint8_t	ltr;

	struct {
		uintpci	bar;		/* base address */
		int	size;
	} mem[6];

	uint8_t	intl;			/* interrupt line */

	Pcidev*	list;
	Pcidev*	link;			/* next device on this bno */

	Pcidev*	parent;			/* up a bus */
	Pcidev*	bridge;			/* down a bus */

	int	pmrb;			/* power management register block */

	struct {
		uintpci	bar;
		int	size;
	} ioa, mema;
};

#define PCIWINDOW	0
#define PCIWADDR(va)	(PADDR(va)+PCIWINDOW)

#pragma varargck	type	"T"	int
#pragma varargck	type	"T"	uint
#define MSI_TARGET_ADDR		0xFFFFFFFFCULL
#define IRQpci 84

enum {
	MSICtrl = 0x02, /* message control register (16 bit) */
	MSIAddr = 0x04, /* message address register (64 bit) */
	MSIData32 = 0x08, /* message data register for 32 bit MSI (16 bit) */
	MSIData64 = 0x0C, /* message data register for 64 bit MSI (16 bit) */
};
typedef struct Ureg {
	ULONG	r0;
	ULONG	r1;
	ULONG	r2;
	ULONG	r3;
	ULONG	r4;
	ULONG	r5;
	ULONG	r6;
	ULONG	r7;
	ULONG	r8;
	ULONG	r9;
	ULONG	r10;
	ULONG	r11;
	ULONG	r12;	/* sb */
	union {
		ULONG	r13;
		ULONG	sp;
	};
	union {
		ULONG	r14;
		ULONG	link;
	};
	ULONG	type;	/* of exception */
	ULONG	psr;
	ULONG	pc;	/* interrupted addr */
} Ureg;
typedef struct Vctl Vctl;
typedef struct Vctl {
	Vctl*	next;		/* handlers on this vector */
	char	*name;		/* of driver, xallocated */
	void	(*f)(Ureg*, void*);	/* handler to call */
	void*	a;		/* argument to call it with */
} Vctl;
typedef struct Pciisr Pciisr;
struct Pciisr {
	void	(*f)(Ureg*, void*);
	void	*a;
	Pcidev	*p;
};
void pcienable(Pcidev *);
void pcidisable(Pcidev *);
void pcisetbme(Pcidev* );
Pcidev* pcimatch(Pcidev* prev, int vid, int did);
//void pciintrenable(int tbdf, void (*f)(Ureg*, void*), void *a);
//void pciintrdisable(int tbdf, void (*f)(Ureg*, void*), void *a);
typedef struct Pcisiz Pcisiz;
struct Pcisiz
{
	Pcidev*	dev;
	int	siz;
	int	bar;
};

enum
{
	MaxFNO		= 7,
	MaxUBN		= 255,
};