#include <exec/types.h>
#include <exec/execbase.h>
#include <workbench/startup.h>
#include <dos/dosextens.h>
#include <dos/rdargs.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/devicetree.h>
#include <stdarg.h>
#include <stdint.h>
#include <malloc.h>
#include "pci.h"

int main();

/* Startup code including workbench message support */
int _start()
{
    struct ExecBase *SysBase = *(struct ExecBase **)4;
    struct Process *p = NULL;
    struct WBStartup *wbmsg = NULL;
    int ret = 0;

    p = (struct Process *)SysBase->ThisTask;

    if (p->pr_CLI == 0)
    {
        WaitPort(&p->pr_MsgPort);
        wbmsg = (struct WBStartup *)GetMsg(&p->pr_MsgPort);
    }

    ret = main();

    if (wbmsg)
    {
        Forbid();
        ReplyMsg((struct Message *)wbmsg);
    }

    return ret;
}

struct ExecBase *       SysBase;
struct DosLibrary *     DOSBase;
static uint32_t*        PCIe;

#define APPNAME "PcieTest"

static const char version[] __attribute__((used)) = "$VER: " VERSION_STRING;




static Pcidev* pciroot;
static Pcidev* pcilist;
static Pcidev* pcitail;


/*
    Some properties, like e.g. #size-cells, are not always available in a key, but in that case the properties
    should be searched for in the parent. The process repeats recursively until either root key is found
    or the property is found, whichever occurs first
*/
CONST_APTR GetPropValueRecursive(APTR key, CONST_STRPTR property, APTR DeviceTreeBase)
{
    do {
        /* Find the property first */
        APTR prop = DT_FindProperty(key, property);

        if (prop)
        {
            /* If property is found, get its value and exit */
            return DT_GetPropValue(prop);
        }

        /* Property was not found, go to the parent and repeat */
        key = DT_GetParent(key);
    } while (key);

    return NULL;
}

void InitPCIe()
{
    APTR key;
    APTR DeviceTreeBase = OpenResource("devicetree.resource");

    if (DeviceTreeBase)
    {
        /* Get VC4 physical address of PCIe interface. Subsequently it will be translated to m68k physical address */
        key = DT_OpenKey("/aliases");
        if (key)
        {
            CONST_STRPTR pcie_alias = DT_GetPropValue(DT_FindProperty(key, "pcie0"));

            DT_CloseKey(key);

            if (pcie_alias != NULL)
            {
                key = DT_OpenKey(pcie_alias);

                if (key)
                {
                    int size_cells = 1;
                    int address_cells = 1;

                    const ULONG * siz = GetPropValueRecursive(key, "#size-cells", DeviceTreeBase);
                    const ULONG * addr = GetPropValueRecursive(key, "#address-cells", DeviceTreeBase);

                    if (siz != NULL)
                        size_cells = *siz;

                    if (addr != NULL)
                        address_cells = *addr;

                    const ULONG *reg = DT_GetPropValue(DT_FindProperty(key, "reg"));

                    PCIe = (uint32_t*)reg[address_cells - 1];

	                //Printf("PCIe %d\n", PCIe);

                    DT_CloseKey(key);
                }
            } else {
				Printf("PCIe alias == null\n");
			}
        }

        /* Open /soc key and learn about VC4 to CPU mapping. Use it to adjust the addresses obtained above */
        key = DT_OpenKey("/scb");
        if (key)
        {
            int size_cells = 1;
            int address_cells = 1;
            int cpu_address_cells = 1;

            const ULONG * siz = GetPropValueRecursive(key, "#size-cells", DeviceTreeBase);
            const ULONG * addr = GetPropValueRecursive(key, "#address-cells", DeviceTreeBase);
            const ULONG * cpu_addr = DT_GetPropValue(DT_FindProperty(DT_OpenKey("/"), "#address-cells"));

            if (siz != NULL)
                size_cells = *siz;

            if (addr != NULL)
                address_cells = *addr;

            if (cpu_addr != NULL)
                cpu_address_cells = *cpu_addr;

            const ULONG *reg = DT_GetPropValue(DT_FindProperty(key, "ranges"));

            ULONG phys_vc4 = reg[address_cells - 1];
            ULONG phys_cpu = reg[address_cells + cpu_address_cells - 1];

            PCIe = (uint32_t*)((ULONG)PCIe - phys_vc4 + phys_cpu);

            DT_CloseKey(key);
        }
    }
}

typedef void (*putc_func)(void *data, char c);

static int int_strlen(char *buf)
{
    int len = 0;

    if (buf)
        while(*buf++)
            len++;

    return len;
}

static void int_itoa(char *buf, char base, uintptr_t value, char zero_pad, int precision, int size_mod, char big, int alternate_form, int neg, char sign)
{
    int length = 0;

    do {
        char c = value % base;

        if (c >= 10) {
            if (big)
                c += 'A'-10;
            else
                c += 'a'-10;
        }
        else
            c += '0';

        value = value / base;
        buf[length++] = c;
    } while(value != 0);

    if (precision != 0)
    {
        while (length < precision)
            buf[length++] = '0';
    }
    else if (size_mod != 0 && zero_pad)
    {
        int sz_mod = size_mod;
        if (alternate_form)
        {
            if (base == 16) sz_mod -= 2;
            else if (base == 8) sz_mod -= 1;
        }
        if (neg)
            sz_mod -= 1;

        while (length < sz_mod)
            buf[length++] = '0';
    }
    if (alternate_form)
    {
        if (base == 8)
            buf[length++] = '0';
        if (base == 16) {
            buf[length++] = big ? 'X' : 'x';
            buf[length++] = '0';
        }
    }

    if (neg)
        buf[length++] = '-';
    else {
        if (sign == '+')
            buf[length++] = '+';
        else if (sign == ' ')
            buf[length++] = ' ';
    }

    for (int i=0; i < length/2; i++)
    {
        char tmp = buf[i];
        buf[i] = buf[length - i - 1];
        buf[length - i - 1] = tmp;
    }

    buf[length] = 0;
}

void vkprintf_pc(putc_func putc_f, void *putc_data, const char * restrict format, va_list args)
{
    char tmpbuf[32];

    while(*format)
    {
        char c;
        char alternate_form = 0;
        int size_mod = 0;
        int length_mod = 0;
        int precision = 0;
        char zero_pad = 0;
        char *str;
        char sign = 0;
        char leftalign = 0;
        uintptr_t value = 0;
        intptr_t ivalue = 0;

        char big = 0;

        c = *format++;

        if (c != '%')
        {
            putc_f(putc_data, c);
        }
        else
        {
            c = *format++;

            if (c == '#') {
                alternate_form = 1;
                c = *format++;
            }

            if (c == '-') {
                leftalign = 1;
                c = *format++;
            }

            if (c == ' ' || c == '+') {
                sign = c;
                c = *format++;
            }

            if (c == '0') {
                zero_pad = 1;
                c = *format++;
            }

            while(c >= '0' && c <= '9') {
                size_mod = size_mod * 10;
                size_mod = size_mod + c - '0';
                c = *format++;
            }

            if (c == '.') {
                c = *format++;
                while(c >= '0' && c <= '9') {
                    precision = precision * 10;
                    precision = precision + c - '0';
                    c = *format++;
                }
            }

            big = 0;

            if (c == 'h')
            {
                c = *format++;
                if (c == 'h')
                {
                    c = *format++;
                    length_mod = 1;
                }
                else length_mod = 2;
            }
            else if (c == 'l')
            {
                c = *format++;
                if (c == 'l')
                {
                    c = *format++;
                    length_mod = 8;
                }
                else length_mod = 4;
            }
            else if (c == 'j')
            {
                c = *format++;
                length_mod = 9;
            }
            else if (c == 't')
            {
                c = *format++;
                length_mod = 10;
            }
            else if (c == 'z')
            {
                c = *format++;
                length_mod = 11;
            }

            switch (c) {
                case 0:
                    return;

                case '%':
                    putc_f(putc_data, '%');
                    break;

                case 'p':
                    value = va_arg(args, uintptr_t);
                    int_itoa(tmpbuf, 16, value, 1, 2*sizeof(uintptr_t), 2*sizeof(uintptr_t), big, 1, 0, sign);
                    str = tmpbuf;
                    size_mod -= int_strlen(str);
                    while (*str) {
                        putc_f(putc_data, *str++);
                    }
                    break;

                case 'X':
                    big = 1;
                    /* fallthrough */
                case 'x':
                    switch (length_mod) {
                        case 8:
                            value = va_arg(args, uint64_t);
                            break;
                        case 9:
                            value = va_arg(args, uintmax_t);
                            break;
                        case 10:
                            value = va_arg(args, uintptr_t);
                            break;
                        case 11:
                            value = va_arg(args, ULONG);
                            break;
                        default:
                            value = va_arg(args, unsigned int);
                            break;
                    }
                    int_itoa(tmpbuf, 16, value, zero_pad, precision, size_mod, big, alternate_form, 0, sign);
                    str = tmpbuf;
                    size_mod -= int_strlen(str);
                    if (!leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    while(*str) {
                        putc_f(putc_data, *str++);
                    }
                    if (leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    break;

                case 'u':
                    switch (length_mod) {
                        case 8:
                            value = va_arg(args, uint64_t);
                            break;
                        case 9:
                            value = va_arg(args, uintmax_t);
                            break;
                        case 10:
                            value = va_arg(args, uintptr_t);
                            break;
                        case 11:
                            value = va_arg(args, ULONG);
                            break;
                        default:
                            value = va_arg(args, unsigned int);
                            break;
                    }
                    int_itoa(tmpbuf, 10, value, zero_pad, precision, size_mod, 0, alternate_form, 0, sign);
                    str = tmpbuf;
                    size_mod -= int_strlen(str);
                    if (!leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    while(*str) {
                        putc_f(putc_data, *str++);
                    }
                    if (leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    break;

                case 'd':
                case 'i':
                    switch (length_mod) {
                        case 8:
                            ivalue = va_arg(args, int64_t);
                            break;
                        case 9:
                            ivalue = va_arg(args, intmax_t);
                            break;
                        case 10:
                            ivalue = va_arg(args, intptr_t);
                            break;
                        case 11:
                            ivalue = va_arg(args, ULONG);
                            break;
                        default:
                            ivalue = va_arg(args, int);
                            break;
                    }
                    if (ivalue < 0)
                        int_itoa(tmpbuf, 10, -ivalue, zero_pad, precision, size_mod, 0, alternate_form, 1, sign);
                    else
                        int_itoa(tmpbuf, 10, ivalue, zero_pad, precision, size_mod, 0, alternate_form, 0, sign);
                    str = tmpbuf;
                    size_mod -= int_strlen(str);
                    if (!leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    while(*str) {
                        putc_f(putc_data, *str++);
                    }
                    if (leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    break;

                case 'o':
                    switch (length_mod) {
                        case 8:
                            value = va_arg(args, uint64_t);
                            break;
                        case 9:
                            value = va_arg(args, uintmax_t);
                            break;
                        case 10:
                            value = va_arg(args, uintptr_t);
                            break;
                        case 11:
                            value = va_arg(args, ULONG);
                            break;
                        default:
                            value = va_arg(args, uint32_t);
                            break;
                    }
                    int_itoa(tmpbuf, 8, value, zero_pad, precision, size_mod, 0, alternate_form, 0, sign);
                    str = tmpbuf;
                    size_mod -= int_strlen(str);
                    if (!leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    while(*str) {
                        putc_f(putc_data, *str++);
                    }
                    if (leftalign)
                        while(size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    break;

                case 'c':
                    putc_f(putc_data, va_arg(args, int));
                    break;

                case 's':
                    {
                        str = va_arg(args, char *);
                        do {
                            if (*str == 0)
                                break;
                            else
                                putc_f(putc_data, *str);
                            size_mod--;
                        } while(*str++ && --precision);
                        while (size_mod-- > 0)
                            putc_f(putc_data, ' ');
                    }
                    break;

                default:
                    putc_f(putc_data, c);
                    break;
            }
        }
    }
}

void putc_s(void *data, char c)
{
    char **ppchr = data;
    char *pchr = *ppchr;
    *pchr++ = c;
    *pchr = 0;
    *ppchr = pchr;
}

void _sprintf(char *buf, const char * restrict format, ...)
{
    va_list v;
    va_start(v, format);
    vkprintf_pc(putc_s, &buf, format, v);
    va_end(v);
}

#define nil ((void*)0)

static int pcimaxdno = 0;
static void*
cfgaddr(int tbdf, int rno)
{
	if(BUSBNO(tbdf) == 0 && BUSDNO(tbdf) == 0)
		return (uint8_t*)PCIe + rno;
	PCIe[EXT_CFG_INDEX] = BUSBNO(tbdf) << 20 | BUSDNO(tbdf) << 15 | BUSFNO(tbdf) << 12;
	//coherence();
	return ((uint8_t*)&PCIe[EXT_CFG_DATA]) + rno;
}
static int
pcicfgrw32(int tbdf, int rno, int data, int read)
{
	int x = -1;
	uint32_t *p;

	//Lock(&pcicfglock);
	if((p = cfgaddr(tbdf, rno & ~3)) != nil){
		if(read)
			x = *p;
		else
			*p = data;
	}
	//UnLock(&pcicfglock);
	return x;
}

static int
pcicfgrw16(int tbdf, int rno, int data, int read)
{
	int x = -1;
	uint16_t *p;

	//ilock(&pcicfglock);
	if((p = cfgaddr(tbdf, rno & ~1)) != nil){
		if(read)
			x = *p;
		else
			*p = data;
	}
	//iunlock(&pcicfglock);
	return x;
}
static int
pcicfgrw8(int tbdf, int rno, int data, int read)
{
	int x = -1;
	uint8_t *p;

	//ilock(&pcicfglock);
	if((p = cfgaddr(tbdf, rno)) != nil){
		if(read)
			x = *p;
		else
			*p = data;
	}
	//iunlock(&pcicfglock);
	return x;
}

int
pcicfgr32(Pcidev* pcidev, int rno)
{
	return pcicfgrw32(pcidev->tbdf, rno, 0, 1);
}
void
pcicfgw32(Pcidev* pcidev, int rno, int data)
{
	pcicfgrw32(pcidev->tbdf, rno, data, 0);
}
int
pcicfgr16(Pcidev* pcidev, int rno)
{
	return pcicfgrw16(pcidev->tbdf, rno, 0, 1);
}
void
pcicfgw16(Pcidev* pcidev, int rno, int data)
{
	pcicfgrw16(pcidev->tbdf, rno, data, 0);
}
int
pcicfgr8(Pcidev* pcidev, int rno)
{
	return pcicfgrw8(pcidev->tbdf, rno, 0, 1);
}
void
pcicfgw8(Pcidev* pcidev, int rno, int data)
{
	pcicfgrw8(pcidev->tbdf, rno, data, 0);
}

static uint32_t
pcibarsize(Pcidev *p, int rno)
{
	uint32_t v, size;

	v = pcicfgrw32(p->tbdf, rno, 0, 1);
	pcicfgrw32(p->tbdf, rno, 0xFFFFFFF0, 0);
	size = pcicfgrw32(p->tbdf, rno, 0, 1);
	if(v & 1)
		size |= 0xFFFF0000;
	pcicfgrw32(p->tbdf, rno, v, 0);

	return -(size & ~0x0F);
}

typedef unsigned long long uvlong;

static void
pcilhinv(Pcidev* p)
{
	int i;
	Pcidev *t;

	if(p == nil) {
		p = pciroot;
		Printf("pci dev type     vid  did intl memory\n");
	}
	for(t = p; t != nil; t = t->link) {
		Printf("%d  %2d/%d %.2ux %.2ux %.2ux %.4ux %.4ux %3d  ",
		      BUSBNO(t->tbdf), BUSDNO(t->tbdf), BUSFNO(t->tbdf),
		      t->ccrb, t->ccru, t->ccrp, t->vid, t->did, t->intl);

		for(i = 0; i < nelem(p->mem); i++) {
			if(t->mem[i].size == 0)
				continue;
			Printf("%d:%llux %d ", i,
			      (uvlong)t->mem[i].bar, t->mem[i].size);
		}
		if(t->bridge)
			Printf("->%d", BUSBNO(t->bridge->tbdf));
		Printf("\n");
	}
	while(p != nil) {
		if(p->bridge != nil)
			pcilhinv(p->bridge);
		p = p->link;
	}
}

static void pcihinv(Pcidev* p)
{
	pcilhinv(p);
}

static int
pcilscan(int bno, Pcidev** list, Pcidev *parent) {
	Pcidev *p, *head, *tail;
	int dno, fno, i, hdt, l, maxfno, maxubn, rno, sbn, tbdf, ubn;

	maxubn = bno;
	head = nil;
	tail = nil;
	for (dno = 0; dno <= pcimaxdno; dno++) {
		maxfno = 0;
		for (fno = 0; fno <= maxfno; fno++) {
			/*
			 * For this possible device, form the
			 * bus+device+function triplet needed to address it
			 * and try to read the vendor and device ID.
			 * If successful, allocate a device struct and
			 * start to fill it in with some useful information
			 * from the device's configuration space.
			 */
			Printf("bno: %d dno: %d fno: %d\n", bno, dno, fno);
			tbdf = MKBUS(BusPCI, bno, dno, fno);
			l = pcicfgrw32(tbdf, PciVID, 0, 1);
			if(l == 0xFFFFFFFF || l == 0)
				continue;
			p = AllocMem(sizeof(*p), MEMF_FAST);
			if(p == nil) {
				Printf("pcilscan: no memory\n");
			}

			p->tbdf = tbdf;
			p->vid = l;
			p->did = l>>16;

			if(pcilist != nil)
				pcitail->list = p;
			else
				pcilist = p;
			pcitail = p;

			p->pcr = pcicfgr16(p, PciPCR);
			p->rid = pcicfgr8(p, PciRID);
			p->ccrp = pcicfgr8(p, PciCCRp);
			p->ccru = pcicfgr8(p, PciCCRu);
			p->ccrb = pcicfgr8(p, PciCCRb);
			p->cls = pcicfgr8(p, PciCLS);
			p->ltr = pcicfgr8(p, PciLTR);

			p->intl = pcicfgr8(p, PciINTL);

			/*
			 * If the device is a multi-function device adjust the
			 * loop count so all possible functions are checked.
			 */
			hdt = pcicfgr8(p, PciHDT);
			if(hdt & 0x80)
				maxfno = MaxFNO;

			/*
			 * If appropriate, read the base address registers
			 * and work out the sizes.
			 */
			switch(p->ccrb) {
				case 0x00:		/* prehistoric */
				case 0x01:		/* mass storage controller */
				case 0x02:		/* network controller */
				case 0x03:		/* display controller */
				case 0x04:		/* multimedia device */
				case 0x07:		/* simple comm. controllers */
				case 0x08:		/* base system peripherals */
				case 0x09:		/* input devices */
				case 0x0A:		/* docking stations */
				case 0x0B:		/* processors */
				case 0x0C:		/* serial bus controllers */
				case 0x0D:		/* wireless controllers */
				case 0x0E:		/* intelligent I/O controllers */
				case 0x0F:		/* sattelite communication controllers */
				case 0x10:		/* encryption/decryption controllers */
				case 0x11:		/* signal processing controllers */
					if((hdt & 0x7F) != 0)
						break;
					rno = PciBAR0;
					for(i = 0; i <= 5; i++) {
						p->mem[i].bar = pcicfgr32(p, rno);
						p->mem[i].size = pcibarsize(p, rno);
						if((p->mem[i].bar & 7) == 4 && i < 5){
							rno += 4;
							p->mem[i].bar |= (uintpci)pcicfgr32(p, rno) << 32;
							i++;
						}
						rno += 4;
					}
					break;

				case 0x05:		/* memory controller */
				case 0x06:		/* bridge device */
				default:
					break;
			}

			p->parent = parent;
			if(head != nil)
				tail->link = p;
			else
				head = p;
			tail = p;
		}
	}

	*list = head;
	for(p = head; p != nil; p = p->link){
		/*
		 * Find PCI-PCI bridges and recursively descend the tree.
		 */
		if(p->ccrb != 0x06 || p->ccru != 0x04)
			continue;

		/*
		 * If the secondary or subordinate bus number is not
		 * initialised try to do what the PCI BIOS should have
		 * done and fill in the numbers as the tree is descended.
		 * On the way down the subordinate bus number is set to
		 * the maximum as it's not known how many buses are behind
		 * this one; the final value is set on the way back up.
		 */
		sbn = pcicfgr8(p, PciSBN);
		ubn = pcicfgr8(p, PciUBN);

		if(sbn == 0 || ubn == 0) {
			sbn = maxubn+1;
			/*
			 * Make sure memory, I/O and master enables are
			 * off, set the primary, secondary and subordinate
			 * bus numbers and clear the secondary status before
			 * attempting to scan the secondary bus.
			 *
			 * Initialisation of the bridge should be done here.
			 */
			pcicfgw32(p, PciPCR, 0xFFFF0000);
			l = (MaxUBN<<16)|(sbn<<8)|bno;
			pcicfgw32(p, PciPBN, l);
			pcicfgw16(p, PciSPSR, 0xFFFF);
			maxubn = pcilscan(sbn, &p->bridge, p);
			l = (maxubn<<16)|(sbn<<8)|bno;

			pcicfgw32(p, PciPBN, l);
		}
		else {
			if(ubn > maxubn)
				maxubn = ubn;
			pcilscan(sbn, &p->bridge, p);
		}
	}

	return maxubn;
}


void delay(ULONG us)
{
	ULONG timer = LE32(*(volatile ULONG*)0xf2003004);
    ULONG end = timer + us;

    if (end < timer) {
        while (end < LE32(*(volatile ULONG*)0xf2003004)) asm volatile("nop");
    }
    while (end > LE32(*(volatile ULONG*)0xf2003004)) asm volatile("nop");

}
static Pciisr pciisr[32];
static void
pciinterrupt(Ureg *ureg, void*asd)
{
	Pciisr *isr;
	uint32_t sts;

	sts = PCIe[MSI_INTR2_BASE + INTR_STATUS];
	if(sts == 0)
		return;
	PCIe[MSI_INTR2_BASE + INTR_CLR] = sts;
	for(isr = pciisr; sts != 0 && isr < &pciisr[nelem(pciisr)]; isr++, sts>>=1){
		if((sts & 1) != 0 && isr->f != nil)
			(*isr->f)(ureg, isr->a);
	}
	PCIe[MISC_EOI_CTRL] = 1;
}

static void
pcicfginit(void)
{
	uintpci mema, ioa;

	//fmtinstall('T', tbdffmt);

	pcilscan(0, &pciroot, nil);

	/*
	 * Work out how big the top bus is
	 *
	ioa = 0;
	mema = 0;
	pcibusmap(pciroot, &mema, &ioa, 0);

	/*
	 * Align the windows and map it
	 *
	ioa = 0;
	mema = PCIWIN;
	pcibusmap(pciroot, &mema, &ioa, 1);
	*/
}

static Vctl* vctl[Nirqs];
int irqtooearly = 0;

static void
intdismiss(Intrcpuregs *icp, uint32_t ack)
{
	icp->end = ack;
	//coherence();
}
void
intcunmask(uint32_t irq)
{
	Intrdistregs *idp = (Intrdistregs *)(ARMLOCAL+Intrdist);

	//ilock(&distlock);
	idp->setena[irq / Bi2long] = 1 << (irq % Bi2long);
	//iunlock(&distlock);
}

/*
 *  enable an irq interrupt
 *  note that the same private interrupt may be enabled on multiple cpus
 */
void
irqenable(int irq, void (*f)(Ureg*, void*), void* a)
{
	Vctl *v;
	int ena;
	static char name[] = "anon";

	/* permute irq numbers for pi4 */
	if(irq >= IRQlocal)
		irq = IRQLOCAL(irq);
	else
		irq = IRQGLOBAL(irq);
	if(irq >= nelem(vctl))
		Printf("irqenable irq %d\n", irq);

	if (irqtooearly) {
		Printf("irqenable for %d %s called too early\n", irq, (ULONG)name);
		return;
	}

	/*
	 * if in use, could be a private interrupt on a secondary cpu,
	 * or a shared irq number (eg emmc and sdhc)
	 */
	ena = 1;
	if(!ISSGI(irq) || vctl[irq] == nil) {
		v = AllocMem(sizeof(Vctl), MEMF_FAST);
		if (v == nil)
			Printf("irqenable: malloc Vctl\n");
		v->f = f;
		v->a = a;
		v->name = AllocMem(int_strlen(name)+1, MEMF_FAST);
		if (v->name == nil)
			Printf("irqenable: malloc name\n");
		CopyMemQuick(name, v->name, int_strlen(name));
		//strcpy(v->name, name);

		//lock(&vctllock);
		v->next = vctl[irq];
		if (v->next == nil)
			vctl[irq] = v;
		else if (!ISSGI(irq)) {
			/* shared irq number */
			vctl[irq] = v;
			ena = 0;
		} else {
			/* allocation race: someone else did it first */
			FreeVec(v->name);
			FreeVec(v);
		}
		//unlock(&vctllock);
	}
	if (ena) {
		intdismiss((Intrcpuregs *)(ARMLOCAL+Intrcpu), irq);
		intcunmask(irq);
	}
}
void
pcilink(void)
{
	int log2dmasize = 30;	// 1GB

	PCIe[RGR1_SW_INIT_1] |= 3;
	delay(200);
	PCIe[RGR1_SW_INIT_1] &= ~2;
	PCIe[MISC_PCIE_CTRL] &= ~5;
	delay(200);

	PCIe[MISC_HARD_PCIE_HARD_DEBUG] &= ~0x08000000;
	delay(200);

	PCIe[MSI_INTR2_BASE + INTR_CLR] = -1;
	PCIe[MSI_INTR2_BASE + INTR_MASK_SET] = -1;

	PCIe[MISC_CPU_2_PCIE_MEM_WIN0_LO] = 0;
	PCIe[MISC_CPU_2_PCIE_MEM_WIN0_HI] = 0;
	PCIe[MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT] = 0;
	PCIe[MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI] = 0;
	PCIe[MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI] = 0;

	// SCB_ACCESS_EN, CFG_READ_UR_MODE, MAX_BURST_SIZE_128, SCB0SIZE
	PCIe[MISC_MISC_CTRL] = 1<<12 | 1<<13 | 0<<20 | (log2dmasize-15)<<27;

	PCIe[MISC_RC_BAR2_CONFIG_LO] = (log2dmasize-15);
	PCIe[MISC_RC_BAR2_CONFIG_HI] = 0;

	PCIe[MISC_RC_BAR1_CONFIG_LO] = 0;
	PCIe[MISC_RC_BAR3_CONFIG_LO] = 0;

	PCIe[MISC_MSI_BAR_CONFIG_LO] = MSI_TARGET_ADDR | 1;
	PCIe[MISC_MSI_BAR_CONFIG_HI] = MSI_TARGET_ADDR>>32;
	PCIe[MISC_MSI_DATA_CONFIG] = 0xFFF86540;
	intrenable(IRQpci, pciinterrupt, nil, BUSUNKNOWN, "pci");

	// force to GEN2
	PCIe[(0xAC + 12)/4] = (PCIe[(0xAC + 12)/4] & ~15) | 2;	// linkcap
	PCIe[(0xAC + 48)/4] = (PCIe[(0xAC + 48)/4] & ~15) | 2;	// linkctl2

	PCIe[RGR1_SW_INIT_1] &= ~1;
	delay(500);

	if((PCIe[MISC_PCIE_STATUS] & 0x30) != 0x30){
		Printf("pcireset: phy link is down %d %d\n", (PCIe[MISC_PCIE_STATUS] & 0x30), PCIe[MISC_REVISION]);
		return;
	}

	PCIe[RC_CFG_PRIV1_ID_VAL3] = 0x060400;
	PCIe[RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1] &= ~0xC;
	PCIe[MISC_HARD_PCIE_HARD_DEBUG] |= 2;

	pcicfginit();
	pcihinv(nil);
}

int main()
{
    struct RDArgs *args;
    SysBase = *(struct ExecBase **)4;

    InitPCIe();

    DOSBase = (struct DosLibrary *)OpenLibrary("dos.library", 37);
    if (DOSBase == NULL)
        return -1;

    Printf("%s\n", (ULONG)&VERSION_STRING[6]);

	if (PCIe) {
		Printf("PCIe initialized 0x%08x %d\n", PCIe, *PCIe);

		pcilink();
	}

    CloseLibrary((struct Library *)DOSBase);
    return 0;
}
