#ifndef _EMU68_VC4_H
#define _EMU68_VC4_H

#include <exec/types.h>
#include <exec/libraries.h>

#include <dos/dos.h>
#include <intuition/intuitionbase.h>
#include <libraries/expansionbase.h>

#include "boardinfo.h"

#define STR(s) #s
#define XSTR(s) STR(s)

#define VC4CARD_VERSION  0
#define VC4CARD_REVISION 1
#define VC4CARD_PRIORITY 0
#define MBOX_SIZE        (512 * 4)

#define CLOCK_HZ        100000000

struct VC4Base {
    struct CardBase         vc4_LibNode;
    BPTR                    vc4_SegList;
    struct ExecBase *       vc4_SysBase;
    struct ExpansionBase *  vc4_ExpansionBase;
    struct DOSBase *        vc4_DOSBase;
    struct IntuitionBase *  vc4_IntuitionBase;
    APTR                    vc4_DeviceTreeBase;
    APTR                    vc4_MailBox;
    APTR                    vc4_RequestBase;
    APTR                    vc4_Request;
    APTR                    vc4_MemBase;
    uint32_t                vc4_MemSize;
    APTR                    vc4_Framebuffer;
    uint32_t                vc4_Pitch;
    uint16_t                vc4_Enabled;
};

struct Size {
    UWORD width;
    UWORD height;
};



void SetDAC(struct BoardInfo *bi asm("a0"), RGBFTYPE format asm("d7"));
void SetGC(struct BoardInfo *bi asm("a0"), struct ModeInfo *mode_info asm("a1"), BOOL border asm("d0"));
UWORD SetSwitch (__REGA0(struct BoardInfo *b), __REGD0(UWORD enabled));
void SetPanning (__REGA0(struct BoardInfo *b), __REGA1(UBYTE *addr), __REGD0(UWORD width), __REGD1(WORD x_offset), __REGD2(WORD y_offset), __REGD7(RGBFTYPE format));
void SetColorArray (__REGA0(struct BoardInfo *b), __REGD0(UWORD start), __REGD1(UWORD num));
UWORD CalculateBytesPerRow (__REGA0(struct BoardInfo *b), __REGD0(UWORD width), __REGD7(RGBFTYPE format));
APTR CalculateMemory (__REGA0(struct BoardInfo *b), __REGA1(unsigned long addr), __REGD7(RGBFTYPE format));
ULONG GetCompatibleFormats (__REGA0(struct BoardInfo *b), __REGD7(RGBFTYPE format));
UWORD SetDisplay (__REGA0(struct BoardInfo *b), __REGD0(UWORD enabled));
LONG ResolvePixelClock (__REGA0(struct BoardInfo *b), __REGA1(struct ModeInfo *mode_info), __REGD0(ULONG pixel_clock), __REGD7(RGBFTYPE format));
ULONG GetPixelClock (__REGA0(struct BoardInfo *b), __REGA1(struct ModeInfo *mode_info), __REGD0(ULONG index), __REGD7(RGBFTYPE format));
void SetClock (__REGA0(struct BoardInfo *b));
void SetMemoryMode (__REGA0(struct BoardInfo *b), __REGD7(RGBFTYPE format));
void SetWriteMask (__REGA0(struct BoardInfo *b), __REGD0(UBYTE mask));
void SetClearMask (__REGA0(struct BoardInfo *b), __REGD0(UBYTE mask));
void SetReadPlane (__REGA0(struct BoardInfo *b), __REGD0(UBYTE plane));
void WaitVerticalSync (__REGA0(struct BoardInfo *b), __REGD0(BOOL toggle));
BOOL GetVSyncState(__REGA0(struct BoardInfo *b), __REGD0(BOOL toggle));
void FillRect (__REGA0(struct BoardInfo *b), __REGA1(struct RenderInfo *r), __REGD0(WORD x), __REGD1(WORD y), __REGD2(WORD w), __REGD3(WORD h), __REGD4(ULONG color), __REGD5(UBYTE mask), __REGD7(RGBFTYPE format));
void InvertRect (__REGA0(struct BoardInfo *b), __REGA1(struct RenderInfo *r), __REGD0(WORD x), __REGD1(WORD y), __REGD2(WORD w), __REGD3(WORD h), __REGD4(UBYTE mask), __REGD7(RGBFTYPE format));
void BlitRect (__REGA0(struct BoardInfo *b), __REGA1(struct RenderInfo *r), __REGD0(WORD x), __REGD1(WORD y), __REGD2(WORD dx), __REGD3(WORD dy), __REGD4(WORD w), __REGD5(WORD h), __REGD6(UBYTE mask), __REGD7(RGBFTYPE format));
void BlitRectNoMaskComplete (__REGA0(struct BoardInfo *b), __REGA1(struct RenderInfo *rs), __REGA2(struct RenderInfo *rt), __REGD0(WORD x), __REGD1(WORD y), __REGD2(WORD dx), __REGD3(WORD dy), __REGD4(WORD w), __REGD5(WORD h), __REGD6(UBYTE minterm), __REGD7(RGBFTYPE format));
void BlitTemplate (__REGA0(struct BoardInfo *b), __REGA1(struct RenderInfo *r), __REGA2(struct Template *t), __REGD0(WORD x), __REGD1(WORD y), __REGD2(WORD w), __REGD3(WORD h), __REGD4(UBYTE mask), __REGD7(RGBFTYPE format));
void BlitPattern (__REGA0(struct BoardInfo *b), __REGA1(struct RenderInfo *r), __REGA2(struct Pattern *p), __REGD0(WORD x), __REGD1(WORD y), __REGD2(WORD w), __REGD3(WORD h), __REGD4(UBYTE mask), __REGD7(RGBFTYPE format));
void DrawLine (__REGA0(struct BoardInfo *b), __REGA1(struct RenderInfo *r), __REGA2(struct Line *l), __REGD0(UBYTE mask), __REGD7(RGBFTYPE format));
void BlitPlanar2Chunky (__REGA0(struct BoardInfo *b), __REGA1(struct BitMap *bm), __REGA2(struct RenderInfo *r), __REGD0(SHORT x), __REGD1(SHORT y), __REGD2(SHORT dx), __REGD3(SHORT dy), __REGD4(SHORT w), __REGD5(SHORT h), __REGD6(UBYTE minterm), __REGD7(UBYTE mask));
void BlitPlanar2Direct (__REGA0(struct BoardInfo *b), __REGA1(struct BitMap *bm), __REGA2(struct RenderInfo *r), __REGA3(struct ColorIndexMapping *clut), __REGD0(SHORT x), __REGD1(SHORT y), __REGD2(SHORT dx), __REGD3(SHORT dy), __REGD4(SHORT w), __REGD5(SHORT h), __REGD6(UBYTE minterm), __REGD7(UBYTE mask));
void SetSprite (__REGA0(struct BoardInfo *b), __REGD0(BOOL enable), __REGD7(RGBFTYPE format));
void SetSpritePosition (__REGA0(struct BoardInfo *b), __REGD0(WORD x), __REGD1(WORD y), __REGD7(RGBFTYPE format));
void SetSpriteImage (__REGA0(struct BoardInfo *b), __REGD7(RGBFTYPE format));
void SetSpriteColor (__REGA0(struct BoardInfo *b), __REGD0(UBYTE idx), __REGD1(UBYTE R), __REGD2(UBYTE G), __REGD3(UBYTE B), __REGD7(RGBFTYPE format));

#endif /* _EMU68_VC4_H */
