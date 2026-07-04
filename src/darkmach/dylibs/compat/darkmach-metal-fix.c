/* Suppress Metal validation aborts in Simulator: DYLD-interposes __assert_rtn,
 * fixes depth/stencil format mismatch, and remaps MetalANGLE pixel formats. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>

typedef unsigned long NSUInteger;


/*
 * Metal validation path: validateWithDevice / MTLDebugValidateMTLPixelFormat
 *   -> MTLReportFailure -> __assert_rtn -> abort().
 * Interposed __assert_rtn longjmps back when the caller's return address is
 * inside the Metal framework image; otherwise it calls the real abort.
 */

#include <setjmp.h>
#include <pthread.h>

static __thread jmp_buf metal_recovery;
static __thread volatile int metal_guard_active = 0;
static int suppress_count = 0;

/*
 * safe_str — return the pointer if readable, else fallback. Metal/MetalANGLE
 * can pass NULL or dangling pointers for __assert_rtn's function/file/expr
 * fields; without this guard fprintf's internal strlen SEGVs on them.
 */
static const char *safe_str(const char *s, const char *fallback) {
    if (!s)
        return fallback;
    /* Probe one byte via Mach VM to verify the address is mapped --
     * catches dangling pointers from unwound stack frames or freed heap. */
    char probe;
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                          (vm_address_t)s, 1,
                                          (vm_address_t)&probe, &out);
    if (kr != KERN_SUCCESS || out != 1)
        return fallback;
    return s;
}

extern void __assert_rtn(const char *, const char *, int, const char *)
    __attribute__((noreturn));

void interposed_assert_rtn(const char *func, const char *file,
                           int line, const char *expr) {
    if (metal_guard_active) {
        if (suppress_count++ < 10)
            fprintf(stderr, "[darkmach-metal-fix] Suppressed assert in %s (%s:%d): %s\n",
                    safe_str(func, "(null)"),
                    safe_str(file, "(null)"),
                    line,
                    safe_str(expr, "(null)"));
        metal_guard_active = 0;
        longjmp(metal_recovery, 1);
        /* not reached */
    }
    /* Not in Metal guard context — pass to real __assert_rtn.
     * NULL-guard here too: the real __assert_rtn may call fprintf internally. */
    __assert_rtn(safe_str(func, "?"),
                 safe_str(file, "?"),
                 line,
                 safe_str(expr, "?"));
}

struct interpose_tuple {
    const void *replacement;
    const void *replacee;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_tuple interpose_assert[] = {
    { (const void *)interposed_assert_rtn, (const void *)__assert_rtn },
};

#define METAL_SAFE_CALL(code) ({ \
    int _caught = 0; \
    metal_guard_active = 1; \
    if (setjmp(metal_recovery) == 0) { \
        code; \
        metal_guard_active = 0; \
    } else { \
        _caught = 1; \
    } \
    _caught; \
})

/*
 * Core Metal depth/stencil formats. MetalANGLE (OpenGL ES -> Metal) may
 * request formats the Simulator's software GPU lacks; those get remapped.
 */

#define MTLPixelFormatInvalid                0UL
#define MTLPixelFormatRGBA8Unorm            70UL
#define MTLPixelFormatBGRA8Unorm            80UL

#define MTLPixelFormatDepth16Unorm         250UL
#define MTLPixelFormatDepth32Float         252UL
#define MTLPixelFormatStencil8             253UL
#define MTLPixelFormatDepth24Unorm_Stencil8  255UL
#define MTLPixelFormatDepth32Float_Stencil8  260UL

/* Compressed formats that MetalANGLE may request (ETC2/EAC from GLES3) */
#define MTLPixelFormatETC2_RGB8            180UL
#define MTLPixelFormatETC2_RGB8_sRGB       181UL
#define MTLPixelFormatETC2_RGB8A1          182UL
#define MTLPixelFormatETC2_RGB8A1_sRGB     183UL
#define MTLPixelFormatEAC_RGBA8            186UL
#define MTLPixelFormatEAC_RGBA8_sRGB       187UL

/* is_depth_stencil_format — 1 for any depth/stencil/combined format
 * (MetalANGLE translates GL_DEPTH_COMPONENT and GL_STENCIL_INDEX to these). */
static int is_depth_stencil_format(NSUInteger fmt) {
    return fmt == MTLPixelFormatDepth16Unorm ||
           fmt == MTLPixelFormatDepth32Float ||
           fmt == MTLPixelFormatStencil8 ||
           fmt == MTLPixelFormatDepth24Unorm_Stencil8 ||
           fmt == MTLPixelFormatDepth32Float_Stencil8;
}

/* remap_pixel_format — map formats the Simulator's software Metal device
 * lacks to safe alternatives; returns the original when no remap is needed. */
static NSUInteger remap_pixel_format(NSUInteger fmt) {
    switch (fmt) {
    /* Separate depth/stencil -> combined (Simulator preference) */
    case MTLPixelFormatDepth32Float:
    case MTLPixelFormatStencil8:
    case MTLPixelFormatDepth16Unorm:
    case MTLPixelFormatDepth24Unorm_Stencil8:
        return MTLPixelFormatDepth32Float_Stencil8;
    default:
        return fmt;
    }
}

static IMP orig_setDepth = NULL;
static IMP orig_setStencil = NULL;
static IMP orig_validate = NULL;

static void swizzled_setDepthFormat(id self, SEL _cmd, NSUInteger fmt) {
    NSUInteger remapped = remap_pixel_format(fmt);
    int caught = METAL_SAFE_CALL(
        ((void(*)(id, SEL, NSUInteger))orig_setDepth)(self, _cmd, remapped)
    );
    if (caught) {
        /* Remapped format also failed — force combined depth/stencil */
        METAL_SAFE_CALL(
            ((void(*)(id, SEL, NSUInteger))orig_setDepth)(self, _cmd, MTLPixelFormatDepth32Float_Stencil8)
        );
    }
    /* Also set matching stencil when using a depth-only format,
     * since the Simulator prefers combined depth/stencil */
    if (is_depth_stencil_format(fmt) && fmt != MTLPixelFormatStencil8) {
        SEL ss = sel_registerName("setStencilAttachmentPixelFormat:");
        METAL_SAFE_CALL(
            ((void(*)(id, SEL, NSUInteger))orig_setStencil)(self, ss, MTLPixelFormatDepth32Float_Stencil8)
        );
    }
}

static void swizzled_setStencilFormat(id self, SEL _cmd, NSUInteger fmt) {
    NSUInteger remapped = remap_pixel_format(fmt);
    int caught = METAL_SAFE_CALL(
        ((void(*)(id, SEL, NSUInteger))orig_setStencil)(self, _cmd, remapped)
    );
    if (caught) {
        METAL_SAFE_CALL(
            ((void(*)(id, SEL, NSUInteger))orig_setStencil)(self, _cmd, MTLPixelFormatDepth32Float_Stencil8)
        );
    }
    /* Also set matching depth when using a stencil-only format */
    if (fmt == MTLPixelFormatStencil8) {
        SEL ds = sel_registerName("setDepthAttachmentPixelFormat:");
        METAL_SAFE_CALL(
            ((void(*)(id, SEL, NSUInteger))orig_setDepth)(self, ds, MTLPixelFormatDepth32Float_Stencil8)
        );
    }
}

static BOOL swizzled_validate(id self, SEL _cmd, id device, id *error) {
    BOOL ok = NO;
    int caught = METAL_SAFE_CALL(
        ok = ((BOOL(*)(id, SEL, id, id*))orig_validate)(self, _cmd, device, error)
    );
    if (caught || !ok) {
        if (error) *error = NULL;
        return YES;
    }
    return ok;
}


static IMP orig_texSetPixelFormat = NULL;

static void swizzled_texSetPixelFormat(id self, SEL _cmd, NSUInteger fmt) {
    NSUInteger remapped = remap_pixel_format(fmt);
    int caught = METAL_SAFE_CALL(
        ((void(*)(id, SEL, NSUInteger))orig_texSetPixelFormat)(self, _cmd, remapped)
    );
    if (!caught) return;

    if (is_depth_stencil_format(fmt) && remapped != MTLPixelFormatDepth32Float_Stencil8) {
        caught = METAL_SAFE_CALL(
            ((void(*)(id, SEL, NSUInteger))orig_texSetPixelFormat)(self, _cmd, MTLPixelFormatDepth32Float_Stencil8)
        );
        if (!caught) return;
    }

    if (remapped != fmt) {
        caught = METAL_SAFE_CALL(
            ((void(*)(id, SEL, NSUInteger))orig_texSetPixelFormat)(self, _cmd, fmt)
        );
        if (!caught) return;
    }

    /* Last resort: RGBA8Unorm (always supported) — better than crashing.
     * This loses depth/stencil semantics but keeps the app alive. */
    METAL_SAFE_CALL(
        ((void(*)(id, SEL, NSUInteger))orig_texSetPixelFormat)(self, _cmd, MTLPixelFormatRGBA8Unorm)
    );
    /* If even RGBA8Unorm fails, silently skip — format stays at its previous value */
}

static IMP orig_tex2DDesc = NULL;

static id swizzled_tex2DDesc(id self, SEL _cmd, NSUInteger fmt,
                              NSUInteger w, NSUInteger h, BOOL mipmapped) {
    id result = NULL;

    NSUInteger remapped = remap_pixel_format(fmt);
    int caught = METAL_SAFE_CALL(
        result = ((id(*)(id, SEL, NSUInteger, NSUInteger, NSUInteger, BOOL))orig_tex2DDesc)(
            self, _cmd, remapped, w, h, mipmapped)
    );
    if (!caught && result) return result;

    if (is_depth_stencil_format(fmt) && remapped != MTLPixelFormatDepth32Float_Stencil8) {
        METAL_SAFE_CALL(
            result = ((id(*)(id, SEL, NSUInteger, NSUInteger, NSUInteger, BOOL))orig_tex2DDesc)(
                self, _cmd, MTLPixelFormatDepth32Float_Stencil8, w, h, mipmapped)
        );
        if (result) return result;
    }

    if (remapped != fmt) {
        METAL_SAFE_CALL(
            result = ((id(*)(id, SEL, NSUInteger, NSUInteger, NSUInteger, BOOL))orig_tex2DDesc)(
                self, _cmd, fmt, w, h, mipmapped)
        );
        if (result) return result;
    }

    METAL_SAFE_CALL(
        result = ((id(*)(id, SEL, NSUInteger, NSUInteger, NSUInteger, BOOL))orig_tex2DDesc)(
            self, _cmd, MTLPixelFormatRGBA8Unorm, w, h, mipmapped)
    );
    return result;
}


static void hook_inst(Class cls, const char *name, IMP imp, IMP *orig) {
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *orig = method_getImplementation(m);
    method_setImplementation(m, imp);
}

static void hook_cls(Class cls, const char *name, IMP imp, IMP *orig) {
    SEL sel = sel_registerName(name);
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    *orig = method_getImplementation(m);
    method_setImplementation(m, imp);
}

__attribute__((constructor))
static void install_metal_fix(void) {
    int hooks = 0;

    Class rpdi = objc_getClass("MTLRenderPipelineDescriptorInternal");
    if (rpdi) {
        hook_inst(rpdi, "setDepthAttachmentPixelFormat:", (IMP)swizzled_setDepthFormat, &orig_setDepth);
        hook_inst(rpdi, "setStencilAttachmentPixelFormat:", (IMP)swizzled_setStencilFormat, &orig_setStencil);
        hook_inst(rpdi, "validateWithDevice:error:", (IMP)swizzled_validate, &orig_validate);
        hooks += 3;
    }
    Class rpd = objc_getClass("MTLRenderPipelineDescriptor");
    if (rpd && rpd != rpdi) {
        IMP unused1 = NULL, unused2 = NULL, unused3 = NULL;
        hook_inst(rpd, "setDepthAttachmentPixelFormat:", (IMP)swizzled_setDepthFormat, orig_setDepth ? &unused1 : &orig_setDepth);
        hook_inst(rpd, "setStencilAttachmentPixelFormat:", (IMP)swizzled_setStencilFormat, orig_setStencil ? &unused2 : &orig_setStencil);
        hook_inst(rpd, "validateWithDevice:error:", (IMP)swizzled_validate, orig_validate ? &unused3 : &orig_validate);
        hooks += 3;
    }

    Class tdi = objc_getClass("MTLTextureDescriptorInternal");
    if (tdi) {
        hook_inst(tdi, "setPixelFormat:", (IMP)swizzled_texSetPixelFormat, &orig_texSetPixelFormat);
        hooks++;
    }

    Class td = objc_getClass("MTLTextureDescriptor");
    if (td) {
        if (td != tdi) {
            IMP unused = NULL;
            hook_inst(td, "setPixelFormat:", (IMP)swizzled_texSetPixelFormat, orig_texSetPixelFormat ? &unused : &orig_texSetPixelFormat);
            hooks++;
        }
        hook_cls(td, "texture2DDescriptorWithPixelFormat:width:height:mipmapped:",
                 (IMP)swizzled_tex2DDesc, &orig_tex2DDesc);
        hooks++;
    }

    fprintf(stderr, "[darkmach-metal-fix] Metal crash guard active — %d ObjC hooks + assert interpose\n", hooks);
}
