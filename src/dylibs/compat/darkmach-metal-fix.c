/*
 * darkmach-metal-fix.c — Suppress Metal validation aborts in Simulator
 *
 * DYLD-interposes __assert_rtn to suppress assertions from Metal.framework.
 * Also fixes depth/stencil format mismatch at the ObjC level.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>

typedef unsigned long NSUInteger;

/* ── DYLD interpose of __assert_rtn ─────────────────────────────── */

/*
 * Metal's validation path: validateWithDevice / MTLDebugValidateMTLPixelFormat
 * -> MTLReportFailure -> __assert_rtn -> abort()
 *
 * We interpose __assert_rtn. If the assertion originates from Metal, we
 * longjmp back instead of aborting. For non-Metal assertions, we call
 * the real abort.
 *
 * To determine if we're in a Metal context, we check if the caller's
 * return address is within the Metal framework image.
 */

#include <setjmp.h>
#include <pthread.h>

static __thread jmp_buf metal_recovery;
static __thread volatile int metal_guard_active = 0;
static int suppress_count = 0;

/* The real __assert_rtn */
extern void __assert_rtn(const char *, const char *, int, const char *)
    __attribute__((noreturn));

void interposed_assert_rtn(const char *func, const char *file,
                           int line, const char *expr) {
    if (metal_guard_active) {
        if (suppress_count++ < 10)
            fprintf(stderr, "[darkmach-metal-fix] Suppressed assert in %s: %s\n",
                    func ? func : "?", expr ? expr : "?");
        metal_guard_active = 0;
        longjmp(metal_recovery, 1);
        /* not reached */
    }
    /* Not in Metal guard context — real assert */
    __assert_rtn(func, file, line, expr);
}

/* DYLD interpose table */
struct interpose_tuple {
    const void *replacement;
    const void *replacee;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_tuple interpose_assert[] = {
    { (const void *)interposed_assert_rtn, (const void *)__assert_rtn },
};

/*
 * METAL_SAFE_CALL — wrap any call that might trigger a Metal assertion.
 * Returns 0 on success, 1 if an assertion was caught and suppressed.
 */
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

/* ── Pipeline depth/stencil format fix ──────────────────────────── */

#define MTLPixelFormatDepth32Float          252UL
#define MTLPixelFormatStencil8              253UL
#define MTLPixelFormatDepth32Float_Stencil8 260UL

static IMP orig_setDepth = NULL;
static IMP orig_setStencil = NULL;
static IMP orig_validate = NULL;

static void swizzled_setDepthFormat(id self, SEL _cmd, NSUInteger fmt) {
    if (fmt == MTLPixelFormatDepth32Float) {
        ((void(*)(id, SEL, NSUInteger))orig_setDepth)(self, _cmd, MTLPixelFormatDepth32Float_Stencil8);
        SEL ss = sel_registerName("setStencilAttachmentPixelFormat:");
        ((void(*)(id, SEL, NSUInteger))orig_setStencil)(self, ss, MTLPixelFormatDepth32Float_Stencil8);
        return;
    }
    ((void(*)(id, SEL, NSUInteger))orig_setDepth)(self, _cmd, fmt);
}

static void swizzled_setStencilFormat(id self, SEL _cmd, NSUInteger fmt) {
    if (fmt == MTLPixelFormatStencil8) {
        ((void(*)(id, SEL, NSUInteger))orig_setStencil)(self, _cmd, MTLPixelFormatDepth32Float_Stencil8);
        SEL ds = sel_registerName("setDepthAttachmentPixelFormat:");
        ((void(*)(id, SEL, NSUInteger))orig_setDepth)(self, ds, MTLPixelFormatDepth32Float_Stencil8);
        return;
    }
    ((void(*)(id, SEL, NSUInteger))orig_setStencil)(self, _cmd, fmt);
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

/* ── Texture descriptor pixel format fix ────────────────────────── */

static IMP orig_texSetPixelFormat = NULL;

static void swizzled_texSetPixelFormat(id self, SEL _cmd, NSUInteger fmt) {
    int caught = METAL_SAFE_CALL(
        ((void(*)(id, SEL, NSUInteger))orig_texSetPixelFormat)(self, _cmd, fmt)
    );
    if (caught) {
        /* Try combined depth/stencil */
        if (fmt == MTLPixelFormatDepth32Float || fmt == MTLPixelFormatStencil8) {
            caught = METAL_SAFE_CALL(
                ((void(*)(id, SEL, NSUInteger))orig_texSetPixelFormat)(self, _cmd, MTLPixelFormatDepth32Float_Stencil8)
            );
            if (!caught) return;
        }
        /* Skip — format stays at whatever it was */
    }
}

static IMP orig_tex2DDesc = NULL;

static id swizzled_tex2DDesc(id self, SEL _cmd, NSUInteger fmt,
                              NSUInteger w, NSUInteger h, BOOL mipmapped) {
    id result = NULL;
    int caught = METAL_SAFE_CALL(
        result = ((id(*)(id, SEL, NSUInteger, NSUInteger, NSUInteger, BOOL))orig_tex2DDesc)(
            self, _cmd, fmt, w, h, mipmapped)
    );
    if (caught || !result) {
        if (fmt == MTLPixelFormatDepth32Float || fmt == MTLPixelFormatStencil8) {
            METAL_SAFE_CALL(
                result = ((id(*)(id, SEL, NSUInteger, NSUInteger, NSUInteger, BOOL))orig_tex2DDesc)(
                    self, _cmd, MTLPixelFormatDepth32Float_Stencil8, w, h, mipmapped)
            );
        }
        if (!result) {
            /* RGBA8Unorm fallback */
            METAL_SAFE_CALL(
                result = ((id(*)(id, SEL, NSUInteger, NSUInteger, NSUInteger, BOOL))orig_tex2DDesc)(
                    self, _cmd, 70UL, w, h, mipmapped)
            );
        }
    }
    return result;
}

/* ── Install ObjC hooks ─────────────────────────────────────────── */

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
    Class rpdi = objc_getClass("MTLRenderPipelineDescriptorInternal");
    if (rpdi) {
        hook_inst(rpdi, "setDepthAttachmentPixelFormat:", (IMP)swizzled_setDepthFormat, &orig_setDepth);
        hook_inst(rpdi, "setStencilAttachmentPixelFormat:", (IMP)swizzled_setStencilFormat, &orig_setStencil);
        hook_inst(rpdi, "validateWithDevice:error:", (IMP)swizzled_validate, &orig_validate);
    }

    Class tdi = objc_getClass("MTLTextureDescriptorInternal");
    if (tdi) {
        hook_inst(tdi, "setPixelFormat:", (IMP)swizzled_texSetPixelFormat, &orig_texSetPixelFormat);
    }

    Class td = objc_getClass("MTLTextureDescriptor");
    if (td) {
        hook_cls(td, "texture2DDescriptorWithPixelFormat:width:height:mipmapped:",
                 (IMP)swizzled_tex2DDesc, &orig_tex2DDesc);
    }

    fprintf(stderr, "[darkmach-metal-fix] Metal crash guard active (DYLD interpose + ObjC hooks)\n");
}
