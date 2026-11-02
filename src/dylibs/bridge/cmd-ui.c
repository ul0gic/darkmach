/* Not built standalone — #included into darkmach-bridge.c as a unity build. */
#include "darkmach-bridge.h"


typedef struct { double x, y, w, h; } ui_cgrect_t;
typedef struct { double x, y; } ui_cgpoint_t;
typedef struct { double w, h; } ui_cgsize_t;

#define UI_RESULT_SZ 4096
#define UI_TIMEOUT_NS (3LL * NSEC_PER_SEC)

static ui_cgrect_t ui_get_frame(id view) {
    SEL frameSel = sel_registerName("frame");
    ui_cgrect_t (*getFrame)(id, SEL) = (ui_cgrect_t (*)(id, SEL))objc_msgSend;
    return getFrame(view, frameSel);
}

static const char *ui_get_label(id view) {
    SEL accSel = sel_registerName("accessibilityLabel");
    id (*getAcc)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id accLabel = getAcc(view, accSel);
    return accLabel ? nsobject_desc(accLabel) : NULL;
}

static const char *ui_get_text(id view) {
    SEL textSel = sel_registerName("text");
    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
    if (responds(view, respondsSel, textSel)) {
        id (*getText)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id textObj = getText(view, textSel);
        if (textObj) return nsobject_desc(textObj);
    }
    return NULL;
}

static const char *ui_get_button_title(id view) {
    SEL titleLabelSel = sel_registerName("titleLabel");
    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
    if (!responds(view, respondsSel, titleLabelSel)) return NULL;
    id (*getTitleLabel)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id titleLabel = getTitleLabel(view, titleLabelSel);
    if (!titleLabel) return NULL;
    return ui_get_text(titleLabel);
}

static BOOL ui_is_kind(id view, const char *className) {
    Class cls = objc_getClass(className);
    if (!cls) return NO;
    SEL isKindSel = sel_registerName("isKindOfClass:");
    BOOL (*isKind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
    return isKind(view, isKindSel, cls);
}

static id ui_shared_app(void) {
    Class appClass = objc_getClass("UIApplication");
    if (!appClass) return nil;
    SEL sharedSel = sel_registerName("sharedApplication");
    id (*getApp)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    return getApp((id)appClass, sharedSel);
}

static id ui_key_window(void) {
    id app = ui_shared_app();
    if (!app) return nil;

    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;

    SEL scenesSel = sel_registerName("connectedScenes");
    if (responds(app, respondsSel, scenesSel)) {
        id (*getScenes)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id scenes = getScenes(app, scenesSel);
        if (scenes) {
            SEL allSel = sel_registerName("allObjects");
            id (*getAll)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id allScenes = getAll(scenes, allSel);
            SEL countSel = sel_registerName("count");
            long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
            long cnt = getCount(allScenes, countSel);
            SEL indexSel = sel_registerName("objectAtIndex:");
            id (*getAt)(id, SEL, unsigned long) =
                (id (*)(id, SEL, unsigned long))objc_msgSend;

            for (long i = 0; i < cnt; i++) {
                id scene = getAt(allScenes, indexSel, (unsigned long)i);
                if (!ui_is_kind(scene, "UIWindowScene")) continue;
                SEL windowsSel = sel_registerName("windows");
                id (*getWindows)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                id windows = getWindows(scene, windowsSel);
                long winCnt = getCount(windows, countSel);
                for (long j = 0; j < winCnt; j++) {
                    id win = getAt(windows, indexSel, (unsigned long)j);
                    SEL isKeySel = sel_registerName("isKeyWindow");
                    BOOL (*isKey)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
                    if (isKey(win, isKeySel)) return win;
                }
                if (winCnt > 0) return getAt(windows, indexSel, 0);
            }
        }
    }

    SEL keyWinSel = sel_registerName("keyWindow");
    id (*getKeyWin)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    return getKeyWin(app, keyWinSel);
}

static id ui_find_by_label(id view, const char *label, int *matchIdx, int target) {
    if (!view) return nil;
    const char *viewLabel = ui_get_label(view);
    if (viewLabel && strstr(viewLabel, label)) {
        if (*matchIdx == target) return view;
        (*matchIdx)++;
    }

    SEL subviewsSel = sel_registerName("subviews");
    id (*getSubs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id subviews = getSubs(view, subviewsSel);
    if (!subviews) return nil;
    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long cnt = getCount(subviews, countSel);
    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    for (long i = 0; i < cnt; i++) {
        id found = ui_find_by_label(getAt(subviews, indexSel, (unsigned long)i),
                                     label, matchIdx, target);
        if (found) return found;
    }
    return nil;
}

static id ui_find_by_class_text(id view, const char *className,
                                 const char *text, int *matchIdx, int target) {
    if (!view) return nil;

    const char *viewClass = class_getName(object_getClass(view));
    BOOL classMatch = (strcmp(viewClass, className) == 0) ||
                      ui_is_kind(view, className);

    if (classMatch) {
        if (text) {
            const char *vt = ui_get_text(view);
            const char *bt = ui_get_button_title(view);
            if ((vt && strstr(vt, text)) || (bt && strstr(bt, text))) {
                if (*matchIdx == target) return view;
                (*matchIdx)++;
            }
        } else {
            if (*matchIdx == target) return view;
            (*matchIdx)++;
        }
    }

    SEL subviewsSel = sel_registerName("subviews");
    id (*getSubs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id subviews = getSubs(view, subviewsSel);
    if (!subviews) return nil;
    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long cnt = getCount(subviews, countSel);
    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    for (long i = 0; i < cnt; i++) {
        id found = ui_find_by_class_text(
            getAt(subviews, indexSel, (unsigned long)i),
            className, text, matchIdx, target);
        if (found) return found;
    }
    return nil;
}

static id ui_find_scroll_view(id view) {
    if (!view) return nil;
    if (ui_is_kind(view, "UIScrollView")) return view;

    SEL subviewsSel = sel_registerName("subviews");
    id (*getSubs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id subviews = getSubs(view, subviewsSel);
    if (!subviews) return nil;
    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long cnt = getCount(subviews, countSel);
    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    for (long i = 0; i < cnt; i++) {
        id found = ui_find_scroll_view(
            getAt(subviews, indexSel, (unsigned long)i));
        if (found) return found;
    }
    return nil;
}

static id ui_find_text_field(id view) {
    if (!view) return nil;
    if (ui_is_kind(view, "UITextField") || ui_is_kind(view, "UITextView"))
        return view;

    SEL subviewsSel = sel_registerName("subviews");
    id (*getSubs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id subviews = getSubs(view, subviewsSel);
    if (!subviews) return nil;
    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long cnt = getCount(subviews, countSel);
    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    for (long i = 0; i < cnt; i++) {
        id found = ui_find_text_field(
            getAt(subviews, indexSel, (unsigned long)i));
        if (found) return found;
    }
    return nil;
}

static id ui_find_first_responder(id view) {
    if (!view) return nil;
    SEL isFirstSel = sel_registerName("isFirstResponder");
    BOOL (*isFirst)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
    if (isFirst(view, isFirstSel)) return view;

    SEL subviewsSel = sel_registerName("subviews");
    id (*getSubs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id subviews = getSubs(view, subviewsSel);
    if (!subviews) return nil;
    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long cnt = getCount(subviews, countSel);
    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    for (long i = 0; i < cnt; i++) {
        id found = ui_find_first_responder(
            getAt(subviews, indexSel, (unsigned long)i));
        if (found) return found;
    }
    return nil;
}

static id ui_top_vc(id vc) {
    if (!vc) return nil;

    SEL presentedSel = sel_registerName("presentedViewController");
    id (*getPresented)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id presented = getPresented(vc, presentedSel);
    if (presented) return ui_top_vc(presented);

    if (ui_is_kind(vc, "UINavigationController")) {
        SEL topSel = sel_registerName("topViewController");
        id (*getTop)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id top = getTop(vc, topSel);
        if (top) return ui_top_vc(top);
    }

    if (ui_is_kind(vc, "UITabBarController")) {
        SEL selVC = sel_registerName("selectedViewController");
        id (*getSel)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id selected = getSel(vc, selVC);
        if (selected) return ui_top_vc(selected);
    }

    return vc;
}

static void ui_send_tap_action(id view) {
    if (ui_is_kind(view, "UIControl")) {
        SEL sendSel = sel_registerName("sendActionsForControlEvents:");
        void (*sendActions)(id, SEL, unsigned long) =
            (void (*)(id, SEL, unsigned long))objc_msgSend;
        /* UIControlEventTouchUpInside = 1 << 6 = 64 */
        sendActions(view, sendSel, 64UL);
        return;
    }

    SEL gesturesSel = sel_registerName("gestureRecognizers");
    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
    if (!responds(view, respondsSel, gesturesSel)) return;

    id (*getGestures)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id gestures = getGestures(view, gesturesSel);
    if (!gestures) return;

    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long cnt = getCount(gestures, countSel);
    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    for (long i = 0; i < cnt; i++) {
        id gr = getAt(gestures, indexSel, (unsigned long)i);
        if (ui_is_kind(gr, "UITapGestureRecognizer")) {
            SEL stateSel = sel_registerName("setState:");
            void (*setState)(id, SEL, long) =
                (void (*)(id, SEL, long))objc_msgSend;
            /* UIGestureRecognizerStateRecognized = 3 */
            setState(gr, stateSel, 3);
            return;
        }
    }
}

static id ui_nsstring(const char *cstr) {
    Class nsStr = objc_getClass("NSString");
    SEL allocSel = sel_registerName("alloc");
    SEL initSel = sel_registerName("initWithUTF8String:");
    id (*alloc)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id (*initUTF8)(id, SEL, const char *) =
        (id (*)(id, SEL, const char *))objc_msgSend;
    return initUTF8(alloc((id)nsStr, allocSel), initSel, cstr);
}

/* ObjC blocks cannot capture C arrays, so these are heap-allocated and passed by pointer. */

typedef struct {
    char result[UI_RESULT_SZ];
    double tap_x, tap_y;
    char label[512];
    char cls_name[256];
    char text[512];
    int target_index;
    int mode; /* 0=coords, 1=label, 2=class+text */
    char type_text[4096];
    unsigned long long type_addr;
    BOOL type_clear;
    unsigned long long scroll_addr;
    double scroll_dx, scroll_dy;
    int alert_button_index;
} ui_block_ctx_t;


static void cmd_ui_tap(const char *args, resp_t *r) {
    char x_str[64] = "", y_str[64] = "";
    char label_buf[512] = "", cls_buf[256] = "", text_buf[512] = "";

    json_get_string(args, "x", x_str, sizeof(x_str));
    json_get_string(args, "y", y_str, sizeof(y_str));
    json_get_string(args, "label", label_buf, sizeof(label_buf));
    json_get_string(args, "class", cls_buf, sizeof(cls_buf));
    json_get_string(args, "text", text_buf, sizeof(text_buf));
    int targetIndex = (int)json_get_long(args, "index");

    BOOL has_coords = (x_str[0] && y_str[0]);
    BOOL has_label = (label_buf[0] != '\0');
    BOOL has_class = (cls_buf[0] != '\0');

    if (!has_coords && !has_label && !has_class) {
        resp_append(r, "\"error\":\"ui_tap requires x+y, label, or class arg\"");
        return;
    }

    ui_block_ctx_t *ctx = calloc(1, sizeof(ui_block_ctx_t));
    if (has_coords) {
        ctx->mode = 0;
        ctx->tap_x = atof(x_str);
        ctx->tap_y = atof(y_str);
    } else if (has_label) {
        ctx->mode = 1;
        strlcpy(ctx->label, label_buf, sizeof(ctx->label));
    } else {
        ctx->mode = 2;
        strlcpy(ctx->cls_name, cls_buf, sizeof(ctx->cls_name));
        strlcpy(ctx->text, text_buf, sizeof(ctx->text));
    }
    ctx->target_index = targetIndex;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            id keyWin = ui_key_window();
            if (!keyWin) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no key window found\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            id target = nil;

            if (ctx->mode == 0) {
                ui_cgpoint_t point = { ctx->tap_x, ctx->tap_y };
                SEL hitSel = sel_registerName("hitTest:withEvent:");
                id (*hitTest)(id, SEL, ui_cgpoint_t, id) =
                    (id (*)(id, SEL, ui_cgpoint_t, id))objc_msgSend;
                target = hitTest(keyWin, hitSel, point, nil);
            } else if (ctx->mode == 1) {
                int matchIdx = 0;
                target = ui_find_by_label(keyWin, ctx->label,
                                           &matchIdx, ctx->target_index);
            } else {
                int matchIdx = 0;
                target = ui_find_by_class_text(
                    keyWin, ctx->cls_name,
                    ctx->text[0] ? ctx->text : NULL,
                    &matchIdx, ctx->target_index);
            }

            if (!target) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no matching UI element found\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            ui_send_tap_action(target);

            const char *tClass = class_getName(object_getClass(target));
            const char *tLabel = ui_get_label(target);
            ui_cgrect_t frame = ui_get_frame(target);

            char esc1[512], esc2[512];
            json_escape(tClass, esc1, sizeof(esc1));

            int off = 0;
            off += snprintf(ctx->result + off, UI_RESULT_SZ - off,
                            "\"tapped\":true,\"target_class\":%s", esc1);
            if (tLabel) {
                json_escape(tLabel, esc2, sizeof(esc2));
                off += snprintf(ctx->result + off, UI_RESULT_SZ - off,
                                ",\"target_label\":%s", esc2);
            }
            snprintf(ctx->result + off, UI_RESULT_SZ - off,
                     ",\"target_frame\":{\"x\":%.1f,\"y\":%.1f,"
                     "\"w\":%.1f,\"h\":%.1f}",
                     frame.x, frame.y, frame.w, frame.h);
        } @catch (id ex) {
            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"error\":\"ui_tap exception: %s\"", nsobject_desc(ex));
        }
        dispatch_semaphore_signal(sem);
    });

    long waited = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)UI_TIMEOUT_NS));
    if (waited != 0)
        resp_append(r, "\"error\":\"ui_tap timed out (3s)\"");
    else
        resp_append(r, "%s", ctx->result);
    free(ctx);
}


static void cmd_ui_type(const char *args, resp_t *r) {
    char text_buf[4096] = "", addr_buf[64] = "", clear_buf[16] = "";

    if (!json_get_string(args, "text", text_buf, sizeof(text_buf))
        || !text_buf[0]) {
        resp_append(r, "\"error\":\"ui_type requires text arg\"");
        return;
    }
    json_get_string(args, "address", addr_buf, sizeof(addr_buf));
    json_get_string(args, "clear", clear_buf, sizeof(clear_buf));

    ui_block_ctx_t *ctx = calloc(1, sizeof(ui_block_ctx_t));
    strlcpy(ctx->type_text, text_buf, sizeof(ctx->type_text));
    ctx->type_addr = addr_buf[0] ? strtoull(addr_buf, NULL, 16) : 0;
    ctx->type_clear = (strcmp(clear_buf, "true") == 0 ||
                       strcmp(clear_buf, "1") == 0);

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            id field = nil;

            if (ctx->type_addr) {
                field = (id)(uintptr_t)ctx->type_addr;
            } else {
                id keyWin = ui_key_window();
                if (keyWin) field = ui_find_first_responder(keyWin);
                if (!field && keyWin) {
                    field = ui_find_text_field(keyWin);
                    if (field) {
                        SEL becomeFirst = sel_registerName("becomeFirstResponder");
                        BOOL (*become)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
                        become(field, becomeFirst);
                    }
                }
            }

            if (!field) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no text field found\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            const char *fieldClass = class_getName(object_getClass(field));
            const char *prevText = ui_get_text(field);
            char prevBuf[1024] = "";
            if (prevText) strlcpy(prevBuf, prevText, sizeof(prevBuf));

            if (ctx->type_clear) {
                SEL setTextSel = sel_registerName("setText:");
                SEL respondsSel = sel_registerName("respondsToSelector:");
                BOOL (*responds)(id, SEL, SEL) =
                    (BOOL (*)(id, SEL, SEL))objc_msgSend;
                if (responds(field, respondsSel, setTextSel)) {
                    Class nsStrCls = objc_getClass("NSString");
                    SEL strSel = sel_registerName("string");
                    id (*emptyStr)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                    id empty = emptyStr((id)nsStrCls, strSel);
                    void (*setText)(id, SEL, id) =
                        (void (*)(id, SEL, id))objc_msgSend;
                    setText(field, setTextSel, empty);
                }
            }

            SEL insertSel = sel_registerName("insertText:");
            SEL respondsSel = sel_registerName("respondsToSelector:");
            BOOL (*responds)(id, SEL, SEL) =
                (BOOL (*)(id, SEL, SEL))objc_msgSend;

            id nsText = ui_nsstring(ctx->type_text);

            if (responds(field, respondsSel, insertSel)) {
                void (*insert)(id, SEL, id) =
                    (void (*)(id, SEL, id))objc_msgSend;
                insert(field, insertSel, nsText);
            } else {
                SEL setTextSel = sel_registerName("setText:");
                if (responds(field, respondsSel, setTextSel)) {
                    void (*setText)(id, SEL, id) =
                        (void (*)(id, SEL, id))objc_msgSend;
                    setText(field, setTextSel, nsText);
                }
            }

            const char *newText = ui_get_text(field);

            char esc_cls[256], esc_prev[1024], esc_new[4096];
            json_escape(fieldClass, esc_cls, sizeof(esc_cls));
            json_escape(prevBuf, esc_prev, sizeof(esc_prev));
            json_escape(newText ? newText : "", esc_new, sizeof(esc_new));

            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"typed\":true,"
                     "\"field_class\":%s,"
                     "\"field_address\":\"0x%lx\","
                     "\"previous_text\":%s,"
                     "\"new_text\":%s",
                     esc_cls, (unsigned long)field, esc_prev, esc_new);
        } @catch (id ex) {
            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"error\":\"ui_type exception: %s\"", nsobject_desc(ex));
        }
        dispatch_semaphore_signal(sem);
    });

    long waited = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)UI_TIMEOUT_NS));
    if (waited != 0)
        resp_append(r, "\"error\":\"ui_type timed out (3s)\"");
    else
        resp_append(r, "%s", ctx->result);
    free(ctx);
}


static void cmd_ui_scroll(const char *args, resp_t *r) {
    char addr_buf[64] = "", dx_buf[64] = "0", dy_buf[64] = "0";
    json_get_string(args, "address", addr_buf, sizeof(addr_buf));
    json_get_string(args, "dx", dx_buf, sizeof(dx_buf));
    json_get_string(args, "dy", dy_buf, sizeof(dy_buf));

    ui_block_ctx_t *ctx = calloc(1, sizeof(ui_block_ctx_t));
    ctx->scroll_addr = addr_buf[0] ? strtoull(addr_buf, NULL, 16) : 0;
    ctx->scroll_dx = atof(dx_buf);
    ctx->scroll_dy = atof(dy_buf);

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            id scrollView = nil;

            if (ctx->scroll_addr) {
                scrollView = (id)(uintptr_t)ctx->scroll_addr;
                if (!ui_is_kind(scrollView, "UIScrollView")) {
                    snprintf(ctx->result, UI_RESULT_SZ,
                             "\"error\":\"address 0x%llx is not a UIScrollView\"",
                             ctx->scroll_addr);
                    dispatch_semaphore_signal(sem);
                    return;
                }
            } else {
                id keyWin = ui_key_window();
                if (keyWin) scrollView = ui_find_scroll_view(keyWin);
            }

            if (!scrollView) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no UIScrollView found\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            SEL offsetSel = sel_registerName("contentOffset");
            ui_cgpoint_t (*getOffset)(id, SEL) =
                (ui_cgpoint_t (*)(id, SEL))objc_msgSend;
            ui_cgpoint_t cur = getOffset(scrollView, offsetSel);

            ui_cgpoint_t newOff = {
                cur.x + ctx->scroll_dx,
                cur.y + ctx->scroll_dy
            };
            SEL setOffsetSel =
                sel_registerName("setContentOffset:animated:");
            void (*setOffset)(id, SEL, ui_cgpoint_t, BOOL) =
                (void (*)(id, SEL, ui_cgpoint_t, BOOL))objc_msgSend;
            setOffset(scrollView, setOffsetSel, newOff, YES);

            SEL sizeSel = sel_registerName("contentSize");
            ui_cgsize_t (*getSize)(id, SEL) =
                (ui_cgsize_t (*)(id, SEL))objc_msgSend;
            ui_cgsize_t cSize = getSize(scrollView, sizeSel);

            const char *svClass =
                class_getName(object_getClass(scrollView));
            char esc[256];
            json_escape(svClass, esc, sizeof(esc));

            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"scrolled\":true,"
                     "\"scroll_view_class\":%s,"
                     "\"content_offset\":{\"x\":%.1f,\"y\":%.1f},"
                     "\"content_size\":{\"w\":%.1f,\"h\":%.1f}",
                     esc, newOff.x, newOff.y, cSize.w, cSize.h);
        } @catch (id ex) {
            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"error\":\"ui_scroll exception: %s\"",
                     nsobject_desc(ex));
        }
        dispatch_semaphore_signal(sem);
    });

    long waited = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)UI_TIMEOUT_NS));
    if (waited != 0)
        resp_append(r, "\"error\":\"ui_scroll timed out (3s)\"");
    else
        resp_append(r, "%s", ctx->result);
    free(ctx);
}


static void cmd_ui_back(const char *args, resp_t *r) {
    ui_block_ctx_t *ctx = calloc(1, sizeof(ui_block_ctx_t));
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            id keyWin = ui_key_window();
            if (!keyWin) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no key window found\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            SEL rootSel = sel_registerName("rootViewController");
            id (*getRoot)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id rootVC = getRoot(keyWin, rootSel);
            if (!rootVC) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no root view controller\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            id topVC = ui_top_vc(rootVC);
            const char *fromClass =
                class_getName(object_getClass(topVC));

            SEL navSel = sel_registerName("navigationController");
            id (*getNav)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id navVC = getNav(topVC, navSel);

            if (navVC) {
                SEL vcsSel = sel_registerName("viewControllers");
                id (*getVCs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                id vcs = getVCs(navVC, vcsSel);
                SEL countSel = sel_registerName("count");
                long (*getCount)(id, SEL) =
                    (long (*)(id, SEL))objc_msgSend;
                long vcCount = getCount(vcs, countSel);

                if (vcCount > 1) {
                    SEL popSel =
                        sel_registerName("popViewControllerAnimated:");
                    id (*popVC)(id, SEL, BOOL) =
                        (id (*)(id, SEL, BOOL))objc_msgSend;
                    popVC(navVC, popSel, YES);

                    SEL topSel = sel_registerName("topViewController");
                    id (*getTop)(id, SEL) =
                        (id (*)(id, SEL))objc_msgSend;
                    id newTop = getTop(navVC, topSel);
                    const char *toClass = newTop ?
                        class_getName(object_getClass(newTop)) : "unknown";

                    char esc1[256], esc2[256];
                    json_escape(fromClass, esc1, sizeof(esc1));
                    json_escape(toClass, esc2, sizeof(esc2));
                    snprintf(ctx->result, UI_RESULT_SZ,
                             "\"action\":\"pop\","
                             "\"from_class\":%s,"
                             "\"to_class\":%s",
                             esc1, esc2);
                    dispatch_semaphore_signal(sem);
                    return;
                }
            }

            SEL presentingSel =
                sel_registerName("presentingViewController");
            id (*getPresenting)(id, SEL) =
                (id (*)(id, SEL))objc_msgSend;
            id presentingVC = getPresenting(topVC, presentingSel);

            if (presentingVC) {
                SEL dismissSel = sel_registerName(
                    "dismissViewControllerAnimated:completion:");
                void (*dismiss)(id, SEL, BOOL, id) =
                    (void (*)(id, SEL, BOOL, id))objc_msgSend;
                dismiss(topVC, dismissSel, YES, nil);

                const char *toClass =
                    class_getName(object_getClass(presentingVC));
                char esc1[256], esc2[256];
                json_escape(fromClass, esc1, sizeof(esc1));
                json_escape(toClass, esc2, sizeof(esc2));
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"action\":\"dismiss\","
                         "\"from_class\":%s,"
                         "\"to_class\":%s",
                         esc1, esc2);
                dispatch_semaphore_signal(sem);
                return;
            }

            char esc[256];
            json_escape(fromClass, esc, sizeof(esc));
            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"action\":\"none\","
                     "\"from_class\":%s,"
                     "\"reason\":\"no navigation stack or presented controller\"",
                     esc);
        } @catch (id ex) {
            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"error\":\"ui_back exception: %s\"",
                     nsobject_desc(ex));
        }
        dispatch_semaphore_signal(sem);
    });

    long waited = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)UI_TIMEOUT_NS));
    if (waited != 0)
        resp_append(r, "\"error\":\"ui_back timed out (3s)\"");
    else
        resp_append(r, "%s", ctx->result);
    free(ctx);
}


static void cmd_ui_alert_dismiss(const char *args, resp_t *r) {
    ui_block_ctx_t *ctx = calloc(1, sizeof(ui_block_ctx_t));
    ctx->alert_button_index = (int)json_get_long(args, "button_index");

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            id keyWin = ui_key_window();
            if (!keyWin) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no key window found\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            SEL rootSel = sel_registerName("rootViewController");
            id (*getRoot)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id rootVC = getRoot(keyWin, rootSel);

            id alertVC = nil;
            id currentVC = rootVC;
            while (currentVC) {
                if (ui_is_kind(currentVC, "UIAlertController")) {
                    alertVC = currentVC;
                    break;
                }
                SEL presentedSel =
                    sel_registerName("presentedViewController");
                id (*getPresented)(id, SEL) =
                    (id (*)(id, SEL))objc_msgSend;
                id next = getPresented(currentVC, presentedSel);
                if (!next || next == currentVC) break;
                currentVC = next;
            }

            if (!alertVC) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"no UIAlertController found\"");
                dispatch_semaphore_signal(sem);
                return;
            }

            SEL titleSel = sel_registerName("title");
            id (*getTitle)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id alertTitle = getTitle(alertVC, titleSel);
            const char *titleStr =
                alertTitle ? nsobject_desc(alertTitle) : "";

            SEL actionsSel = sel_registerName("actions");
            id (*getActions)(id, SEL) =
                (id (*)(id, SEL))objc_msgSend;
            id actions = getActions(alertVC, actionsSel);

            SEL countSel = sel_registerName("count");
            long (*getCount)(id, SEL) =
                (long (*)(id, SEL))objc_msgSend;
            long actionCount = getCount(actions, countSel);

            int idx = ctx->alert_button_index;
            if (idx < 0 || idx >= actionCount) {
                snprintf(ctx->result, UI_RESULT_SZ,
                         "\"error\":\"button_index %d out of range (0-%ld)\"",
                         idx, actionCount - 1);
                dispatch_semaphore_signal(sem);
                return;
            }

            SEL indexSel = sel_registerName("objectAtIndex:");
            id (*getAt)(id, SEL, unsigned long) =
                (id (*)(id, SEL, unsigned long))objc_msgSend;
            id action = getAt(actions, indexSel, (unsigned long)idx);

            id actionTitle = getTitle(action, titleSel);
            const char *buttonTitle =
                actionTitle ? nsobject_desc(actionTitle) : "";

            SEL dismissSel = sel_registerName(
                "dismissViewControllerAnimated:completion:");
            void (*dismiss)(id, SEL, BOOL, id) =
                (void (*)(id, SEL, BOOL, id))objc_msgSend;
            dismiss(alertVC, dismissSel, YES, nil);

            char esc1[512], esc2[256];
            json_escape(titleStr, esc1, sizeof(esc1));
            json_escape(buttonTitle, esc2, sizeof(esc2));

            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"dismissed\":true,"
                     "\"alert_title\":%s,"
                     "\"button_title\":%s,"
                     "\"button_index\":%d,"
                     "\"action_count\":%ld",
                     esc1, esc2, idx, actionCount);
        } @catch (id ex) {
            snprintf(ctx->result, UI_RESULT_SZ,
                     "\"error\":\"ui_alert_dismiss exception: %s\"",
                     nsobject_desc(ex));
        }
        dispatch_semaphore_signal(sem);
    });

    long waited = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)UI_TIMEOUT_NS));
    if (waited != 0)
        resp_append(r, "\"error\":\"ui_alert_dismiss timed out (3s)\"");
    else
        resp_append(r, "%s", ctx->result);
    free(ctx);
}
