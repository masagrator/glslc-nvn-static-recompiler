/* test_entry.c -- exercise the generated entry points. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "guest_api.h"

static size_t g_live = 0;

static void *my_alloc(size_t size, size_t align, void *uptr) {
    (void)align; (void)uptr;
    g_live += size;
    return malloc(size);
}
static void my_free(void *ptr, void *uptr) {
    (void)uptr;
    free(ptr);
}
static void *my_realloc(void *ptr, size_t newSz, void *uptr) {
    (void)uptr;
    return realloc(ptr, newSz);
}

int main(void) {
    int fail = 0;

    /* The allocator must be installed before glslcInitialize. */
    glslcSetAllocator(my_alloc, my_free, my_realloc, (void *)0x1234);
    printf("glslcSetAllocator: installed\n");

    /* ---- glslcGetVersion: pure function, returns a struct via x8 ---- */
    GLSLCversion v = glslcGetVersion();
    printf("glslcGetVersion: api=%u.%u gpuCode=%u.%u package=%u\n",
           v.apiMajor, v.apiMinor, v.gpuCodeVersionMajor,
           v.gpuCodeVersionMinor, v.package);
    if (v.apiMajor == 0 && v.apiMinor == 0 && v.package == 0) {
        printf("  !! all zero -- suspicious\n");
        fail++;
    }
    /* the reserved tail must have been zeroed by the movi/stur pairs */
    for (unsigned i = 0; i < sizeof(v.reserved); i++) {
        if (v.reserved[i] != 0) { printf("  !! reserved[%u]=%u\n", i, v.reserved[i]); fail++; break; }
    }

    /* ---- glslcGetDefaultOptions ---- */
    GLSLCoptions o = glslcGetDefaultOptions();
    printf("glslcGetDefaultOptions: optLevel=%d language=%d unrollControl=%d "
           "outputDebugInfo=%d forceIncludeStdHeader=%p\n",
           (int)o.optionFlags.optLevel, (int)o.optionFlags.language,
           (int)o.optionFlags.unrollControl, (int)o.optionFlags.outputDebugInfo,
           (void *)(uintptr_t)o.ptrforceIncludeStdHeader);

    /* ---- glslcInitialize / glslcFinalize ---- */
    GLSLCcompileObject obj;
    memset(&obj, 0, sizeof(obj));
    uint8_t ok = glslcInitialize(&obj);
    printf("glslcInitialize: ret=%u initStatus=%d privateData=%p\n",
           ok, (int)obj.initStatus, (void *)(uintptr_t)obj.ptrprivateData);
    if (obj.initStatus != GLSLC_INIT_SUCCESS) {
        printf("  !! expected GLSLC_INIT_SUCCESS(%d)\n", GLSLC_INIT_SUCCESS);
        fail++;
    }
    printf("  options.optLevel=%d language=%d  (initialize copies the defaults in)\n",
           (int)obj.options.optionFlags.optLevel,
           (int)obj.options.optionFlags.language);

    glslcFinalize(&obj);
    printf("glslcFinalize: privateData=%p (expect null)\n",
           (void *)(uintptr_t)obj.ptrprivateData);

    printf(fail ? "\nFAILURES: %d\n" : "\nall entry points behaved\n", fail);
    return fail != 0;
}
