/* t_frag.c -- minimal failing case: one fragment shader with vec4(vec3, float). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "guest_api.h"

static const char *kFragment =
    "#version 450\n"
    "layout(location = 0) in vec3 vNormal;\n"
    "layout(location = 0) out vec4 color;\n"
    "void main() {\n"
    "    color = vec4(vNormal, 1.0);\n"
    "}\n";

static void *my_alloc(size_t size, size_t align, void *u) { (void)align; (void)u; return malloc(size); }
static void my_free(void *p, void *u)  { (void)u; free(p); }
static void *my_realloc(void *p, size_t n, void *u) { (void)u; return realloc(p, n); }

int main(void) {
    GLSLCcompileObject obj;
    const char *srcs[1] = { kFragment };
    NVNshaderStage stages[1] = { NVN_SHADER_STAGE_FRAGMENT };
    setvbuf(stdout, NULL, _IONBF, 0);
    glslcSetAllocator(my_alloc, my_free, my_realloc, NULL);
    memset(&obj, 0, sizeof(obj));
    if (!glslcInitialize(&obj)) { printf("init FAILED\n"); return 2; }
    obj.input.sources = srcs;
    obj.input.stages = stages;
    obj.input.count = 1;
    uint8_t ok = glslcCompile(&obj);
    GLSLCresults *res = (GLSLCresults *)(uintptr_t)obj.ptrlastCompiledResults;
    GLSLCcompilationStatus *st = res ? (GLSLCcompilationStatus *)(uintptr_t)res->ptrcompilationStatus : NULL;
    printf("ret=%u success=%u\n", ok, st ? st->success : 0);
    const char *log = st ? (const char *)(uintptr_t)st->ptrinfoLog : NULL;
    if (log && *log) printf("infoLog: %.300s\n", log);
    glslcFinalize(&obj);
    return 0;
}
