/* test_compile.c -- drive a real shader through the translated compiler. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "guest_api.h"

static const char *kVertex =
    "#version 450\n"
    "layout(location = 0) in vec4 position;\n"
    "layout(location = 1) in vec3 normal;\n"
    "layout(location = 0) out vec3 vNormal;\n"
    "void main() {\n"
    "    vNormal = normalize(normal);\n"
    "    gl_Position = position;\n"
    "}\n";

static const char *kFragment =
    "#version 450\n"
    "layout(location = 0) in vec3 vNormal;\n"
    "layout(location = 0) out vec4 color;\n"
    "void main() {\n"
    "    float d = max(dot(normalize(vNormal), vec3(0.0, 0.0, 1.0)), 0.0);\n"
    "    color = vec4(vec3(d), 1.0);\n"
    "}\n";

/* A shader with a deliberate error, to prove the error path works too. */
static const char *kBroken =
    "#version 450\n"
    "void main() { this is not glsl; }\n";

static void *my_alloc(size_t size, size_t align, void *u) {
    (void)align; (void)u;
    return malloc(size);
}
static void my_free(void *p, void *u)  { (void)u; free(p); }
static void *my_realloc(void *p, size_t n, void *u) { (void)u; return realloc(p, n); }

static int run_case(const char *label, const char *const *sources,
                    const NVNshaderStage *stages, int count, int expect_ok)
{
    GLSLCcompileObject obj;
    memset(&obj, 0, sizeof(obj));

    if (!glslcInitialize(&obj)) {
        printf("[%s] glslcInitialize FAILED (initStatus=%d)\n", label, (int)obj.initStatus);
        return 1;
    }

    obj.input.sources = sources;
    obj.input.stages = stages;
    obj.input.count = (uint8_t)count;

    uint8_t ok = glslcCompile(&obj);

    /* Results are reached through lastCompiledResults, not through the
       compile object directly. */
    GLSLCresults *res = (GLSLCresults *)(uintptr_t)obj.ptrlastCompiledResults;
    GLSLCcompilationStatus *st =
        res ? (GLSLCcompilationStatus *)(uintptr_t)res->ptrcompilationStatus : NULL;

    unsigned success = st ? st->success : 0;
    printf("[%s] glslcCompile -> ret=%u success=%u infoLogLength=%u\n",
           label, ok, success, st ? st->infoLogLength : 0);

    const char *log = st ? (const char *)(uintptr_t)st->ptrinfoLog : NULL;
    if (log && *log) {
        printf("       infoLog: %.400s%s\n", log, strlen(log) > 400 ? "..." : "");
    }

    if (success) {
        GLSLCoutput *out = res ? (GLSLCoutput *)(uintptr_t)res->ptrglslcOutput : NULL;
        printf("       output: %s numSections=%u\n",
               out ? "present" : "(none)", out ? out->numSections : 0);
    }

    int bad = (success != 0) != (expect_ok != 0);
    if (bad) printf("       !! expected success=%d\n", expect_ok);

    glslcFinalize(&obj);
    return bad;
}

int main(void) {
    int fail = 0;
    setvbuf(stdout, NULL, _IONBF, 0);   /* unbuffered: survive a crash */
    glslcSetAllocator(my_alloc, my_free, my_realloc, NULL);

    GLSLCversion v = glslcGetVersion();
    printf("compiler version: api=%u.%u gpu=%u.%u package=%u\n\n",
           v.apiMajor, v.apiMinor, v.gpuCodeVersionMajor,
           v.gpuCodeVersionMinor, v.package);

    {
        const char *srcs[1] = { kVertex };
        NVNshaderStage stages[1] = { NVN_SHADER_STAGE_VERTEX };
        fail += run_case("vertex", srcs, stages, 1, 1);
    }
    {
        const char *srcs[1] = { kFragment };
        NVNshaderStage stages[1] = { NVN_SHADER_STAGE_FRAGMENT };
        fail += run_case("fragment", srcs, stages, 1, 1);
    }
    {
        const char *srcs[2] = { kVertex, kFragment };
        NVNshaderStage stages[2] = { NVN_SHADER_STAGE_VERTEX,
                                     NVN_SHADER_STAGE_FRAGMENT };
        fail += run_case("vertex+fragment", srcs, stages, 2, 1);
    }
    {
        const char *srcs[1] = { kBroken };
        NVNshaderStage stages[1] = { NVN_SHADER_STAGE_VERTEX };
        fail += run_case("broken (expect failure)", srcs, stages, 1, 0);
    }

    printf("\n%s\n", fail ? "SOME CASES BEHAVED UNEXPECTEDLY" : "all compile cases behaved as expected");
    return fail != 0;
}
