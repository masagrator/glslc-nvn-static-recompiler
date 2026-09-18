/* t_suite.c -- compile a spread of shaders and print a fingerprint of each
   result, so the port and the QEMU reference can be compared line for line. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "guest_api.h"

static void *my_alloc(size_t s, size_t a, void *u){ (void)a;(void)u; return malloc(s); }
static void  my_free(void *p, void *u){ (void)u; free(p); }
static void *my_realloc(void *p, size_t n, void *u){ (void)u; return realloc(p,n); }

struct tcase { const char *name; NVNshaderStage stage; const char *src; };

static const struct tcase cases[] = {
 {"vert-basic", NVN_SHADER_STAGE_VERTEX,
  "#version 450\nlayout(location=0) in vec4 p;layout(location=1) in vec3 n;"
  "layout(location=0) out vec3 vN;void main(){vN=normalize(n);gl_Position=p;}\n"},
 {"frag-ctor-vec3f", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nlayout(location=0) in vec3 v;layout(location=0) out vec4 c;"
  "void main(){c=vec4(v,1.0);}\n"},
 {"frag-ctor-nested", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nlayout(location=0) in vec3 v;layout(location=0) out vec4 c;"
  "void main(){float d=max(dot(normalize(v),vec3(0,0,1)),0.0);c=vec4(vec3(d),1.0);}\n"},
 {"frag-ctor-swizzle", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nlayout(location=0) in vec4 v;layout(location=0) out vec4 c;"
  "void main(){c=vec4(v.xy,v.zw);}\n"},
 {"frag-comma", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nlayout(location=0) in vec4 v;layout(location=0) out vec4 c;"
  "void main(){float a=v.x,b=v.y;c=vec4((a,b),0,0,1);}\n"},
 {"frag-loop", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nlayout(location=0) in vec4 v;layout(location=0) out vec4 c;"
  "void main(){vec4 s=vec4(0);for(int i=0;i<8;++i){s+=v*float(i);}c=s;}\n"},
 {"frag-branch-fn", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nlayout(location=0) in vec4 v;layout(location=0) out vec4 c;"
  "float f(float x){ if(x>0.5) return x*x; else return -x; }"
  "void main(){c=vec4(f(v.x),f(v.y),f(v.z),1.0);}\n"},
 {"frag-mat-struct", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nstruct S{vec3 a;float b;};layout(location=0) in vec4 v;"
  "layout(location=0) out vec4 c;void main(){S s;s.a=v.xyz;s.b=v.w;"
  "mat3 m=mat3(1.0);c=vec4(m*s.a,s.b);}\n"},
 {"frag-texture", NVN_SHADER_STAGE_FRAGMENT,
  "#version 450\nlayout(binding=0) uniform sampler2D t;layout(location=0) in vec2 uv;"
  "layout(location=0) out vec4 c;void main(){c=texture(t,uv);}\n"},
 {"vert-broken", NVN_SHADER_STAGE_VERTEX,
  "#version 450\nvoid main(){ this is not glsl; }\n"},
};

int main(int argc, char **argv){
    int only = (argc>1)? atoi(argv[1]) : -1;
    setvbuf(stdout,NULL,_IONBF,0);
    glslcSetAllocator(my_alloc,my_free,my_realloc,NULL);
    GLSLCversion ver = glslcGetVersion();
    printf("version %u.%u/%u.%u/%u\n", ver.apiMajor, ver.apiMinor,
           ver.gpuCodeVersionMajor, ver.gpuCodeVersionMinor, ver.package);
    for (unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i){
        if (only>=0 && (int)i!=only) continue;
        GLSLCcompileObject obj; memset(&obj,0,sizeof(obj));
        if(!glslcInitialize(&obj)){ printf("%-18s INIT-FAIL\n",cases[i].name); continue; }
        const char *srcs[1]={cases[i].src};
        NVNshaderStage st[1]={cases[i].stage};
        obj.input.sources=srcs; obj.input.stages=st; obj.input.count=1;
        uint8_t ok=glslcCompile(&obj);
        GLSLCresults *res=(GLSLCresults*)(uintptr_t)obj.ptrlastCompiledResults;
        GLSLCcompilationStatus *s=res?(GLSLCcompilationStatus*)(uintptr_t)res->ptrcompilationStatus:NULL;
        GLSLCoutput *o=(s&&s->success&&res)?(GLSLCoutput*)(uintptr_t)res->ptrglslcOutput:NULL;
        /* FNV-1a over the whole output blob: catches any content difference. */
        unsigned long long h=1469598103934665603ULL;
        if(o){ const unsigned char *p=(const unsigned char*)o;
               for(unsigned k=0;k<o->size;++k){ h^=p[k]; h*=1099511628211ULL; } }
        printf("%-18s ok=%u success=%u sections=%u size=%u hash=%016llx loglen=%u\n",
               cases[i].name, ok, s?s->success:0, o?o->numSections:0,
               o?o->size:0, o?h:0ULL, s?s->infoLogLength:0);
        const char *log = s?(const char*)(uintptr_t)s->ptrinfoLog:NULL;
        if(log&&*log){ printf("    log: %.160s\n", log); }
        glslcFinalize(&obj);
    }
    return 0;
}
