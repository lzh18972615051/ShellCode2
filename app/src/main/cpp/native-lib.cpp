#include <stdio.h>
#include <jni.h>

#include "Hook/include/inlineHook.h"
#include <android/log.h>
#include "Hook/byopen.h"
#include "Hook/prefix.h"
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define LOG_TAG "cnzzh"
typedef unsigned char byte;
#define LOGD(fmt,args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,fmt, ##args)
struct DexFile{
    uint32_t declaring_class_;
    void *begin;
    uint32_t  size;
};
struct ArtMethod{
    uint32_t declaring_class_;
    uint32_t access_flags_;
    uint32_t dex_code_item_offset_;
    uint32_t dex_method_index_;
};


void **(*oriexecve)(const char *__file, char *const *__argv, char *const *__envp);
void **myexecve(const char *__file,char *const *__argv,char *const *__envp){
    LOGD("cnzzh");
    LOGD("process:%d,befor run myexecve:",getpid());
    LOGD("process:%d,enter execve:%s",getpid(),__file);
    if(strstr(__file,"dex2oat")){
        return NULL;
    }else{
        return oriexecve(__file,__argv,__envp);
    }
}
void *(*oriloadmethod)(void *,void *,void *,void *,void *);
//void ClassLinker::LoadMethod(Thread* self,
//                             const DexFile& dex_file,
//                           const ClassDataItemIterator& it,
//                             Handle<mirror::Class> klass,
//                            ArtMethod* dst)
void *myloadmethod(void *a,void *b,void *c,void *d,void *e){
    //定位到testFunc，对其进行填充，这里采用DexFile和ArtMethod两个结构体实现定位
    LOGD("process:%d,befor run loadmethod:",getpid());
    struct ArtMethod *artmethod =(struct ArtMethod *) e;
    struct DexFile *dexfile=(struct DexFile *)b;
    LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d",getpid(),dexfile->begin,dexfile->size);

   /**
    * 修复前dump dex，这里仅作为比较类抽取壳的样本，没有实际意义
    */

    char dexfilepath[100] = {0};
    sprintf(dexfilepath,"/sdcard/%d_%d.dex",dexfile->size,getpid());
    int fd = open(dexfilepath,O_CREAT |O_RDWR,0666);
    if(fd>0){
        write(fd,dexfile->begin,dexfile->size);
        close(fd);
    }


    //由于artMethod在loadMethod未被调用时未完成初始化，所以需要调用原始的loadMethod函数，初始化artMethod结构体
    void *result =oriloadmethod(a,b,c,d,e);
    LOGD("process:%d,enter loadmethod:code_offset:%d,idx:%d",getpid(),
            artmethod->dex_code_item_offset_,artmethod->dex_method_index_);
    byte *code_item_addr=static_cast<byte *>(dexfile->begin)+artmethod->dex_code_item_offset_;
    LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,beforedumpcodeitem:%p",getpid(),
            dexfile->begin,dexfile->size,code_item_addr);
    if(artmethod->dex_method_index_==21862){//methodid
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,start repire method",getpid(),
                dexfile->begin,dexfile->size);
        byte *code_item_addr =(byte*)dexfile->begin + artmethod->dex_code_item_offset_;
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,beforedumpcodeitem:%p",getpid(),
                dexfile->begin,dexfile->size,code_item_addr);
    int result=mprotect(dexfile->begin,dexfile->size,PROT_WRITE);
    //索引的前16个byte是固定的，因此需要加上16
    byte *code_item_start= static_cast<byte *>(code_item_addr)+16;
    LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,code_item_start:%p",getpid(),
            dexfile->begin,dexfile->size,code_item_start);
    byte inst[16]={0x1a,0x00,0x2e,0x3f,0x1a,0x01,0x90,0x10,0x71,0x20,0x02,0x07,
                    0x10,0x00,0x0e,0x00};
    for(int i=0;i<sizeof(inst);i++){
        code_item_start[i]=inst[i];
    }
    memset(dexfilepath,0,100);
    sprintf(dexfilepath,"/sdcard/%d_%d.dex_15203_2",dexfile->size,getpid());
    fd=open(dexfilepath,O_CREAT|O_RDWR,0666);
    if(fd>0){
        write(fd,dexfile->begin,dexfile->size);
        close(fd);
        }
    }
    LOGD("process:%d,after loadmethod:code_offset:%d,idx:%d",getpid(),
            artmethod->dex_code_item_offset_,artmethod->dex_method_index_);
    return result;
}
void hooklibc(){
    LOGD("I am hoolibc");
    void *libc_addr=dlopen("/system/lib/libc.so",RTLD_NOW);
    void *execve_addr=dlsym(libc_addr,"execve");
    if(execve_addr != NULL){
        if(ELE7EN_OK == registerInlineHook((uint32_t) execve_addr,(uint32_t)myexecve,(uint32_t **) &oriexecve)){
            if (ELE7EN_OK == inlineHook((uint32_t) execve_addr)){
                LOGD("inlineHook execve success");
            }else{
                LOGD("inlineHook execve failure");
            }
        }
    }
}
void hookART(){
    LOGD("I am hookART");
    void *libart_addr=by_dlopen("/system/lib/libart.so",RTLD_NOW);
    if(libart_addr!=NULL){
        void *loadmethod_addr=by_dlsym(libart_addr,"_ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_"
                                                "6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
        if(loadmethod_addr!=NULL){
            if(ELE7EN_OK==registerInlineHook((uint32_t)loadmethod_addr,(uint32_t)  myloadmethod,(uint32_t **)&oriloadmethod)){
                if(ELE7EN_OK == inlineHook((uint32_t)loadmethod_addr)){
                    LOGD("inlineHook loadmethod success");
                }else{
                    LOGD("inlineHook loadmethod failure");
                }
            }
        }
    }
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_cnzzh_shellcode2_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Art类抽取壳";
    return env->NewStringUTF(hello.c_str());
}
extern "C" JNIEXPORT void JNICALL
Java_com_cnzzh_shellcode2_MainActivity_SecondShell(
        JNIEnv* env,
        jobject /* this */) {
    hooklibc();
    hookART();
    return;
}