#include <cstring>
#include <jni.h>
#include <pthread.h>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <sys/prctl.h>
#include <dirent.h>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <random>
#include <unistd.h>
#include "oxorany_include.h"
#include "obfuscate.h"
#define _(hbj) OBFUSCATE(hbj)
#include "lzma.h"
#include "URL.h"
#include "base64.h"
#include "zygisk.hpp"
#include "data.h"

// Define LDEBUG Only for Debugging!
//#define LDEBUG

#include "log.h"

#ifdef __LP64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym  Elf64_Sym
#define Elf_Rela Elf64_Rela
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
#endif

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <elf.h>

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

bool proc_stat = false;

bool contains(const std::string& in, const std::string& target) {
    if (strstr(in.c_str(), target.c_str())) {
        return true;
    }
    return false;
}

bool equals(const std::string& first, const std::string& second) {
    if (first == second) {
        return true;
    }
    return false;
}

bool isLibraryLoaded(const char *libraryName) {
    char line[512] = {0};
    FILE *fp = fopen(OBFUSCATE("/proc/self/maps"), OBFUSCATE("rt"));
    if (fp != nullptr) {
        while (fgets(line, sizeof(line), fp)) {
            std::string a = line;
            if (strstr(line, OBFUSCATE("rw-p")) && strstr(line, libraryName)) {
                return true;
            }
        }
        fclose(fp);
    }
    return false;
}


bool checkc() {
    std::ifstream file(base64_decode(OBFUSCATE("L3N5c3RlbS9ldGMvaG9zdHM=")), std::ios::in | std::ios::binary);
    if (!file) {
        LOGI("Cannot open file");
        return atoi(OBFUSCATE("1"));
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (contains(content, base64_decode(OBFUSCATE("Z2l0aHVi"))) || contains(content, base64_decode(OBFUSCATE("bW9ka2V5")))) {
        return atoi(OBFUSCATE("1"));
    }
    return atoi(OBFUSCATE("0"));
}

__attribute((__annotate__(("nosub"))));
bool decompress_lzma(const std::vector<char>& input_data, std::vector<char>& output_data) {
    LOGI("Starting LZMA decompression...");
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_auto_decoder(&strm, (12 * 1024 * 1024), 0);
    if (ret != LZMA_OK) {
        LOGE("Error initializing decoder: %d", ret);
        return false;
    }
    strm.next_in = reinterpret_cast<const uint8_t*>(input_data.data());
    strm.avail_in = input_data.size();
    LOGD("Input data size: %zu bytes", input_data.size());
    output_data.resize(input_data.size() * 2);
    strm.next_out = reinterpret_cast<uint8_t*>(output_data.data());
    strm.avail_out = output_data.size();
    LOGD("Allocated output buffer size: %zu bytes", output_data.size());
    while (strm.avail_in > 0) {
        ret = lzma_code(&strm, LZMA_RUN);
        if (ret == LZMA_OK || ret == LZMA_STREAM_END) {
            LOGD("Processed: %zu bytes, Decompressed: %zu bytes.", strm.avail_in, strm.avail_out);
        } else {
            LOGE("Error during decompression: Return code %d", ret);
            lzma_end(&strm);
            return false;
        }
        if (strm.avail_out == 0) {
            size_t old_size = output_data.size();
            output_data.resize(old_size * 2);
            strm.next_out = reinterpret_cast<uint8_t*>(output_data.data() + old_size);
            strm.avail_out = output_data.size() - old_size;
        }
    }
    if (ret != LZMA_STREAM_END) {
        LOGE("Decompression did not complete correctly. Return code: %d", ret);
        lzma_end(&strm);
        return false;
    }
    output_data.resize(strm.total_out);
    LOGD("Decompression complete. Total decompressed data size: %zu bytes.", strm.total_out);
    lzma_end(&strm);
    LOGI("LZMA decompression finished successfully.");
    return true;
}

uintptr_t str2uptr(const char *c) {
    return strtoull(c, nullptr, 16);
}

void xor_cipher(std::vector<char>& data, const std::string& key, bool mode) {
    uint32_t key1 = str2uptr(_("0x1EFF2FE1")), key2 = str2uptr(_("0x1E00A2E3"));
    for (char c : key) {
        key1 = (key1 * atoi(_("33"))) ^ static_cast<uint8_t>(c);
        key2 = (key2 * atoi(_("31"))) + static_cast<uint8_t>(c);
    }
    for (size_t i = 0; i < data.size(); ++i) {
        if (mode) { // Encrypt
            data[i] = (data[i] << atoi(_("3"))) | (data[i] >> atoi(_("5")));
            data[i] ^= static_cast<uint8_t>(key1 >> (i % atoi(_("32"))));
            data[i] = (data[i] >> atoi(_("2"))) | (data[i] << atoi(_("6")));
            data[i] ^= static_cast<uint8_t>(key2 >> ((i + atoi(_("5"))) % atoi(_("32"))));
        } else { // Decrypt
            data[i] ^= static_cast<uint8_t>(key2 >> ((i + atoi(_("5"))) % atoi(_("32"))));
            data[i] = (data[i] << atoi(_("2"))) | (data[i] >> atoi(_("6")));
            data[i] ^= static_cast<uint8_t>(key1 >> (i % atoi(_("32"))));
            data[i] = (data[i] >> atoi(_("3"))) | (data[i] << atoi(_("5")));
        }
    }
}

__attribute((__annotate__(("sub"))));
__attribute((__annotate__(("bcf"))));
__attribute((__annotate__(("split"))));
__attribute((__annotate__(("fla"))));

std::vector<char> JNIURL(JNIEnv *env, jstring urlString) {
    const char* url = env->GetStringUTFChars(urlString, nullptr);
    jclass urlClass = env->FindClass(_("java/net/URL"));
    jclass httpURLConnectionClass = env->FindClass(_("java/net/HttpURLConnection"));
    if (urlClass == nullptr || httpURLConnectionClass == nullptr) {
        return {};
    }
    jmethodID urlConstructor = env->GetMethodID(urlClass, _("<init>"), _("(Ljava/lang/String;)V"));
    jobject urlObj = env->NewObject(urlClass, urlConstructor, urlString);
    jmethodID openConnectionMethod = env->GetMethodID(urlClass, _("openConnection"), _("()Ljava/net/URLConnection;"));
    jobject connectionObj = env->CallObjectMethod(urlObj, openConnectionMethod);
    if (connectionObj == nullptr) return {};
    jobject httpURLConnectionObj = env->NewGlobalRef(connectionObj);
    jmethodID setRequestMethodMethod = env->GetMethodID(httpURLConnectionClass, _("setRequestMethod"), _("(Ljava/lang/String;)V"));
    jstring getMethod = env->NewStringUTF(_("GET"));
    env->CallVoidMethod(httpURLConnectionObj, setRequestMethodMethod, getMethod);
    jmethodID setRequestPropertyMethod = env->GetMethodID(httpURLConnectionClass, _("setRequestProperty"), _("(Ljava/lang/String;Ljava/lang/String;)V"));
    jstring ngrokSkip = env->NewStringUTF(_("Ngrok-Skip-Browser-Warning"));
    jstring trueStr = env->NewStringUTF(_("true"));
    env->CallVoidMethod(httpURLConnectionObj, setRequestPropertyMethod, ngrokSkip, trueStr);
    env->DeleteLocalRef(ngrokSkip);
    env->DeleteLocalRef(trueStr);
    jmethodID connectMethod = env->GetMethodID(httpURLConnectionClass, _("connect"), _("()V"));
    env->CallVoidMethod(httpURLConnectionObj, connectMethod);
    jmethodID getInputStreamMethod = env->GetMethodID(httpURLConnectionClass, _("getInputStream"), _("()Ljava/io/InputStream;"));
    jobject inputStreamObj = env->CallObjectMethod(httpURLConnectionObj, getInputStreamMethod);
    if (inputStreamObj == nullptr) return {};
    jclass inputStreamClass = env->GetObjectClass(inputStreamObj);
    jmethodID readMethod = env->GetMethodID(inputStreamClass, _("read"), _("([B)I"));
    std::vector<char> responseStream;
    jbyteArray byteArray = env->NewByteArray(4096);
    jint bytesRead = 0;
    while ((bytesRead = env->CallIntMethod(inputStreamObj, readMethod, byteArray)) != -1) {
        if (bytesRead > 0) {
            jbyte* byteData = env->GetByteArrayElements(byteArray, nullptr);
            responseStream.insert(responseStream.end(), byteData, byteData + bytesRead);
            env->ReleaseByteArrayElements(byteArray, byteData, JNI_ABORT);
        }
    }
    env->ReleaseStringUTFChars(urlString, url);
    return responseStream;
}

JavaVM* jvm;

__attribute((__annotate__(("sub"))));
__attribute((__annotate__(("bcf"))));
__attribute((__annotate__(("split"))));
__attribute((__annotate__(("fla"))));

std::vector<char> get_url(std::string url) {
    std::vector<char> ret;
    std::thread t([&]() {
        JNIEnv* thread_env;
        bool attached = false;
        if (jvm->AttachCurrentThread(&thread_env, nullptr) == JNI_OK) {
            attached = true;
            ret = JNIURL(thread_env, thread_env->NewStringUTF(url.c_str()));
        }
        if (attached) {
            jvm->DetachCurrentThread();
        }
    });
    t.join();
    return ret;
}

__attribute((__annotate__(("nosub"))));
size_t get_random_mem_size(size_t base_size) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(10 * 1024, 1024 * 1024);
    size_t random_increment = dist(gen);
    size_t new_size = base_size + random_increment;
    return (new_size + page_size - 1) & ~(page_size - 1);
}


char *symtab = nullptr, *strtab = nullptr;
size_t symbol_count = 0;

typedef struct {
    void *base;
    size_t size;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    void *tls_block;
    Elf64_Addr fini_func = 0;
    Elf64_Addr *fini_array = nullptr;
    size_t fini_array_size = 0;
} ELFObject;

__attribute((__annotate__(("nosub"))));
size_t get_symbol_count(const void* elf_base) {
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(elf_base);
    const auto* shdr = reinterpret_cast<const Elf64_Shdr*>(
        reinterpret_cast<const uint8_t*>(elf_base) + ehdr->e_shoff
    );
    for (size_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
            symbol_count += shdr[i].sh_size / shdr[i].sh_entsize;
        }
    }
    return symbol_count;
}

__attribute((__annotate__(("nosub"))));
void *find_symbol(void *base, const char *symbol) {
    if (!symtab || !strtab) {
        LOGE("SYMTAB or STRTAB not found");
        return nullptr;
    }
    size_t symtab_size = symbol_count;
    for (size_t i = 0; i < symtab_size; i++) {
        if (((Elf64_Sym *)symtab)[i].st_name != 0) {
            const char *sym_name = strtab + ((Elf64_Sym *)symtab)[i].st_name;
            if (strcmp(sym_name, symbol) == 0) {
                //LOGD("Found symbol: %s at address: 0x%lx", symbol, ((Elf64_Sym *)symtab)[i].st_value);
                return (void *)((char *)base + ((Elf64_Sym *)symtab)[i].st_value);
            }
        }
    }
    LOGE("Can't find symbol: %s", symbol);
    return NULL;
}

__attribute((__annotate__(("nosub"))));
void *resolve_symbol(const char *name, ELFObject obj) {
	void *symbol = find_symbol(obj.base, name);
    if (!symbol) {
		void *handle = dlopen(nullptr, RTLD_LAZY | RTLD_GLOBAL);
		if (!handle) return nullptr;
        symbol = dlsym(handle, name);
		if (!symbol) return nullptr;
    }
    return symbol;
}

__attribute((__annotate__(("nosub"))));
ELFObject load_elf(void *elf_mem, size_t size) {
#ifdef p_type
#undef p_type
#endif
    ELFObject obj = {nullptr};
    obj.ehdr = (Elf64_Ehdr *)elf_mem;
    if (memcmp(obj.ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Invalid ELF");
    }
    obj.phdr = (Elf64_Phdr *)((char *)obj.ehdr + obj.ehdr->e_phoff);
    LOGI("ELF program headers loaded, count: %d", obj.ehdr->e_phnum);
    size_t mem_size = 0;
    for (int i = 0; i < obj.ehdr->e_phnum; i++) {
        if (obj.phdr[i].p_type == PT_LOAD) {
            size_t end = obj.phdr[i].p_vaddr + obj.phdr[i].p_memsz;
            if (end > mem_size) mem_size = end;
        }
    }
    mem_size = get_random_mem_size(mem_size);
    obj.base = mmap(nullptr, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (obj.base == MAP_FAILED) {
        LOGE("Memory allocation failed");
    }
    LOGI("Allocated memory at %p (size: %zu)", obj.base, mem_size);
    for (int i = 0; i < obj.ehdr->e_phnum; i++) {
        if (obj.phdr[i].p_type == PT_LOAD) {
            memcpy((char *)obj.base + obj.phdr[i].p_vaddr, (char *)elf_mem + obj.phdr[i].p_offset, obj.phdr[i].p_filesz);
        } else if (obj.phdr[i].p_type == PT_TLS) {
            obj.tls_block = mmap(nullptr, obj.phdr[i].p_memsz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            memcpy((char *)obj.tls_block, (char *)elf_mem + obj.phdr[i].p_offset, obj.phdr[i].p_filesz);
        }
    }
    symbol_count = get_symbol_count(elf_mem);
    LOGD("Loaded ELF sections into memory, SHNUM: %zu", symbol_count);
    for (int i = 0; i < obj.ehdr->e_phnum; i++) {
        if (obj.phdr[i].p_type == PT_DYNAMIC) {
            auto *dyn = (Elf64_Dyn *)((char *)obj.base + obj.phdr[i].p_vaddr);
            Elf64_Addr *preinit_array = nullptr;
            size_t preinit_array_size = 0;
            Elf64_Rel *rel = nullptr;
            size_t rel_size = 0;
            Elf64_Rela *rela = nullptr, *jmprel = nullptr;
            size_t rela_size = 0, jmprel_size = 0;
            Elf64_Addr init_func = 0;
            Elf64_Addr *init_array = nullptr;
            size_t init_array_size = 0;
            Elf64_Addr fini_func = 0;
            Elf64_Addr *fini_array = nullptr;
            size_t fini_array_size = 0;
            Elf64_Xword dt_flags = 0, dt_flags_1 = 0;
            char **needed_libs = nullptr;
            int needed_count = 0;
            while (dyn->d_tag != DT_NULL) {
                if (dyn->d_tag == DT_PREINIT_ARRAY) preinit_array = (Elf64_Addr *)((char *)obj.base + dyn->d_un.d_ptr);
                if (dyn->d_tag == DT_PREINIT_ARRAYSZ) preinit_array_size = dyn->d_un.d_val;
                if (dyn->d_tag == DT_REL) rel = (Elf64_Rel *)((char *)obj.base + dyn->d_un.d_ptr);
                if (dyn->d_tag == DT_RELSZ) rel_size = dyn->d_un.d_val;
                if (dyn->d_tag == DT_RELA) rela = (Elf64_Rela *)((char *)obj.base + dyn->d_un.d_ptr);
                if (dyn->d_tag == DT_RELASZ) rela_size = dyn->d_un.d_val;
                if (dyn->d_tag == DT_SYMTAB) symtab = (char *)obj.base + dyn->d_un.d_ptr;
                if (dyn->d_tag == DT_STRTAB) strtab = (char *)obj.base + dyn->d_un.d_ptr;
                if (dyn->d_tag == DT_JMPREL) jmprel = (Elf64_Rela *)((char *)obj.base + dyn->d_un.d_ptr);
                if (dyn->d_tag == DT_PLTRELSZ) jmprel_size = dyn->d_un.d_val;
                if (dyn->d_tag == DT_NEEDED) needed_count++;
                dyn++;
            }
            LOGI("Found %d needed libraries", needed_count);
            needed_libs = (char **)malloc(sizeof(char *) * needed_count);
            int needed_index = 0;
            dyn = (Elf64_Dyn *)((char *)obj.base + obj.phdr[i].p_vaddr);
            while (dyn->d_tag != DT_NULL) {
                if (dyn->d_tag == DT_NEEDED) {
                    needed_libs[needed_index++] = (char *)(strtab + dyn->d_un.d_val);
                }
                dyn++;
            }
            void **handles = (void **)malloc(sizeof(void *) * needed_count);
            for (int j = 0; j < needed_count; j++) {
                handles[j] = dlopen(needed_libs[j], RTLD_LAZY);
                if (!handles[j]) {
                    LOGE("Failed to load dependency: %s", needed_libs[j]);
                } else {
                    LOGI("Loaded dependency: %s", needed_libs[j]);
                }
            }
            free(needed_libs);
            if (preinit_array && preinit_array_size > 0) {
                size_t count = preinit_array_size / sizeof(Elf64_Addr);
                LOGI("Calling %zu pre-initialization functions from DT_PREINIT_ARRAY", count);
                for (size_t j = 0; j < count; j++) {
                    if (preinit_array[j]) {
                        LOGI("Calling pre-initialization function at %p", (void *)preinit_array[j]);
                        ((void (*)())preinit_array[j])();
                    }
                }
            }
            if (rela && rela_size > 0) {
                for (size_t j = 0; j < rela_size / sizeof(Elf64_Rela); j++) {
                    Elf64_Rela *r = &rela[j];
                    void *addr = (char *)obj.base + r->r_offset;
                    Elf64_Xword type = ELF64_R_TYPE(r->r_info);
                    Elf64_Xword sym = ELF64_R_SYM(r->r_info);
                    if (type == R_AARCH64_RELATIVE) {
                        *(Elf64_Addr *)addr = (Elf64_Addr)((char *)obj.base + r->r_addend);
                    } else if (type == R_AARCH64_GLOB_DAT) {
                        Elf64_Sym *symbol = (Elf64_Sym *)symtab + sym;
                        const char *sym_name = (char *)(strtab + symbol->st_name);
                        *(Elf64_Addr *)addr = (Elf64_Addr)resolve_symbol(sym_name, obj);
                    }
                }
            }
            if (rel && rel_size > 0) {
                for (size_t j = 0; j < rel_size / sizeof(Elf64_Rel); j++) {
                    Elf64_Rel *r = &rel[j];
                    void *addr = (char *)obj.base + r->r_offset;
                    Elf64_Xword type = ELF64_R_TYPE(r->r_info);
                    Elf64_Xword sym = ELF64_R_SYM(r->r_info);
                    if (type == R_AARCH64_RELATIVE) {
                        *(Elf64_Addr *)addr += (Elf64_Addr)((char *)obj.base);
                    } else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT) {
                        Elf64_Sym *symbol = (Elf64_Sym *)symtab + sym;
                        const char *sym_name = (char *)(strtab + symbol->st_name);
                        *(Elf64_Addr *)addr = (Elf64_Addr)resolve_symbol(sym_name, obj);
                    }

                }
            }
            if (jmprel && jmprel_size > 0) {
                for (size_t j = 0; j < jmprel_size / sizeof(Elf64_Rela); j++) {
                    Elf64_Rela *r = &jmprel[j];
                    void *addr = (char *)obj.base + r->r_offset;
                    Elf64_Xword type = ELF64_R_TYPE(r->r_info);
                    Elf64_Xword sym = ELF64_R_SYM(r->r_info);
                    if (type == R_AARCH64_JUMP_SLOT) {
                        Elf64_Sym *symbol = (Elf64_Sym *)symtab + sym;
                        const char *sym_name = (char *)(strtab + symbol->st_name);
                        *(Elf64_Addr *)addr = (Elf64_Addr)resolve_symbol(sym_name, obj);
                    }
                }
            }
            free(handles);
            dyn = (Elf64_Dyn *)((char *)obj.base + obj.phdr[i].p_vaddr);
            while (dyn->d_tag != DT_NULL) {
                if (dyn->d_tag == DT_INIT) {
                    init_func = (Elf64_Addr)((char *)obj.base + dyn->d_un.d_ptr);
                }
                if (dyn->d_tag == DT_INIT_ARRAY) {
                    init_array = (Elf64_Addr *)((char *)obj.base + dyn->d_un.d_ptr);
                }
                if (dyn->d_tag == DT_INIT_ARRAYSZ) {
                    init_array_size = dyn->d_un.d_val;
                }
                if (dyn->d_tag == DT_FINI) {
                    fini_func = (Elf64_Addr)((char *)obj.base + dyn->d_un.d_ptr);
                }
                if (dyn->d_tag == DT_FINI_ARRAY) {
                    fini_array = (Elf64_Addr *)((char *)obj.base + dyn->d_un.d_ptr);
                }
                if (dyn->d_tag == DT_FINI_ARRAYSZ) {
                    fini_array_size = dyn->d_un.d_val;
                }
                if (dyn->d_tag == DT_FLAGS) {
                    dt_flags = dyn->d_un.d_val;
                    LOGI("DT_FLAGS: 0x%lx", dt_flags);
                }
                if (dyn->d_tag == DT_FLAGS_1) {
                    dt_flags_1 = dyn->d_un.d_val;
                    LOGI("DT_FLAGS_1: 0x%lx", dt_flags_1);
                }
                dyn++;
            }
            if (init_func) {
                LOGI("Calling DT_INIT at %p", (void *)init_func);
                ((void (*)())init_func)();
            }
            if (init_array && init_array_size > 0) {
                size_t count = init_array_size / sizeof(Elf64_Addr);
                LOGI("Calling %zu constructors from DT_INIT_ARRAY", count);
                for (size_t j = 0; j < count; j++) {
                    if (init_array[j]) {
                        LOGI("Calling constructor at %p", (void *)init_array[j]);
                        ((void (*)())init_array[j])();
                    }
                }
            }
            obj.fini_func = fini_func;
            obj.fini_array = fini_array;
            obj.fini_array_size = fini_array_size;
        }
    }
    if (obj.tls_block) {
        LOGI("Setting TLS block");
#if defined(__aarch64__)
        asm volatile("msr tpidr_el0, %0" : : "r"(obj.tls_block));
#elif defined(__x86_64__)
        asm volatile("movq %0, %%fs:0" : : "r"(obj.tls_block));
#else
#warning "TLS setting not implemented for this architecture"
#endif
    }
    void* epoint = (void *)((char *)obj.base + obj.ehdr->e_entry);
    register void *sp asm("sp");
    sp = (void *)(((uintptr_t)sp) & ~0xF);
    LOGI("Jumping to entry point: %p", epoint);
    ((void (*)())((char *)epoint))();
    LOGI("Called entry point");
    obj.size = mem_size;
    return obj;
}

__attribute((__annotate__(("nosub"))));
void unload_elf(ELFObject obj) {
    LOGI("Unloading ELF");
    if (obj.fini_array && obj.fini_array_size > 0) {
        size_t count = obj.fini_array_size / sizeof(Elf64_Addr);
        LOGI("Calling %zu destructors from DT_FINI_ARRAY", count);
        for (size_t j = count; j > 0; j--) {
            if (obj.fini_array[j - 1]) {
                LOGI("Calling destructor at %p", (void *)obj.fini_array[j - 1]);
                ((void (*)())obj.fini_array[j - 1])();
            }
        }
    }
    if (obj.fini_func) {
        LOGI("Calling DT_FINI at %p", (void *)obj.fini_func);
        ((void (*)())obj.fini_func)();
    }
    if (obj.base) {
        munmap(obj.base, obj.size);
    }
    if (obj.tls_block) {
        munmap(obj.tls_block, obj.phdr->p_memsz);
    }
}

bool canUnload = false;

void load_elf_thread() {
    do {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (!isLibraryLoaded(OBFUSCATE("bin/linker64")));
    bool hdata = checkc();
    std::vector<char> elf_data(chdata, chdata + sizeof(chdata));
    xor_cipher(elf_data, OBFUSCATE("System.Reflection"), false);
    std::vector<char> new_elf_data;
    if (!decompress_lzma(elf_data, new_elf_data) || hdata) {
        LOGT(OBFUSCATE("Failed to decompress. %zu"), elf_data.size());
        return;
    }
    LOGE("Got ELF bytes, size: %zu", new_elf_data.size());
    ELFObject elf_base = load_elf(new_elf_data.data(), new_elf_data.size());
    if (!elf_base.base || hdata) {
        LOGT(OBFUSCATE("Failed to load ELF data."));
        return;
    }
    elf_data.clear();
    elf_data.shrink_to_fit();
    new_elf_data.clear();
    new_elf_data.shrink_to_fit();
    LOGD("ELF successfully loaded at %p", elf_base.base);
    void* awakenptr = resolve_symbol(OBFUSCATE("_Z6awakenv"), elf_base);
    LOGI("Calling _Z6awakenv: %p", awakenptr);
    if (!hdata && awakenptr) {
        ((void(*)())awakenptr)();
        LOGI("Successfully called _Z6awakenv: %p", awakenptr);
    } else {
        LOGT(OBFUSCATE("_Z6awakenv failed: %p"), awakenptr);
    }
    canUnload = true;
}


class Socket_Module : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        env_ = env;
		api_ = api;
        env->GetJavaVM(&jvm);
    }
    void preAppSpecialize(AppSpecializeArgs *args) override {
		std::string process_name;
		const char *process_cstr = env_->GetStringUTFChars(args->nice_name, nullptr);
		if (process_cstr) {
			process_name = process_cstr;
			env_->ReleaseStringUTFChars(args->nice_name, process_cstr);
		}
		proc_stat = equals(process_name, pname);
    }
    void postAppSpecialize(const AppSpecializeArgs *) override {
        if (proc_stat) {
            std::thread(load_elf_thread).detach();
            std::thread([this]() {
                while (!canUnload) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                if (api_)
                    api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            }).detach();
        }
    }
private:
    JNIEnv *env_{};
	Api *api_{};
};

REGISTER_ZYGISK_MODULE(Socket_Module)
