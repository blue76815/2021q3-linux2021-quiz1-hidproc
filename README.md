# 2021q3 Homework1 (quiz1)
contributed by < [`blue76815` ](https://github.com/blue76815/linux2021_q3_quiz1_hideproc)>
###### tags: `linux2021`
<style>
.blue {
  color: blue; 
}
.red {
  color: red;
}
</style>
[2021 年暑期 Linux 核心 第 1 週測驗題](https://hackmd.io/@sysprog/linux2021-summer-quiz1)
> 延伸問題:
> 1. 解釋上述程式碼運作原理，包含 ftrace 的使用
> 2. 本程式僅在 Linux v5.4 測試，若你用的核心較新，請試著找出替代方案
> 2020 年的變更 Unexporting kallsyms_lookup_name()
> Access to kallsyms on Linux 5.7+
> 3. 本核心模組只能隱藏單一 PID，請擴充為允許其 PPID 也跟著隱藏，或允許給定一組 PID 列表，而非僅有單一 PID
> 4. 指出程式碼可改進的地方，並動手實作
## 開發環境
kernel 版本
```
$ uname -r
5.4.0-80-generic
```
注意：若專案所在的**路徑名稱檔名沒有_相連，則make時會無法編譯**
例如專案路徑在
/home/blue76185/**2021 年暑期 Linux 核心課程**/quiz_1/linux2021_q3_quiz1_hideproc


```
blue76185@blue76815-tuf-gaming-fx504ge-fx80ge:~/2021 年暑期 Linux 核心課程/quiz_
1/linux2021_q3_quiz1_hideproc$ make
make -C /lib/modules/`uname -r`/build M=/home/blue76185/2021 年暑期 Linux 核心課程/quiz_1/linux2021_q3_quiz1_hideproc modules
make[1]: 進入目錄「/usr/src/linux-headers-5.4.0-80-generic」
make[1]: *** 沒有規則可製作目標「年暑期」。 停止。
make[1]: 離開目錄「/usr/src/linux-headers-5.4.0-80-generic」
make: *** [Makefile:9：all] 錯誤 2
```
後來路徑 **2021 年暑期 Linux 核心 課程**
改成**2021_年暑期_Linux_核心課程**
就能編譯成功
```
blue76185@blue76815-tuf-gaming-fx504ge-fx80ge:~/2021_年暑期_Linux_核心課程/quiz_
1/linux2021_q3_quiz1_hideproc$ make
make -C /lib/modules/`uname -r`/build M=/home/blue76185/2021_年暑期_Linux_核心課程/quiz_1/linux2021_q3_quiz1_hideproc modules
make[1]: 進入目錄「/usr/src/linux-headers-5.4.0-80-generic」
  CC [M]  /home/blue76185/2021_年暑期_Linux_核心課程/quiz_1/linux2021_q3_quiz1_hideproc/hid_proc.o
  LD [M]  /home/blue76185/2021_年暑期_Linux_核心課程/quiz_1/linux2021_q3_quiz1_hideproc/hideproc.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC [M]  /home/blue76185/2021_年暑期_Linux_核心課程/quiz_1/linux2021_q3_quiz1_hideproc/hideproc.mod.o
  LD [M]  /home/blue76185/2021_年暑期_Linux_核心課程/quiz_1/linux2021_q3_quiz1_hideproc/hideproc.ko
make[1]: 離開目錄「/usr/src/linux-headers-5.4.0-80-generic」
```

## 模組操作指令
* lsmod：列出當前kernel中的所有模組
例如`sudo lsmod | grep hello` 可搭配 `| grep`搜尋特定模組關鍵字
* insmod:模組載入到kernel
例如`sudo insmod hello-1.ko`
* modinfo:查詢模組內訊息
例如`sudo modinfo hello-1.ko`
* rmmod：將模組從kernel中刪除
例如 `sudo rmmod hello_1`
* dmesg： 顯示kernel訊息

參考資料：
* [Linux 核心模組運作原理](https://hackmd.io/@sysprog/linux-kernel-module)
* The Linux Kernel Module Programming Guide 0.4.1 The Simplest Module
## 1. 解釋上述程式碼運作原理，包含 ftrace 的使用
### 1.1 MODULE_LICENSE()和 MODULE_AUTHOR()
```
#include <linux/list.h>
#include <linux/module.h>
MODULE_LICENSE("Dual MIT/GPL"); //宣告程式 License
MODULE_AUTHOR("National Cheng Kung University, Taiwan");//宣告模組作者
```
參考資料：
* The Linux Kernel Module Programming Guide 
0.4.4 Licensing and Module Documentation
* [MODULE_LICENSE](https://www.kernel.org/doc/html/latest/process/license-rules.html?highlight=module_license#id1)
* [include/linux/module.h](https://elixir.bootlin.com/linux/latest/source/include/linux/module.h#L363)
```clike=185
/*
 * The following license idents are currently accepted as indicating free
 * software modules
 *
 *	"GPL"				[GNU Public License v2]
 *	"GPL v2"			[GNU Public License v2]
 *	"GPL and additional rights"	[GNU Public License v2 rights and more]
 *	"Dual BSD/GPL"			[GNU Public License v2
 *					 or BSD license choice]
 *	"Dual MIT/GPL"			[GNU Public License v2
 *					 or MIT license choice]
 *	"Dual MPL/GPL"			[GNU Public License v2
 *					 or Mozilla license choice]
 *
 * The following other idents are available
 *
 *	"Proprietary"			[Non free products]
 */ 
```
* [編寫模組時的宣告(含MODULE_LICENSE等)](https://codertw.com/%E7%A8%8B%E5%BC%8F%E8%AA%9E%E8%A8%80/458735/)
> 編寫模組必須先宣告下面兩句：
> ```
> #include <linux/module.h> //這個標頭檔案包含了許多符號與函式的定義，這些符號與函式多與載入模組有關
> #include <linux/init.h> //這個標頭檔案包含了你的模組初始化與清除的函式
> ```
> MODULE_LICENSE(); //模組授權
> MODULE_AUTHOR();   // 宣告作者
> MODULE_DESCRIPTION();// 對這個模組作一個簡單的描述 
> MODULE_VERSION();  // 這個模組的版本
> MODULE_ALIAS(); // 這個模組的別名
> MODULE_DEVICE_TABLE();//告訴使用者空間這個模組支援什麼樣的裝置
* [[Linux Kernel] 簡單 hello world: License and Module 介紹(part 3)](https://blog.wu-boy.com/2010/07/linux-kernel-%E7%B0%A1%E5%96%AE-hello-world-license-and-module-%E4%BB%8B%E7%B4%B9part-3/)
### 1.2 module_init() 和 module_exit() 
```
module_init(_hideproc_init);//模組初始化 進入點
module_exit(_hideproc_exit);//模組卸載 離開點
```
從這裡可看出quiz程式
1. `module_init()`模組初始化時，<span class="blue">**進入點為調用`_hideproc_init()`函式**</span>
2. `module_exit()`模組卸載，<span class="red">**離開點為調用`_hideproc_exit()`函式**</span>

下面單元將分別從
* _hideproc_init()
* _hideproc_exit()

來介紹程式流程

參考資料
* [Driver Basics-Driver Entry and Exit points](https://www.kernel.org/doc/html/latest/driver-api/basics.html#driver-entry-and-exit-points)
> module_init(x) //driver initialization entry point，裡面的x為填**進入點**要調用的函式
> module_exit(x) //driver exit entry point，裡面的x為填**離開點**要調用的函式
* The Linux Kernel Module Programming Guide 
0.5.1 How modules begin and end

> A program usually begins with a main() function, executes a bunch of instructions and terminates upon completion of those instructions. <span class="blue">Kernel modules work a bit differently. 
> A module always begin with either the initmodule or the function you specify with **module_init** call.</span> 
> <span class="blue">This is the entry function for modules; it tells the kernel what functionality the module provides and sets up the kernel to run the module’s functions when they’re needed.</span>
> Once it does this, entry function returns and the module does nothing until the kernel wants to do something with the code that the module provides.
> 
> <span class="red">All modules end by calling either **cleanup_module** or the function you specify with the **module_exit** call. 
> This is the exit function for modules;</span>
> it undoes whatever entry function did. 
> It unregisters the functionality that the entry function registered.
> 
> <span class="blue">Every module must have an **entry function** and an **exit function**.</span>
> Since there’s more than one way to specify entry and exit functions, I’ll try my best to use the terms ‘entry function’ and ‘exit function’, but if I slip and simply refer to them as <span class="blue">**init_module** and **cleanup_module**,</span> I think you’ll know what I mean.

* 一般程式是從main()函式進入點
* 但是linux kernel mudule(模組)運作方式有點不同
     * module_init(填**進入點**要調用的函式);模組函數進入點
     * module_exit(填**離開點**要調用的函式);模組函數離開點

### 1.3 `_hideproc_init(void)`：模組函式進入點

```clike=212
static int _hideproc_init(void)
{
    int err, dev_major;
    dev_t dev;
    printk(KERN_INFO "@ %s\n", __func__);
    err = alloc_chrdev_region(&dev, 0, MINOR_VERSION, DEVICE_NAME);//alloc_chrdev_region()申請一個 char device numbers(字元設備號碼)
    dev_major = MAJOR(dev);//獲取主 device numbers

    hideproc_class = class_create(THIS_MODULE, DEVICE_NAME);//class_create(owner, name)在 sys/class/ 目錄下 創建一個class,
															
    cdev_init(&cdev, &fops);//初始化cdev
    cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1);//cdev_add()向系統註冊設備
    device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION), NULL,
                  DEVICE_NAME);//創建一個設備(在/dev目錄下創建設備文件)，並註冊到sysfs
                            //因為我們寫 DEVICE_NAME "hideproc"，所以會創建在 /dev/hideproc 目錄
    init_hook();

    return 0;
}
```
參考資料
* [二、字符设备API](https://zhuanlan.zhihu.com/p/73974707)
* [The Linux Kernel API Char devices](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html?highlight=alloc_chrdev_region#char-devices) 
    * [alloc_chrdev_region](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html?highlight=alloc_chrdev_region#c.alloc_chrdev_region)
* [3.3. 相关概念及数据结构](http://doc.embedfire.com/linux/imx6/base/zh/latest/linux_driver/character_device.html#id3)
介紹 MKDEV(ma,mi) ，MAJOR(dev)，MINOR(dev)，struct cdev 用途，struct file_operations 用途

### 1.4 `_hideproc_exit(void)`：模組函式離開點

```clike=233
static void _hideproc_exit(void)
{
    printk(KERN_INFO "@ %s\n", __func__);
    /* FIXME: ensure the release of all allocated resources */
}
```

### 1.5 init_hook();
```
static void init_hook(void)
{
    real_find_ge_pid = (find_ge_pid_func) kallsyms_lookup_name("find_ge_pid");
    hook.name = "find_ge_pid";
    hook.func = hook_find_ge_pid;
    hook.orig = &real_find_ge_pid;
    hook_install(&hook);
}
```
ftrace_hook *hook 其struct為
```c
struct ftrace_hook {
    const char *name;
    void *func, *orig;
    unsigned long address;
    struct ftrace_ops ops;
};
```

```c
static int hook_install(struct ftrace_hook *hook)
{
    int err = hook_resolve_addr(hook);
    if (err)
        return err;

    hook->ops.func = hook_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);//追蹤指定的函式
    if (err) {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);//開啟tracing call
    if (err) {
        printk("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);//開啟tracing call
        return err;
    }
    return 0;
}
```
該測驗 程式 頻繁呼叫
```c
ftrace_set_filter_ip();//追蹤指定的函式
register_ftrace_function(&ops);//開啟tracing call
unregister_ftrace_function(&ops);//關閉tracing call
```
#### [Using ftrace to hook to functions](https://www.kernel.org/doc/html/latest/trace/ftrace-uses.html?highlight=ftrace_set_filter_ip#)
> To **enable tracing call:**
> `register_ftrace_function(&ops);`
> To **disable tracing call:**
> `unregister_ftrace_function(&ops);`
> The above is defined by including the header:
> `#include <linux/ftrace.h>`
> Sometimes more than one function has the same name. **To trace just a specific function in this case**, `ftrace_set_filter_ip()` can be used.
> `ret = ftrace_set_filter_ip(&ops, ip, 0, 0);`

本測驗在
* hook_install();內有呼叫register_ftrace_function(&ops);(開啟tracing call)
* 在hook_remove();內有呼叫unregister_ftrace_function(&ops);(關閉tracing call)
**但是在程式執行時沒有使用到hook_remove(&hook);**

**我將會在`static void _hideproc_exit(void)`內補完`hook_remove(&hook);`**

### 1.6 `device_write()` 和 `device_read()`函式呼叫方式
<span class="blue">**程式有執行`device_write()` 和 `device_read()`**</span> 函式，但是我們在程式碼中的執行函式流程中，<span class="red">**都沒看到有調用到`device_write()` 和 `device_read()` 函式**</span>

答案是將<span class="blue">**`device_write()` 和 `device_read()`**</span> 註冊到 <span class="red">**`static const struct file_operations fops`**</span>

```c
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,//註冊device_open()
    .release = device_close,//註冊device_close()函數
    .read = device_read,//註冊device_read()函數
    .write = device_write,//註冊device_write()函數
};
```
<span class="red">**注意 struct file_operations內的那些.open和.release 和 .read和 .write不能自己隨便自創定義**</span>
得在 [include/linux/fs.h](https://elixir.bootlin.com/linux/latest/source/include/linux/fs.h#L2022) 內<span class="red">找到 struct file_operations 對應的**函數指標成員名稱**</span>，才能調用註冊
詳細說明參照
[3.3.3.1. file_operations結構體](http://doc.embedfire.com/linux/imx6/base/zh/latest/linux_driver/character_device.html#file-operations)
> ## 3.3.3.1. file_operations結構體
> <span class="red">**file_operation**</span>就是把<span class="blue">**系統調用(system call)**</span> 和<span class="red">**驅動(Device)程序**</span>關聯起來的<span class="red">**關鍵數據結構**</span>。
> 
> 這個結構的<span class="blue">**每一個成員**</span>都<span class="blue">**對應著一個系統調用(system call)**</span>。
> 
> <span class="blue">**讀取 file_operation**</span>中相應的<span class="blue">**函數指標**</span>，接著<span class="blue">**把控制權轉交給函數指標指向的函數**</span>，從而完成了Linux設備驅動程序的工作。
```clike=2022
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *kiocb, bool spin);
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	__poll_t (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	unsigned long mmap_supported_flags;
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*fasync) (int, struct file *, int);
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock) (struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **, void **);
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
	void (*show_fdinfo)(struct seq_file *m, struct file *f);
#ifndef CONFIG_MMU
	unsigned (*mmap_capabilities)(struct file *);
#endif
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
			loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   loff_t len, unsigned int remap_flags);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
} __randomize_layout;
```

PS.在 **The Linux Kernel Module Programming Guide**
0.6 Character Device drivers
0.6.1 The proc_ops Structure
<span class="red">介紹的 struct proc_ops 是根據 kernel 3.0
定義在 `/usr/include/linux/fs.h`
這個Character Device drivers **定義結構名稱和所在目錄路徑**
已經和現在的 kernel v5.13.6 定義不同</span>
書中描述的架構介紹為
> ```c
> struct proc_ops {
>     struct module *owner;
>     loff_t (*llseek) (struct file *, loff_t, int);
>     ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
>     ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
>     ssize_t (*aio_read) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
>     ssize_t (*aio_write) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
>     int (*iterate) (struct file *, struct dir_context *);
>     unsigned int (*poll) (struct file *, struct poll_table_struct *);
>     long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
>     long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
>     int (*mmap) (struct file *, struct vm_area_struct *);
>     int (*open) (struct inode *, struct file *);
>     int (*flush) (struct file *, fl_owner_t id);
>     int (*release) (struct inode *, struct file *);
>     int (*fsync) (struct file *, loff_t, loff_t, int datasync);
>     int (*aio_fsync) (struct kiocb *, int datasync);
>     int (*fasync) (int, struct file *, int);
>     int (*lock) (struct file *, int, struct file_lock *);
>     ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
>     unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned
>     int (*check_flags)(int);
>     int (*flock) (struct file *, int, struct file_lock *);
>     ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsig
>     ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsign
>     int (*setlease)(struct file *, long, struct file_lock **);
>     long (*fallocate)(struct file *file, int mode, loff_t offset,
>     loff_t len);
>     int (*show_fdinfo)(struct seq_file *m, struct file *f);
> };
> ```
> 
> ```c
> struct proc_ops fops = {
>     .proc_read: device_read,
>     .proc_write: device_write,
>     .proc_open: device_open,
>     .proc_release: device_release
> };
> ```

書中提到的這個 `struct proc_ops` 定義，<span class="red">**在kernel v5.13.6 已經移到 [include/linux/proc_fs.h](https://elixir.bootlin.com/linux/latest/source/include/linux/proc_fs.h#L29)**</span>

---
### 1.7 `is_hidden_proc()`,`hide_process()`,`unhide_process()`從何處被呼叫
從`device_write()`內有呼叫到`hide_process()`,`unhide_process()`

```clike=168
static ssize_t device_write(struct file *filep,
                            const char *buffer,
                            size_t len,
                            loff_t *offset)
{
    long pid;
    char *message;

    char add_message[] = "add", del_message[] = "del";
    if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
        return -EAGAIN;

    message = kmalloc(len + 1, GFP_KERNEL);//GFP_KERNEL說明請看 https://blog.xuite.net/kerkerker2013/wretch/113322033
    memset(message, 0, len + 1);
    copy_from_user(message, buffer, len);//buffer取出資料，放到message，而buffer 來自輸入變數 const char *buffer
    if (!memcmp(message, add_message, sizeof(add_message) - 1)) {//比較字串是否為 "add"
        kstrtol(message + sizeof(add_message), 10, &pid);//kstrtol()為將字串轉成 long 整數  https://www.kernel.org/doc/htmldocs/kernel-api/API-kstrtol.html
        hide_process(pid);//作業問的內容 將取到的數字 隱藏此PID數字的行程
    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) {//比較字串是否為 "del"
        kstrtol(message + sizeof(del_message), 10, &pid);
        unhide_process(pid);//作業問的內容 將取到的數字 回復顯示此PID數字的行程
    } else {
        kfree(message);
        return -EAGAIN;
    }

    *offset = len;
    kfree(message);
    return len;
}
```
在device_write()內，有呼叫到
```c
hide_process(pid);
unhide_process(pid);
```
為本次作答區考題

另一個`is_hidden_proc()`考題

```c
static bool is_hidden_proc(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) { ///AAA答案  
        if (proc->id == pid)
            return true;
    }
    return false;
}
```
`is_hidden_proc()`是從這裡開始呼叫
```c
static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
    struct pid *pid = real_find_ge_pid(nr, ns);
    while (pid && is_hidden_proc(pid->numbers->nr))//有呼叫到is_hidden_proc()`
        pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
    return pid;
}
```
和
```c
static void init_hook(void)
{
    real_find_ge_pid = (find_ge_pid_func) kallsyms_lookup_name("find_ge_pid");
    hook.name = "find_ge_pid";
    hook.func = hook_find_ge_pid;//函式最外層進入點，設定hook要呼叫的函式為 hook_find_ge_pid()
    hook.orig = &real_find_ge_pid;
    hook_install(&hook);
}
```
#### 總結`is_hidden_proc(pid->numbers->nr)`執行過程
step1.`init_hook(void)`，設定hook要呼叫的函式為 `hook_find_ge_pid()`
step2.`hook_find_ge_pid()`內才調用到 <span class="blue">`is_hidden_proc(pid->numbers->nr)` 本次 AAA考題</span>

## 1.8 ftrace分析
參考 [mfinmuch](https://hackmd.io/@mfinmuch/hideproc)同學
先安裝
`sudo apt install trace-cmd`

---

## 3.本核心模組只能隱藏單一 PID，請擴充為允許其 PPID 也跟著隱藏，或允許給定一組 PID 列表，而非僅有單一 PID

---


## 4.指出程式碼可改進的地方，並動手實作
根據 [字符设备驱动](https://zhuanlan.zhihu.com/p/73974707)
> ## 三、char device的驅動架構
> **(1) 為device定義一個device相關的struct(包含device所涉及的cdev,私有數據及鎖等信息)**
> 
> **(2) 初始化函數xxx_init的定義**
> 1. 向系統申請設備號 **(register_chrdev_region()或alloc_chrdev_region())**
> 2. 使用kzalloc申請設備記憶體(為(1)中定義的struct申請memory空間)
> 3. **調用cdev_init()** 初始化cdev
> 4. **調用cdev_add()** 向系統註冊設備
> 
> **(3) 卸載函數xxx_exit的定義**
> 1. 釋放設備號(**unregister_chrdev_region()**)
> 2. **調用cdev_del()** 註銷設備
> 
> **(4) 定義file_operations**
> 1. 實現write()函數 (copy_to_user())
> 2. 實現read()函數(copy_from_user())
> 
> 撰寫模組的基本格式如下
> 
> ```c
> /*
> 設備struct
> */
> struct xxx_dev_t{
>     struct cdev cdev;
>     ...
> };
> 
> struct xxx_dev_t *dev;
> dev_t devno;
> 
> //讀設備
> ssize_t xxx_read(struct file *filp, char __user *buf, size_t count, loff_t* f_pos)
> {
>     ...
>     copy_to_user(buf, ..., ...);
> }
> //寫設備
> ssize_t xxx_write(struct file *filp, const char __user *buf, size_t count, loff_t* f_pos)
> {
>     ...
>     copy_from_user(..., buf, ...);
> }
> 
> //操作函数file_operations
> struct file_operations xxx_fops = {
>     .owner = THIS_MODULE,
>     .read = xxx_read,
>     .write = xxx_write,
>     ...
> };
> 
> 
> //設備驅動模組掛載函式
> static int __init xxx_init(void)
> {
>     ...
>     devno = MKDEV(xxx_major, 0);
>     //(1)申請設備號 
>     if(xxx_major)
>     {
>         register_chrdev_region(devno, 1, "xxx_dev");
>     } 
>     else
>     {
>         alloc_chrdev_region(&devno, 0, 1, "xxx_dev");
>     }
>     //(2)为設備struct申请memory(推鍵使用devm_kzalloc)
>     dev = kzalloc(sizeof(struct xxx_dev_t), GFP_KERNEL); 
>     //(3)初始化cdev
>     cdev_init(&dev.cdev, &xxx_fops);
>     dev.cdev.owner = THIS_MODULE;
>     //(4)向系统註冊設備
>     cdev_add(dev.cdev, dev_no, 1);
> }
> module_init(xxx_init);
> 
> //設備驅動模組卸載函式
> static void __exit xxx_exit(void)
> {
>     //釋放設備號
>     unregister_chrdev_region(dev_no, 1);
>     //註銷設備
>     cdev_del(&dev.cdev);
>     ...
> }
> module_exit(xxx_exit);
> MODULE_LICENSE("GPL v2");
> ```

驗證 `static void _hideproc_exit(void)`內
若沒註銷設備 沒釋放設備號
是否有影響
可用
`cat /proc/devices` 查詢kernel分配的設備號碼。

### 4.1 修改 `static void _hideproc_exit(void)`
加入
```c
hook_remove(&hook); //移除 ftrace hook 
device_destroy(hideproc_class, MKDEV(MAJOR(dev), 1));//刪除使用device_create函數創建的設備        
class_destroy(hideproc_class);
cdev_del(&cdev);//註銷設備
unregister_chrdev_region(dev, MINOR_VERSION);//釋放設備號
```

```c
static void _hideproc_exit(void)
{
    printk(KERN_INFO "@ %s\n", __func__);
    /* FIXME: ensure the release of all allocated resources */
    hook_remove(&hook); //移除 ftrace hook 
    device_destroy(hideproc_class, MKDEV(MAJOR(dev), 1));//刪除使用device_create函數創建的設備        
    class_destroy(hideproc_class);
    cdev_del(&cdev);//註銷設備
    unregister_chrdev_region(dev, MINOR_VERSION);//釋放設備號 
}
```


## 4.2 實驗
### 4.2.1 沒修改 `static void _hideproc_exit(void)`時
```
$ sudo insmod hideproc.ko
$ pidof cron
1115  //得到 pid 1115
```
查詢 cron的 pid
```
$ ps -aux | grep cron
root        1115  0.0  0.0   9976  3248 ?        Ss   07:58   0:00 /usr/sbin/cron -f
blue761+    5654  0.0  0.0   9388  2548 pts/1    S+   08:05   0:00 grep --color=auto cron
```
此時用`$ cat /proc/devices`查詢我們的 device number

```
$ cat /proc/devices
Character devices:
.....
510 hideproc //目前配置510號
```

隱藏 1115
```
$ echo "add 1115" | sudo tee /dev/hideproc 
add 1115
```
再次查詢PID 找不到 PID 1115的 `/usr/sbin/cron -f`
```
$ ps -aux | grep cron
blue761+    6195  0.0  0.0   9256   728 pts/1    S+   08:16   0:00 grep --color=auto cron
```
顯示 1115
```
$ echo "del 1115" | sudo tee /dev/hideproc 
del 1115
```
再次查詢PID
```
ps -aux | grep cron
root        1115  0.0  0.0   9976  3248 ?        Ss   07:58   0:00 /usr/sbin/cron -f
```
卸載 hideproc
`$ sudo rmmod hideproc`

仍然存在 hideproc 的設備號沒卸除
```
$ cat /proc/devices
Character devices:
....
510 hideproc
```

可以用 `cat sys/class`  查詢 掛載前後 有無 hideproc 目錄
用 `cat  /dev` 查詢 掛載前後 有無 hideproc 目錄
例如 `void _hideproc_exit(void)`中
<span class="red">若沒寫
`unregister_chrdev_region(dev, MINOR_VERSION);釋放設備號 `
則就算卸載 hideproc
在Linux的 `/proc/devices`也會看到，之前掛載 hideproc 殘留的 Device number</span>
![](https://i.imgur.com/PP1ahQe.png)

```
$ cat /proc/devices | grep hideproc
508 hideproc
509 hideproc
510 hideproc
```
這問題得重開機才能消除殘留的 Device number

### 4.2.2 修正 `static void _hideproc_exit(void)`
終端機用這三個指令，比對檢查 hideproc 掛載.
在卸載後,`/proc/devices`和`/sys/class`和`/dev `目錄是否還殘留 hideproc driver 模組
```
$ cat /proc/devices | grep hideproc 
$ ls /sys/class | grep hideproc 
$ ls /dev | grep hideproc
```
實驗結果
```
$ sudo insmod hideproc.ko //掛載 hideproc模組
$ cat /proc/devices | grep hideproc 
510 hideproc
$ ls /sys/class | grep hideproc 
hideproc
$ ls /dev | grep hideproc
hideproc
//下面在卸載後 已搜尋不到 hideproc 模組資源
$ sudo rmmod hideproc //卸載 hideproc模組以後
$ cat /proc/devices | grep hideproc
$ ls /sys/class | grep hideproc
$ ls /dev | grep hideproc
```
![](https://i.imgur.com/OoBkS6i.png)

