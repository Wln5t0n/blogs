---
title: Convergence of Process Doppelgänging and Process Hollowing within the Osiris Dropper
tags: Process-Injection Doppelgänging Osiris NTDLL SYSCALL Process-Hollowing Kernel-Transaction-Manager Distributed-Transaction-Coordinator TxF TxR CLFS NTFS-transactions
---

One of the paramount objectives pursued by malicious software authors pertains to the flawless emulation of authentic processes. This endeavor aims to facilitate the inconspicuous execution of their malevolent modules, thereby evading detection by antivirus solutions. Throughout time, a multitude of methodologies have surfaced, aiding these actors in advancing towards the realization of this aspiration. This subject matter equally captivates the attention of researchers and reverse engineers, as it unveils ingenious applications of Windows APIs.

[Process Doppelgänging](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/), a new technique of impersonating a process, was published in 2017 at the [Black Hat conference](https://www.youtube.com/watch?v=Cch8dvp836w). After some time, a ransomware named [SynAck was found adopting that technique](https://securelist.com/synack-targeted-ransomware-uses-the-doppelganging-technique/85431/) for malicious purposes. Even though `Process Doppelgänging` still remains rare in the wild, I recently discovered some of its traits in the dropper for the Osiris banking Trojan ([a other version of the infamous Kronos](https://www.proofpoint.com/us/threat-insight/post/kronos-reborn)). After closer examination, I found out that the original technique was further customized.

Undoubtedly, the creators of malicious software have adeptly amalgamated components derived from both Process Doppelgänging and Process Hollowing methodologies, adeptly selecting the most advantageous aspects of each technique to engender a synergistically potent amalgamation. Within this discourse, we undertake a comprehensive examination of the deployment of Osiris onto target systems, facilitated by this intriguing loader mechanism.

### Overview
Osiris is loaded in three steps as pictured in the diagram below:

![overview](https://github.com/Wln5t0n/blogs/assets/85233203/66ca4cf2-68f8-4e1d-baac-9d09c7acb55b)

The first stage loader is the one that was inspired by the Process Doppelgänging technique but with an unexpected twist. Finally, Osiris proper is delivered thanks to a second stage loader.

### Loading additional NTDLL
When ran, the initial dropper creates a new suspended process, wermgr.exe.

![added_ntdll-0](https://github.com/Wln5t0n/blogs/assets/85233203/c2c44a40-db3e-40fe-883a-dbeba7822dd5)

Looking into the modules loaded within the injector's process space, we can see this additional copy of NTDLL:

![added_ntdll-1](https://github.com/Wln5t0n/blogs/assets/85233203/17c492c1-b2af-4862-b58a-24ec7eb27bc8)

This is a well-known technique that some malware authors use in order to evade monitoring applications and hide the API calls that they use. When we closely examine what functions are called from that additional NTDLL, we find more interesting details. It calls several APIs related to NTFS transactions. It was easy to guess that the technique of Process Doppelgänging, which relies on this mechanism, was applied here.

NTDLL is a special, low-level DLL. Basically, it is just a wrapper around [syscalls](https://en.wikipedia.org/wiki/System_call). It does not have any dependencies from other DLLs in the system. Thanks to this, it can be loaded conveniently, without the need to fill its import table.

Other system DLLs, such as Kernel32, rely heavily on functions exported from NTDLL. This is why many user-land monitoring tools hook and intercept the functions exported by NTDLL: to watch what functions are being called and check if the process does not display any suspicious activity.

Of course malware authors know about this, so sometimes, in order to fool this mechanism, they load their own, fresh and unhooked copy of NTDLL from disk. There are several ways to implement this. Let's have a look how the authors of the Osiris dropper did it.

Looking at the memory mapping, we see that the additional NTDLL is loaded as an image, just like other DLLs. This type of mapping is typical for DLLs loaded by `LoadLibrary` function or its low-level version from NTDLL, `LdrLoadDll`. But NTDLL is loaded by default in every executable, and loading the same DLL twice is impossible by the official API.

Usually, malware authors decide to map the second copy manually, but that gives a different mapping type and stands out from the normally-loaded DLLs. Here, the authors made a workaround: they loaded the file as a section, using the following functions:

- `ntdll.NtCreateFile` - to open the ntdll.dll file
- `ntdll`.[NtCreateSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwcreatesection) - to create a section out of this file
- `ntdll.ZwMapViewOfSection` - to map this section into the process address space

![create-and-map](https://github.com/Wln5t0n/blogs/assets/85233203/42b8204f-eb96-459e-baec-840025db9b3b)

This was a smart move because the DLL is mapped as an image, so it looks like it was loaded in a typical way.

This DLL was further used to make the payload injection more stealthy. Having their fresh copy of NTDLL, they were sure that the functions used from there are not hooked by security products.

#### Comparison with Process Doppelgänging and Process Hollowing

The way in which the loader injects the payload into a new process displays some significant similarities with Process Dopplegänging. However, if we analyze it very carefully, we can see also differences from the classic implementation proposed in 2017 at Black Hat. The differing elements are closer to Process Hollowing.

**Classic Process Doppelgänging:**

![dopel](https://github.com/Wln5t0n/blogs/assets/85233203/53247493-8d81-444a-8278-87333482c9d3)

**Process Hollowing:**

![hollow](https://github.com/Wln5t0n/blogs/assets/85233203/ddcac992-5f8e-4c4f-a230-76886ef46fe9)

**Osiris Loader:**

![osiris](https://github.com/Wln5t0n/blogs/assets/85233203/4d385ba7-a294-45ab-a323-668b476b2acf)


### Kernel Transaction Manager

Kernel Transaction Manager sort of exposes the kernel and user API's for interacting with transactions and related objects. So if you are writing client code and you just want to use transactions you are not providing them to the other components then tha API is very simple create transaction and then `commit` or `rollback` transaction. Basically use a transactions to wrap the bunch of other operations in the file system and the registry and then atomically all of them happen or non of them happen. This can be operated over different disks and different system if you are using [Distributed Transaction Coordinator (DTC)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms684146(v=vs.85)).

![KTM](https://github.com/Wln5t0n/blogs/assets/85233203/5cd55311-43a0-4c2b-a9e1-153881ff4741)

- **NT/ZW API's:** The Windows native operating system services API is implemented as a set of routines that run in kernel mode. These routines have names that begin with the prefix **Nt** or **Zw**. Kernel-mode drivers can call these routines directly. User-mode applications can access these routines by using system calls.
- **TxF:** The KTM is used to implement Transactional NTFS (TxF) allows transacted file system operations within the NTFS file system.
- **TxR:** The KTM is used to implement Transactional Registry (TxR) allows transacted registry operations. KTM enables client applications to coordinate file system and registry operations with a transaction.
- **Common Log File System (CLFS):** is a general-purpose logging service that can be used by software [clients](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/clfs-terminology#kernel-clfs-term-client) running in user-mode or kernel-mode. CLFS encapsulates all the functionality of the Algorithm for Recovery and Isolation Exploiting Semantics (ARIES). However, the CLFS device driver interface (DDI) is not limited to supporting ARIES; it is well suited to a variety of logging scenarios.
- **State-Machine (SM):** State-Machine keep tracks of state of different transactions and the set of operations which are legal to do with them.
- **OB:** OB is the generic object manager in the kernel your went objects your i/o completion ports, file objects all are the existing type of OB objects.

### Creating a new process

The Osiris loader starts by creating the process into which it is going to inject. The process is created by a function from Kernel32: `CreateProcessInternalW`:

![create_process_internal](https://github.com/Wln5t0n/blogs/assets/85233203/a644517e-9e49-4ee1-912e-f19b7124c50c)

The new process (wermgr.exe) is created in a suspended state from the original file. So far, it reminds us of Process Hollowing, a much older technique of process impersonation.

In the Process Dopplegänging algorithm, the step of creating the new process is taken much later and uses a different, undocumented API: `NtCreateProcessEx`:

```c
typedef NTSTATUS(NTAPI *fpNtCreateProcessEx)
(
    OUT PHANDLE     ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
    IN HANDLE   ParentProcess,
    IN ULONG    Flags,
    IN HANDLE SectionHandle     OPTIONAL,
    IN HANDLE DebugPort     OPTIONAL,
    IN HANDLE ExceptionPort     OPTIONAL,
    IN BOOLEAN  InJob
);
```

The dissimilarity holds importance as, in the context of Process Doppelgänging, the novel process originates not from the original file, but rather from a distinct buffer (section). This specific section should have been established beforehand, utilizing a concealed file generated within the NTFS transaction. While this sequence is also observed in the Osiris loader, the sequential arrangement is reversed, prompting contemplation regarding the appropriateness of labeling it as the identical algorithm.

After the process is created, the same image (wermgr.exe) is mapped into the context of the loader, just like it was previously done with NTDLL.

![mapped_wermgr](https://github.com/Wln5t0n/blogs/assets/85233203/820e6e74-c1d0-4b8f-899e-26b937c707a6)

As it later turns out, the loader will patch the remote process. The local copy of the wermgr.exe will be used to gather information about where the patches should be applied.

### Usage of NTFS transactions

Let's start from having a brief look at what are the NTFS transactions. This mechanism is commonly used while operating on databases—in a similar way, they exist in the NTFS file system. The NTFS transactions encapsulate a series of operations into a single unit. When the file is created inside the transaction, nothing from outside can have access to it until the transaction is committed. Process Doppelgänging uses them in order to create invisible files where the payload is dropped.

In the analyzed case, the usage of NTFS transactions is exactly the same. We can spot only small differences in the APIs used. The loader creates a new transaction, within which a new file is created. The original implementation used `CreateTransaction` and `CreateFileTransacted` from Kernel32. Here, they were substituted by low-level equivalents.

![set_current_transaction](https://github.com/Wln5t0n/blogs/assets/85233203/adb128c8-4d8f-4c7c-8d8f-25adf764d3e5)

First, a function `ZwCreateTransaction` from a NTDLL is called. Then, instead of `CreateFileTransacted`, the authors [open the transacted file](http://microsoft.public.win32.programmer.kernel.narkive.com/MH2k9XfA/ntfs-transaction-using-native-functions-in-user-mode) by `RtlSetCurrentTransaction` along with `ZwCreateFile` (the created file is %TEMP%\\Liebert.bmp). Then, the dropper writes a buffer into to the file. Analogically, `RtlSetCurrentTransaction` with `ZwWriteFile` is used.

![write_file](https://github.com/Wln5t0n/blogs/assets/85233203/de5165ce-5278-47f0-9d0e-6e5371c3f27e)

We can see that the buffer that is being written contains the new PE file: the second stage payload. Typically for this technique, the file is visible only within the transaction and cannot be opened by other processes, such as AV scanners.

This transacted file is then used to create a section. The function that can do it is available only via low-level API: `ZwCreateSection/NtCreateSection`.


![roll_back_transaction](https://github.com/Wln5t0n/blogs/assets/85233203/b1242fa6-64e8-4df0-aa8a-2089bdfd21d9)

After the section is created, that file is no longer needed. The transaction gets rolled back (by `ZwRollbackTransaction`), and the changes to the file are never saved on the disk.

So, the part described above is identical to the analogical part of Process Doppelgänging. Authors of the dropper made it even more stealthy by using low-level equivalents of the functions, called from a custom copy of NTDLL.

### From a section to a process

At this point, the Osiris dropper creates two completely unrelated elements:

- A process (at this moment containing a mapped, legitimate executable wermgr.exe)
- A section (created from the transacted file) and containing the malicious payload

If this were typical Process Doppelgänging, this situation would never occur, and we would have the process created directly based on the section with the mapped payload. So, the question arises, how did the author of the dropper decide to merge the elements together at this point?

If we trace the execution, we can see following function being called, just after the transaction is rolled back (format: `RVA;function`):

```ruby
4b1e6;ntdll_1.ZwQuerySection
4b22b;ntdll.NtClose
4b239;ntdll.NtClose
4aab8;ntdll_1.ZwMapViewOfSection
4af27;ntdll_1.ZwProtectVirtualMemory
4af5b;ntdll_1.ZwWriteVirtualMemory
4af8a;ntdll_1.ZwProtectVirtualMemory
4b01c;ntdll_1.ZwWriteVirtualMemory
4b03a;ntdll_1.ZwResumeThread
```

So, it looks like the newly created section is just mapped into the new process as an additional module. After writing the payload into memory and setting the necessary patches, such as Entry Point redirection, the process is resumed:

![resume_proc](https://github.com/Wln5t0n/blogs/assets/85233203/d695c04c-5097-4a7b-8fc5-a7af00201827)

The way in which the execution was redirected looks similar to variants of Process Hollowing. [The PEB of the remote process is patched](https://github.com/hasherezade/demos/blob/master/run_pe/src/runpe.h#L127), and the new module base is set to the added section. (Thanks to this, imports will get loaded automatically when the process resumes.)

![patching_PEB](https://github.com/Wln5t0n/blogs/assets/85233203/73412892-3269-41c5-8b8f-8d615dfc084b)

The Entry Point redirection is, however, done just by a patch at the Entry Point address of the original module. A single jump redirects to the Entry Point of the injected module:

![patched_ep-1](https://github.com/Wln5t0n/blogs/assets/85233203/950a05e1-d693-473b-ac6a-bf0f79a9f8c0)

In case patching the Entry Point has failed, the loader contains a second variant of Entry Point redirection, by setting the new address in the thread context (ZwGetThreadContext -> ZwSetThreadContext), which is [a classic technique used in Process Hollowing](https://github.com/hasherezade/demos/blob/master/run_pe/src/runpe.h#L139):

![set_context](https://github.com/Wln5t0n/blogs/assets/85233203/893b0b64-4ff8-47b4-ab9e-3b508ee8d6ed)

### Best of both worlds

As we can see, the author merged some elements of Process Doppelgänging with some elements of Process Hollowing. This choice was not accidental. Both of those techniques have strong and weak points, but by merging them together, we get a power combo.

The weakest point of Process Hollowing is about the protection rights set on the memory space where the payload is injected (more info [here](https://youtu.be/Cch8dvp836w?t=569)). Process Hollowing allocates memory pages in the remote process by `VirtualAllocEx`, then writes the payload there. It gives one undesirable effect: the access rights (MEM_PRIVATE) were different than in the executable that is normally loaded (MEM_IMAGE).

Example of a payload loaded using Process Hollowing:

![hollowing_example-2](https://github.com/Wln5t0n/blogs/assets/85233203/97c9f151-496e-4ac0-857c-06e28203919a)

The major obstacle in loading the payload as an image is that, to do so, it has to be first dropped on the disk. Of course we cannot do this, because once dropped, it would easily be picked by an antivirus.

Process Doppelgänging on the other hand provides a solution: invisible transacted files, where the payload can be safely dropped without being noticed. This technique assumes that the transacted file will be used to create a section (MEM_IMAGE), and then this section will become a base of the new process ([using NtCreateProcessEx](https://github.com/hasherezade/process_doppelganging/blob/master/main.cpp#L196)).

Example of a payload loaded using Process Doppelgänging:

![doppel_example](https://github.com/Wln5t0n/blogs/assets/85233203/fb64e3bb-8bf1-44bb-8dcc-335b17025c24)

This solution works well, but requires that all the process parameters have to be also loaded manually: first creating them by [RtlCreateProcessParametersEx and then setting them into the remote PEB](https://github.com/hasherezade/process_doppelganging/blob/master/main.cpp#L76). It was making it difficult to run a 32-bit process on 64-bit system, because in case of WoW64 processes, there are 2 PEBs to be filled.

Those problems of Process Doppelgänging can be solved easily if we create the process just like Process Hollowing does it. Rather than using low-level API, which was the only way to create a new process out of a section, the authors created a process out of the legitimate file, using a documented API from Kernel32. Yet, the section carrying the payload, loaded with proper access rights (MEM_IMAGE), can be added later, and the execution can get redirected to it.

### Second stage loader

The next layer ([8d58c731f61afe74e9f450cc1c7987be](https://www.virustotal.com/#/file/40288538ec1b749734cb58f95649bd37509281270225a87597925f606c013f3a/details)) is not the core yet, but the next stage of the loader. It imports only one DLL, Kernel32.

Its only role is to load the final payload. At this stage, we can hardly find something innovative. The Osiris core is unpacked piece by piece and manually loaded along with its dependencies into a newly-allocated memory area within the loader process.

![final_payload](https://github.com/Wln5t0n/blogs/assets/85233203/256d48b6-f41a-4511-8d4c-b10a32331779)

After this self-injection, the loader jumps into the payload's entry point:

![payload_entry_point](https://github.com/Wln5t0n/blogs/assets/85233203/6a1abfc7-1408-4e2d-891e-630e00566772)

The interesting thing is that the application's entry point is different than the entry point saved in the header. So, if we dump the payload and try to run it interdependently, we will not get the same code executed. This is an interesting technique used to misguide researchers.

This is the entry point that was set in the headers is at RVA 0x26840:

![org_ep](https://github.com/Wln5t0n/blogs/assets/85233203/f2bc5e41-4af6-420e-8793-7fc05ce8dbb4)

The call leads to a function that makes the application go in an infinite sleep loop:

![fake_ep](https://github.com/Wln5t0n/blogs/assets/85233203/0c15d403-f84a-4029-96c6-8b9407e4c367)

The real entry point, from which the execution of the malware should start, is at 0x25386, and it is known only to the loader.

![osiris_ep_code](https://github.com/Wln5t0n/blogs/assets/85233203/9e3086a7-ab8a-4aab-9d5e-de0c55d8771b)

### The second stage versus Kronos loader

A similar trick using a hidden entry point was used by the original Kronos ([2a550956263a22991c34f076f3160b49](https://www.hybrid-analysis.com/sample/8389dd850c991127f3b3402dce4201cb693ec0fb7b1e7663fcfa24ef30039851?environmentId=100)). In Kronos' case, the final payload is injected into svchost. The execution is redirected to the core by patching the entry point in svchost:

![svchost_patch](https://github.com/Wln5t0n/blogs/assets/85233203/6c65a84b-2ac4-45c6-ae49-3796a25fed52)

In this case, the entry point within the payload is at RVA 0x13B90, while the entry point saved in the payload's header ([d8425578fc2d84513f1f22d3d518e3c3](https://www.virustotal.com/#/file/258d67283afa5195436b1eaa8d02953785974d3709109ebff3b9b638332df514/details)) is at 0x15002.

![kronos_ep](https://github.com/Wln5t0n/blogs/assets/85233203/d4f422c4-086b-461c-b9ad-13b78e0714aa)

The code at the real Kronos entry point displays similarities with the analogical point in Osiris. Yet, we can see they are not identical:

![kronos_ep_code](https://github.com/Wln5t0n/blogs/assets/85233203/abfb8665-5fd1-4388-b7aa-ce225d7c9bc7)

### A precision implementation

The first stage loader is strongly inspired by Process Dopplegänging and is implemented in a clean and professional way. The author adopted elements from a relatively new technique and made the best out of it by composing it with other known tricks. The precision used here reminds us of the code used in the original Kronos.

### Indicators of Compromise (IOCs)

**Stage 1 (original sample)**
```
e7d3181ef643d77bb33fe328d1ea58f512b4f27c8e6ed71935a2e7548f2facc0
```

**Stage 2 (second stage loader)**
```
40288538ec1b749734cb58f95649bd37509281270225a87597925f606c013f3a
```

**Osiris (core bot)**
```
d98a9c5b4b655c6d888ab4cf82db276d9132b09934a58491c642edf1662e831e
```
