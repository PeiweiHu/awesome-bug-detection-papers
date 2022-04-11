# awesome-bug-detection-papers
### [USENIX Security '16] APISan: Sanitizing API Usages through Semantic Cross-Checking

[paper](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_yun.pdf) [tool: APISan](https://github.com/sslab-gatech/apisan)

<details>
	<summary>Abstract</summary>
API misuse is a well-known source of bugs. Some of them (e.g., incorrect use of SSL API, and integer overflow of memory allocation size) can cause serious security vulnerabilities (e.g., man-in-the-middle (MITM) attack, and privilege escalation). Moreover, modern APIs, which are large, complex, and fast evolving, are error-prone. However, existing techniques to help finding bugs require manual effort by developers (e.g., providing specification or model) or are not scalable to large real-world software comprising millions of lines of code.<br/><br/>In this paper, we present APISAN, a tool that automatically infers correct API usages from source code without manual effort. The key idea in APISAN is to extract likely correct usage patterns in four different aspects (e.g., causal relation, and semantic relation on arguments) by considering semantic constraints. APISAN is tailored to check various properties with security implications. We applied APISAN to 92 million lines of code, including Linux Kernel, and OpenSSL, found 76 previously unknown bugs, and provided patches for all the bugs.
</details>

### [USENIX Security '17] DR. CHECKER: A Soundy Analysis for Linux Kernel Drivers

[paper](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-machiry.pdf) [tool: DR. CHECKER](https://github.com/ucsb-seclab/dr_checker)

<details>
	<summary>Abstract</summary>
While kernel drivers have long been know to poses huge security risks, due to their privileged access and lower code quality, bug-finding tools for drivers are still greatly lacking both in quantity and effectiveness. This is because the pointer-heavy code in these drivers present some of the hardest challenges to static analysis, and their tight coupling with the hardware make dynamic analysis infeasible in most cases. In this work, we present DR. CHECKER, a soundy (i.e., mostly sound) bug-finding tool for Linux kernel drivers that is based on well-known program analysis techniques. We are able to overcome many of the inherent limitations of static analysis by scoping our analysis to only the most bug-prone parts of the kernel (i.e., the drivers), and by only sacrificing soundness in very few cases to ensure that our technique is both scalable and precise. DR. CHECKER is a fully-automated static analysis tool capable of performing general bug finding using both pointer and taint analyses that are flow-sensitive, context-sensitive, and field-sensitive on kernel drivers. To demonstrate the scalability and efficacy of DR. CHECKER, we analyzed the drivers of nine production Linux kernels (3.1 million LOC), where it correctly identified 158 critical zero-day bugs with an overall precision of 78%.
</details>

### [NDSS '18] K-Miner: Uncovering Memory Corruption in Linux
[paper](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_05A-1_Gens_paper.pdf) [tool: K-Miner](https://github.com/ssl-tud/k-miner)

<details>
	<summary>Abstract</summary>
Operating system kernels are appealing attack targets: compromising the kernel usually allows attackers to bypass all deployed security mechanisms and take control over the entire system. Commodity kernels, like Linux, are written in low-level programming languages that offer only limited type and memory-safety guarantees, enabling adversaries to launch sophisticated run-time attacks against the kernel by exploiting memory-corruption vulnerabilities. Many defenses have been proposed to protect operating systems at run time, such as control-flow integrity (CFI). However, the goal of these run-time monitors is to prevent exploitation as a symptom of memory corruption, rather than eliminating the underlying root cause, i.e., bugs in the kernel code. While finding bugs can be automated, e.g., using static analysis, all existing approaches are limited to local, intra-procedural checks, and face severe scalability challenges due to the large kernel code base. Consequently, there currently exist no tools for conducting global static analysis of operating system kernels. In this paper, we present K-Miner, a new framework to efficiently analyze large, commodity operating system kernels like Linux. Our novel approach exploits the highly standardized interface structure of the kernel code to enable scalable pointer analysis and conduct global, context-sensitive analysis. Through our inter-procedural analysis we show that K-Miner systematically and reliably uncovers several different classes of memory-corruption vulnerabilities, such as dangling pointers, user-after-free, double-free, and double-lock vulnerabilities. We thoroughly evaluate our extensible analysis framework, which leverages the popular and widely used LLVM compiler suite, for the current Linux kernel and demonstrate its effectiveness by reporting several memory-corruption vulnerabilities.
</details>

### [USENIX ATC '18] DSAC: Effective Static Analysis of Sleep-in-Atomic-Context Bugs in Kernel Modules

[paper](https://www.usenix.org/system/files/conference/atc18/atc18-bai.pdf) <u>tool: DSAC</u>

<details>
	<summary>Abstract</summary>
In a modern OS, kernel modules often use spinlocks and interrupt handlers to monopolize a CPU core for executing concurrent code in atomic context. In this situation, if the kernel module performs an operation that can sleep at runtime, a system hang may occur in execution. We refer to this kind of concurrency bug as a sleep-in-atomic-context (SAC) bug. In practice, SAC bugs have received insufficient attention and are hard to find, as they do not always cause problems in real executions.<br/><br/>In this paper, we propose a practical static approach named DSAC, to effectively detect SAC bugs and automatically recommend patches to help fix them. DSAC uses four key techniques: (1) a hybrid of flow-sensitive and -insensitive analysis to perform accurate and efficient code analysis; (2) a heuristics-based method to accurately extract sleep-able kernel interfaces that can sleep at runtime; (3) a path-check method to effectively filter out repeated reports and false bugs; (4) a pattern-based method to automatically generate recommended patches to help fix the bugs.<br/><br/>We evaluate DSAC on kernel modules (drivers, file systems, and network modules) of the Linux kernel, and on the FreeBSD and NetBSD kernels, and in total find 401 new real bugs. 272 of these bugs have been confirmed by the relevant kernel maintainers, and 43 patches generated by DSAC have been applied by kernel maintainers.
</details>

### [USENIX ATC '19] Effective Static Analysis of Concurrency Use-After-Free Bugs in Linux Device Drivers

[paper](https://www.usenix.org/system/files/atc19-bai.pdf) <u>tool: DCUAF</u>

<details>
	<summary>Abstract</summary>
In Linux device drivers, use-after-free (UAF) bugs can cause system crashes and serious security problems. According to our study of Linux kernel commits, 42% of the driver commits fixing use-after-free bugs involve driver concurrency. We refer to these use-after-free bugs as concurrency use-after-free bugs. Due to the non-determinism of concurrent execution, concurrency use-after-free bugs are often more difficult to reproduce and detect than sequential use-after-free bugs.<br/><br/>In this paper, we propose a practical static analysis approach named DCUAF, to effectively detect concurrency use-after-free bugs in Linux device drivers. DCUAF combines a local analysis analyzing the source code of each driver with a global analysis statistically analyzing the local results of all drivers, forming a local-global analysis, to extract the pairs of driver interface functions that may be concurrently executed. Then, with these pairs, DCUAF performs a summary-based lockset analysis to detect concurrency use-after-free bugs. We have evaluated DCUAF on the driver code of Linux 4.19, and found 640 real concurrency use-after-free bugs. We have randomly selected 130 of the real bugs and reported them to Linux kernel developers, and 95 have been confirmed.
</details>

### [USENIX Security '19] PeX: A Permission Check Analysis Framework for Linux Kernel

[paper](https://www.usenix.org/system/files/sec19-zhang-tong.pdf) [tool: PeX](https://github.com/lzto/pex)

<details>
	<summary>Abstract</summary>
Permission checks play an essential role in operating system security by providing access control to privileged functionalities. However, it is particularly challenging for kernel developers to correctly apply new permission checks and to scalably verify the soundness of existing checks due to the large codebase and complexity of the kernel. In fact, Linux kernel contains millions of lines of code with hundreds of permission checks, and even worse its complexity is fast-growing.<br/><br/>This paper presents PeX, a static Permission check error detector for LinuX, which takes as input a kernel source code and reports any missing, inconsistent, and redundant permission checks. PeX uses KIRIN (Kernel InteRface based In-direct call aNalysis), a novel, precise, and scalable indirect call analysis technique, leveraging the common programming paradigm used in kernel abstraction interfaces. Over the inter-procedural control flow graph built by KIRIN, PeX automatically identifies all permission checks and infers the mappings between permission checks and privileged functions. For each privileged function, PeX examines all possible paths to the function to check if necessary permission checks are correctly enforced before it is called.<br/><br/>We evaluated PeX on the latest stable Linux kernel v4.18.5for three types of permission checks: Discretionary AccessControls (DAC), Capabilities, and Linux Security Modules(LSM). PeX reported 36 new permission check errors, 14 of which have been confirmed by the kernel developers.
</details>

### [USENIX Security '19] Detecting missing-check bugs via semantic- and context-aware criticalness and constraints inferences

[paper](https://www.usenix.org/system/files/sec19-lu.pdf) [tool: CRIX](https://github.com/umnsec/crix/)

<details>
	<summary>Abstract</summary>
Missing a security check is a class of semantic bugs in software programs where erroneous execution states are not validated. Missing-check bugs are particularly common in OS kernels because they frequently interact with external untrusted user space and hardware, and carry out error-prone computation. Missing-check bugs may cause a variety of critical security consequences, including permission bypasses, out-of-bound accesses, and system crashes. While missingcheck bugs are common and critical, only a few research works have attempted to detect them, which is arguably because of the inherent challenges in the detection--whether a variable requires a security check depends on its semantics, contexts and developer logic, and understanding them is a hard problem.<br/><br/>In this paper, we present CRIX, a system for detecting missing-check bugs in OS kernels. CRIX can scalably and precisely evaluate whether any security checks are missing for critical variables, using an inter-procedural, semantic- and context-aware analysis. In particular, CRIX's modeling and cross-checking of the semantics of conditional statements in the peer slices of critical variables infer their criticalness, which allows CRIX to effectively detect missing-check bugs. Evaluation results show that CRIX finds missing-check bugs with reasonably low false-report rates. Using CRIX, we have found 278 new missing-check bugs in the Linux kernel that can cause security issues. We submitted patches for all these bugs; Linux maintainers have accepted 151 of them. The promising results show that missing-check bugs are a common occurrence, and CRIX is effective and scalable in detecting missing-check bugs in OS kernels.
</details>

### [CCS '20] RTFM! Automatic Assumption Discovery and Verification Derivation from Library Document for API Misuse Detection

[paper](https://homes.luddy.indiana.edu/luyixing/bib/CCS20-rtmf.pdf) [tool: Advance](https://kaichen.org/tools/Advance.html) 

<details>
  <summary>Abstract</summary>
To use library APIs, a developer is supposed to follow guidance and respect some constraints, which we call integration assumptions (IAs). Violations of these assumptions can have serious consequences, introducing security-critical flaws such as use-after-free, NULL-dereference, and authentication errors. Analyzing a program for compliance with IAs involves significant effort and needs to be automated. A promising direction is to automatically recover IAs from a library document using Natural Language Processing (NLP) and then verify their consistency with the ways APIs are used in a program through code analysis. However, a practical solution along this line needs to overcome several key challenges, particularly the discovery of IAs from loosely formatted documents and interpretation of their informal descriptions to identify complicated constraints (e.g., data-/control-flow relations between different APIs). <br/><br/>In this paper, we present a new technique for automated assumption discovery and verification derivation from library documents. Our approach, called Advance, utilizes a suite of innovations to address those challenges. More specifically, we leverage the observation that IAs tend to express a strong sentiment in emphasizing the importance of a constraint, particularly those security-critical, and utilize a new sentiment analysis model to accurately recover them from loosely formatted documents. These IAs are further processed to identify hidden references to APIs and parameters, through an embedding model, to identify the information-flow relations expected to be followed. Then our approach runs frequent subtree mining to discover the grammatical units in IA sentences that tend to indicate some categories of constraints that could have security implications. These components are mapped to verification code snippets organized in line with the IA sentence's grammatical structure, and can be assembled into verification code executed through CodeQL to discover misuses inside a program. We implemented this design and evaluated it on 5 popular libraries (OpenSSL, SQLite, libpcap, libdbus and libxml2) and 39 real-world applications. Our analysis discovered 193 API misuses, including 139 flaws never reported before.
</details>

### [CCS '21] Detecting Missed Security Operations through Differential Checking of Object-based Similar Paths

[paper](https://nesa.zju.edu.cn/download/ldh_pdf_IPPO.pdf) <u>tool: IPPO</u>

<details>
  <summary>Abstract</summary>
Missing a security operation such as a bound check has been a major cause of security-critical bugs. Automatically checking whether the code misses a security operation in large programs is challenging since it has to understand whether the security operation is indeed necessary in the context. Recent methods typically employ cross-checking to identify deviations as security bugs, which collects functionally similar program slices and infers missed security operations through majority-voting. An inherent limitation of such approaches is that they heavily rely on a substantial number of similar code pieces to enable cross-checking. In practice, many code pieces are unique, and thus we may be unable to find adequate similar code snippets to utilize cross-checking. In this paper, we present IPPO (Inconsistent Path Pairs as a bug Oracle), a static analysis framework for detecting security bugs based on differential checking. IPPO defines several novel rules to identify code paths that share similar semantics with respect to an object, and collects them as similar-path pairs. It then investigates the path pairs for identifying inconsistent security operations with respect to the object. If one path in a path pair enforces a security operation while the other does not, IPPO reports it as a potential security bug. By utilizing on object-based path-similarity analysis, IPPO achieves a higher precision, compared to conventional code-similarity analysis methods. Through differential checking of a similar-path pair, IPPO eliminates the requirement of constructing a large number of similar code pieces, addressing the limitation of traditional cross-checking approaches. We implemented IPPO and extensively evaluated it on four widely used open-source programs: Linux kernel, OpenSSL library, FreeBSD kernel, and PHP. IPPO found 154, 5, 1, and 1 new security bugs in the above systems, respectively. We have submitted patches for all these bugs, and 136 of them have been accepted by corresponding maintainers. The results confirm the effectiveness and usefulness of IPPO in practice.
</details>

### [CCS '21] CPscan: Detecting Bugs Caused by Code Pruning in IoT Kernels

[paper](https://www-users.cse.umn.edu/~kjlu/papers/cpscan.pdf) [tool: CPscan](https://github.com/zjuArclab/CPscan)

<details>
	<summary>Abstract</summary>
To reduce the development costs, IoT vendors tend to construct IoT kernels by customizing the Linux kernel. Code pruning is common in this customization process. However, due to the intrinsic complexity of the Linux kernel and the lack of long-term effective maintenance, IoT vendors may mistakenly delete necessary security operations in the pruning process, which leads to various bugs such as memory leakage and NULL pointer dereference. Yet detecting bugs caused by code pruning in IoT kernels is difficult. Specifically, (1) a significant structural change makes precisely locating the deleted security operations (DSO ) difficult, and (2) inferring the security impact of a DSO is not trivial since it requires complex semantic understanding, including the developing logic and the context of the corresponding IoT kernel.<br/><br/>In this paper, we present CPscan, a system for automatically detecting bugs caused by code pruning in IoT kernels. First, using a new graph-based approach that iteratively conducts a structure-aware basic block matching, CPscan can precisely and efficiently identify theDSOs in IoT kernels. Then, CPscan infers the security impact of a DSO by comparing the bounded use chains (where and how a variable is used within potentially influenced code segments) of the security-critical variable associated with it. Specifically, CPscan reports the deletion of a security operation as vulnerable if the bounded use chain of the associated security-critical variable remains the same before and after the deletion. This is because the unchanged uses of a security-critical variable likely need the security operation, and removing it may have security impacts. The experimental results on 28 IoT kernels from 10 popular IoT vendors show that CPscan is able to identify 3,193DSO s and detect 114 new bugs with a reasonably low false-positive rate. Many such bugs tend to have a long latent period (up to 9 years and 5 months). We believe CPscan paves a way for eliminating the bugs introduced by code pruning in IoT kernels. We will open-source CPscan to facilitate further research.
</details>