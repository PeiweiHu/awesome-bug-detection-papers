- [awesome-bug-detection-papers (static)](#awesome-bug-detection-papers-static)
	- [2016](#2016)
		- [[USENIX Security '16] APISan: Sanitizing API Usages through Semantic Cross-Checking](#usenix-security-16-apisan-sanitizing-api-usages-through-semantic-cross-checking)
	- [2017](#2017)
		- [[USENIX Security '17] DR. CHECKER: A Soundy Analysis for Linux Kernel Drivers](#usenix-security-17-dr-checker-a-soundy-analysis-for-linux-kernel-drivers)
	- [2018](#2018)
		- [[NDSS '18] K-Miner: Uncovering Memory Corruption in Linux](#ndss-18-k-miner-uncovering-memory-corruption-in-linux)
		- [[USENIX ATC '18] DSAC: Effective Static Analysis of Sleep-in-Atomic-Context Bugs in Kernel Modules](#usenix-atc-18-dsac-effective-static-analysis-of-sleep-in-atomic-context-bugs-in-kernel-modules)
	- [2019](#2019)
		- [[USENIX ATC '19] Effective Static Analysis of Concurrency Use-After-Free Bugs in Linux Device Drivers](#usenix-atc-19-effective-static-analysis-of-concurrency-use-after-free-bugs-in-linux-device-drivers)
		- [[USENIX Security '19] PeX: A Permission Check Analysis Framework for Linux Kernel](#usenix-security-19-pex-a-permission-check-analysis-framework-for-linux-kernel)
		- [[USENIX Security '19] Detecting missing-check bugs via semantic- and context-aware criticalness and constraints inferences](#usenix-security-19-detecting-missing-check-bugs-via-semantic--and-context-aware-criticalness-and-constraints-inferences)
	- [2020](#2020)
		- [[CCS '20] RTFM! Automatic Assumption Discovery and Verification Derivation from Library Document for API Misuse Detection](#ccs-20-rtfm-automatic-assumption-discovery-and-verification-derivation-from-library-document-for-api-misuse-detection)
	- [2021](#2021)
		- [[S&P '21] ARBITRAR: User-Guided API Misuse Detection](#sp-21-arbitrar-user-guided-api-misuse-detection)
		- [[USENIX Security '21] Finding Bugs Using Your Own Code: Detecting Functionally-similar yet Inconsistent Code](#usenix-security-21-finding-bugs-using-your-own-code-detecting-functionally-similar-yet-inconsistent-code)
		- [[USENIX Security '21] Understanding and Detecting Disordered Error Handling with Precise Function Pairing](#usenix-security-21-understanding-and-detecting-disordered-error-handling-with-precise-function-pairing)
		- [[USENIX Security '21] Detecting Kernel Refcount Bugs with Two-Dimensional Consistency Checking](#usenix-security-21-detecting-kernel-refcount-bugs-with-two-dimensional-consistency-checking)
		- [[USENIX Security '21] PASAN: Detecting Peripheral Access Concurrency Bugs within Bare-Metal Embedded Applications](#usenix-security-21-pasan-detecting-peripheral-access-concurrency-bugs-within-bare-metal-embedded-applications)
		- [[USENIX Security '21] Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems](#usenix-security-21-sharing-more-and-checking-less-leveraging-common-input-keywords-to-detect-bugs-in-embedded-systems)
		- [[CCS '21] Statically Discovering High-Order Taint Style Vulnerabilities in OS Kernels](#ccs-21-statically-discovering-high-order-taint-style-vulnerabilities-in-os-kernels)
		- [[CCS '21] DoubleX: Statically Detecting Vulnerable Data Flows in Browser Extensions at Scale](#ccs-21-doublex-statically-detecting-vulnerable-data-flows-in-browser-extensions-at-scale)
		- [[CCS '21] MirChecker: Detecting Bugs in Rust Programs via Static Analysis](#ccs-21-mirchecker-detecting-bugs-in-rust-programs-via-static-analysis)
		- [[CCS '21] Detecting Missed Security Operations through Differential Checking of Object-based Similar Paths](#ccs-21-detecting-missed-security-operations-through-differential-checking-of-object-based-similar-paths)
		- [[CCS '21] CPscan: Detecting Bugs Caused by Code Pruning in IoT Kernels](#ccs-21-cpscan-detecting-bugs-caused-by-code-pruning-in-iot-kernels)
		- [[NDSS '21] KUBO: Precise and Scalable Detection of User-triggerable Undefined Behavior Bugs in OS Kernel](#ndss-21-kubo-precise-and-scalable-detection-of-user-triggerable-undefined-behavior-bugs-in-os-kernel)
		- [[NDSS '21] Detecting Kernel Memory Leaks in Specialized Modules with Ownership Reasoning](#ndss-21-detecting-kernel-memory-leaks-in-specialized-modules-with-ownership-reasoning)
	- [2022](#2022)
		- [[NDSS '22] Testability Tarpits: the Impact of Code Patterns on the Security Testing of Web Applications](#ndss-22-testability-tarpits-the-impact-of-code-patterns-on-the-security-testing-of-web-applications)
		- [[NDSS '22] An In-depth Analysis of Duplicated Linux Kernel Bug Reports](#ndss-22-an-in-depth-analysis-of-duplicated-linux-kernel-bug-reports)
		- [[NDSS '22] Progressive Scrutiny: Incremental Detection of UBI bugs in the Linux Kernel](#ndss-22-progressive-scrutiny-incremental-detection-of-ubi-bugs-in-the-linux-kernel)
- [awesome-bug-detection-papers (dynamic)](#awesome-bug-detection-papers-dynamic)

# awesome-bug-detection-papers (static)

## 2016

### [USENIX Security '16] APISan: Sanitizing API Usages through Semantic Cross-Checking

[paper](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_yun.pdf) [project: APISan](https://github.com/sslab-gatech/apisan)

<details>
	<summary>Abstract</summary>
API misuse is a well-known source of bugs. Some of them (e.g., incorrect use of SSL API, and integer overflow of memory allocation size) can cause serious security vulnerabilities (e.g., man-in-the-middle (MITM) attack, and privilege escalation). Moreover, modern APIs, which are large, complex, and fast evolving, are error-prone. However, existing techniques to help finding bugs require manual effort by developers (e.g., providing specification or model) or are not scalable to large real-world software comprising millions of lines of code.<br/><br/>In this paper, we present APISAN, a tool that automatically infers correct API usages from source code without manual effort. The key idea in APISAN is to extract likely correct usage patterns in four different aspects (e.g., causal relation, and semantic relation on arguments) by considering semantic constraints. APISAN is tailored to check various properties with security implications. We applied APISAN to 92 million lines of code, including Linux Kernel, and OpenSSL, found 76 previously unknown bugs, and provided patches for all the bugs.
</details>

## 2017

### [USENIX Security '17] DR. CHECKER: A Soundy Analysis for Linux Kernel Drivers

[paper](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-machiry.pdf) [project: DR. CHECKER](https://github.com/ucsb-seclab/dr_checker)

<details>
	<summary>Abstract</summary>
While kernel drivers have long been know to poses huge security risks, due to their privileged access and lower code quality, bug-finding tools for drivers are still greatly lacking both in quantity and effectiveness. This is because the pointer-heavy code in these drivers present some of the hardest challenges to static analysis, and their tight coupling with the hardware make dynamic analysis infeasible in most cases. In this work, we present DR. CHECKER, a soundy (i.e., mostly sound) bug-finding tool for Linux kernel drivers that is based on well-known program analysis techniques. We are able to overcome many of the inherent limitations of static analysis by scoping our analysis to only the most bug-prone parts of the kernel (i.e., the drivers), and by only sacrificing soundness in very few cases to ensure that our technique is both scalable and precise. DR. CHECKER is a fully-automated static analysis tool capable of performing general bug finding using both pointer and taint analyses that are flow-sensitive, context-sensitive, and field-sensitive on kernel drivers. To demonstrate the scalability and efficacy of DR. CHECKER, we analyzed the drivers of nine production Linux kernels (3.1 million LOC), where it correctly identified 158 critical zero-day bugs with an overall precision of 78%.
</details>

## 2018

### [NDSS '18] K-Miner: Uncovering Memory Corruption in Linux
[paper](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_05A-1_Gens_paper.pdf) [project: K-Miner](https://github.com/ssl-tud/k-miner)

<details>
	<summary>Abstract</summary>
Operating system kernels are appealing attack targets: compromising the kernel usually allows attackers to bypass all deployed security mechanisms and take control over the entire system. Commodity kernels, like Linux, are written in low-level programming languages that offer only limited type and memory-safety guarantees, enabling adversaries to launch sophisticated run-time attacks against the kernel by exploiting memory-corruption vulnerabilities. Many defenses have been proposed to protect operating systems at run time, such as control-flow integrity (CFI). However, the goal of these run-time monitors is to prevent exploitation as a symptom of memory corruption, rather than eliminating the underlying root cause, i.e., bugs in the kernel code. While finding bugs can be automated, e.g., using static analysis, all existing approaches are limited to local, intra-procedural checks, and face severe scalability challenges due to the large kernel code base. Consequently, there currently exist no tools for conducting global static analysis of operating system kernels. In this paper, we present K-Miner, a new framework to efficiently analyze large, commodity operating system kernels like Linux. Our novel approach exploits the highly standardized interface structure of the kernel code to enable scalable pointer analysis and conduct global, context-sensitive analysis. Through our inter-procedural analysis we show that K-Miner systematically and reliably uncovers several different classes of memory-corruption vulnerabilities, such as dangling pointers, user-after-free, double-free, and double-lock vulnerabilities. We thoroughly evaluate our extensible analysis framework, which leverages the popular and widely used LLVM compiler suite, for the current Linux kernel and demonstrate its effectiveness by reporting several memory-corruption vulnerabilities.
</details>

### [USENIX ATC '18] DSAC: Effective Static Analysis of Sleep-in-Atomic-Context Bugs in Kernel Modules

[paper](https://www.usenix.org/system/files/conference/atc18/atc18-bai.pdf) <u>project: DSAC</u>

<details>
	<summary>Abstract</summary>
In a modern OS, kernel modules often use spinlocks and interrupt handlers to monopolize a CPU core for executing concurrent code in atomic context. In this situation, if the kernel module performs an operation that can sleep at runtime, a system hang may occur in execution. We refer to this kind of concurrency bug as a sleep-in-atomic-context (SAC) bug. In practice, SAC bugs have received insufficient attention and are hard to find, as they do not always cause problems in real executions.<br/><br/>In this paper, we propose a practical static approach named DSAC, to effectively detect SAC bugs and automatically recommend patches to help fix them. DSAC uses four key techniques: (1) a hybrid of flow-sensitive and -insensitive analysis to perform accurate and efficient code analysis; (2) a heuristics-based method to accurately extract sleep-able kernel interfaces that can sleep at runtime; (3) a path-check method to effectively filter out repeated reports and false bugs; (4) a pattern-based method to automatically generate recommended patches to help fix the bugs.<br/><br/>We evaluate DSAC on kernel modules (drivers, file systems, and network modules) of the Linux kernel, and on the FreeBSD and NetBSD kernels, and in total find 401 new real bugs. 272 of these bugs have been confirmed by the relevant kernel maintainers, and 43 patches generated by DSAC have been applied by kernel maintainers.
</details>

## 2019

### [USENIX ATC '19] Effective Static Analysis of Concurrency Use-After-Free Bugs in Linux Device Drivers

[paper](https://www.usenix.org/system/files/atc19-bai.pdf) <u>project: DCUAF</u>

<details>
	<summary>Abstract</summary>
In Linux device drivers, use-after-free (UAF) bugs can cause system crashes and serious security problems. According to our study of Linux kernel commits, 42% of the driver commits fixing use-after-free bugs involve driver concurrency. We refer to these use-after-free bugs as concurrency use-after-free bugs. Due to the non-determinism of concurrent execution, concurrency use-after-free bugs are often more difficult to reproduce and detect than sequential use-after-free bugs.<br/><br/>In this paper, we propose a practical static analysis approach named DCUAF, to effectively detect concurrency use-after-free bugs in Linux device drivers. DCUAF combines a local analysis analyzing the source code of each driver with a global analysis statistically analyzing the local results of all drivers, forming a local-global analysis, to extract the pairs of driver interface functions that may be concurrently executed. Then, with these pairs, DCUAF performs a summary-based lockset analysis to detect concurrency use-after-free bugs. We have evaluated DCUAF on the driver code of Linux 4.19, and found 640 real concurrency use-after-free bugs. We have randomly selected 130 of the real bugs and reported them to Linux kernel developers, and 95 have been confirmed.
</details>

### [USENIX Security '19] PeX: A Permission Check Analysis Framework for Linux Kernel

[paper](https://www.usenix.org/system/files/sec19-zhang-tong.pdf) [project: PeX](https://github.com/lzto/pex)

<details>
	<summary>Abstract</summary>
Permission checks play an essential role in operating system security by providing access control to privileged functionalities. However, it is particularly challenging for kernel developers to correctly apply new permission checks and to scalably verify the soundness of existing checks due to the large codebase and complexity of the kernel. In fact, Linux kernel contains millions of lines of code with hundreds of permission checks, and even worse its complexity is fast-growing.<br/><br/>This paper presents PeX, a static Permission check error detector for LinuX, which takes as input a kernel source code and reports any missing, inconsistent, and redundant permission checks. PeX uses KIRIN (Kernel InteRface based In-direct call aNalysis), a novel, precise, and scalable indirect call analysis technique, leveraging the common programming paradigm used in kernel abstraction interfaces. Over the inter-procedural control flow graph built by KIRIN, PeX automatically identifies all permission checks and infers the mappings between permission checks and privileged functions. For each privileged function, PeX examines all possible paths to the function to check if necessary permission checks are correctly enforced before it is called.<br/><br/>We evaluated PeX on the latest stable Linux kernel v4.18.5for three types of permission checks: Discretionary AccessControls (DAC), Capabilities, and Linux Security Modules(LSM). PeX reported 36 new permission check errors, 14 of which have been confirmed by the kernel developers.
</details>

### [USENIX Security '19] Detecting missing-check bugs via semantic- and context-aware criticalness and constraints inferences

[paper](https://www.usenix.org/system/files/sec19-lu.pdf) [project: CRIX](https://github.com/umnsec/crix/)

<details>
	<summary>Abstract</summary>
Missing a security check is a class of semantic bugs in software programs where erroneous execution states are not validated. Missing-check bugs are particularly common in OS kernels because they frequently interact with external untrusted user space and hardware, and carry out error-prone computation. Missing-check bugs may cause a variety of critical security consequences, including permission bypasses, out-of-bound accesses, and system crashes. While missingcheck bugs are common and critical, only a few research works have attempted to detect them, which is arguably because of the inherent challenges in the detection--whether a variable requires a security check depends on its semantics, contexts and developer logic, and understanding them is a hard problem.<br/><br/>In this paper, we present CRIX, a system for detecting missing-check bugs in OS kernels. CRIX can scalably and precisely evaluate whether any security checks are missing for critical variables, using an inter-procedural, semantic- and context-aware analysis. In particular, CRIX's modeling and cross-checking of the semantics of conditional statements in the peer slices of critical variables infer their criticalness, which allows CRIX to effectively detect missing-check bugs. Evaluation results show that CRIX finds missing-check bugs with reasonably low false-report rates. Using CRIX, we have found 278 new missing-check bugs in the Linux kernel that can cause security issues. We submitted patches for all these bugs; Linux maintainers have accepted 151 of them. The promising results show that missing-check bugs are a common occurrence, and CRIX is effective and scalable in detecting missing-check bugs in OS kernels.
</details>

## 2020

### [CCS '20] RTFM! Automatic Assumption Discovery and Verification Derivation from Library Document for API Misuse Detection

[paper](https://homes.luddy.indiana.edu/luyixing/bib/CCS20-rtmf.pdf) [project: Advance](https://kaichen.org/tools/Advance.html)

<details>
  <summary>Abstract</summary>
To use library APIs, a developer is supposed to follow guidance and respect some constraints, which we call integration assumptions (IAs). Violations of these assumptions can have serious consequences, introducing security-critical flaws such as use-after-free, NULL-dereference, and authentication errors. Analyzing a program for compliance with IAs involves significant effort and needs to be automated. A promising direction is to automatically recover IAs from a library document using Natural Language Processing (NLP) and then verify their consistency with the ways APIs are used in a program through code analysis. However, a practical solution along this line needs to overcome several key challenges, particularly the discovery of IAs from loosely formatted documents and interpretation of their informal descriptions to identify complicated constraints (e.g., data-/control-flow relations between different APIs). <br/><br/>In this paper, we present a new technique for automated assumption discovery and verification derivation from library documents. Our approach, called Advance, utilizes a suite of innovations to address those challenges. More specifically, we leverage the observation that IAs tend to express a strong sentiment in emphasizing the importance of a constraint, particularly those security-critical, and utilize a new sentiment analysis model to accurately recover them from loosely formatted documents. These IAs are further processed to identify hidden references to APIs and parameters, through an embedding model, to identify the information-flow relations expected to be followed. Then our approach runs frequent subtree mining to discover the grammatical units in IA sentences that tend to indicate some categories of constraints that could have security implications. These components are mapped to verification code snippets organized in line with the IA sentence's grammatical structure, and can be assembled into verification code executed through CodeQL to discover misuses inside a program. We implemented this design and evaluated it on 5 popular libraries (OpenSSL, SQLite, libpcap, libdbus and libxml2) and 39 real-world applications. Our analysis discovered 193 API misuses, including 139 flaws never reported before.
</details>

## 2021

### [S&P '21] ARBITRAR: User-Guided API Misuse Detection

[paper](https://www.cis.upenn.edu/~mhnaik/papers/oakland21.pdf) [project: arbitrar](https://github.com/petablox/arbitrar)

<details>
	<summary>Abstract</summary>
Software APIs exhibit rich diversity and complexity which not only renders them a common source of programming errors but also hinders program analysis tools for checking them. Such tools either expect a precise API specification, which requires program analysis expertise, or presume that correct API usages follow simple idioms that can be automatically mined from code, which suffers from poor accuracy. We propose a new approach that allows regular programmers to find API misuses. Our approach interacts with the user to classify valid and invalid usages of each target API method. It minimizes user burden by employing an active learning algorithm that ranks API usages by their likelihood of being invalid. We implemented our approach in a tool called ARBITRAR for C/C++ programs, and applied it to check the uses of 18 API methods in 21 large real-world programs, including OpenSSL and Linux Kernel. Within just 3 rounds of user interaction on average per API method, ARBITRAR found 40 new bugs, with patches accepted for 18 of them. Moreover, ARBITRAR finds all known bugs reported by a state-of-the-art tool APISAN in a benchmark suite comprising 92 bugs with a false positive rate of only 51.5% compared to APISAN’s 87.9%.
</details>

### [USENIX Security '21] Finding Bugs Using Your Own Code: Detecting Functionally-similar yet Inconsistent Code

[paper](https://www.usenix.org/system/files/sec21-ahmadi.pdf) [project: FICS](https://github.com/RiS3-Lab/FICS)

<details>
	<summary>Abstract</summary>
Probabilistic classification has shown success in detecting known types of software bugs. However, the works following this approach tend to require a large amount of specimens to train their models. We present a new machine learning-based bug detection technique that does not require any external code or samples for training. Instead, our technique learns from the very codebase on which the bug detection is performed, and therefore, obviates the need for the cumbersome task of gathering and cleansing training samples (e.g., buggy code of certain kinds). The key idea behind our technique is a novel two-step clustering process applied on a given codebase. This clustering process identifies code snippets in a project that are functionally-similar yet appear in inconsistent forms. Such inconsistencies are found to cause a wide range of bugs, anything from missing checks to unsafe type conversions. Unlike previous works, our technique is generic and not specific to one type of inconsistency or bug. We prototyped our technique and evaluated it using 5 popular open source software, including QEMU and OpenSSL. With a minimal amount of manual analysis on the inconsistencies detected by our tool, we discovered 22 new unique bugs, despite the fact that many of these programs are constantly undergoing bug scans and new bugs in them are believed to be rare.
</details>

### [USENIX Security '21] Understanding and Detecting Disordered Error Handling with Precise Function Pairing

[paper](https://www.usenix.org/system/files/sec21-wu-qiushi.pdf) <u>project: HERO</u>

<details>
	<summary>Abstract</summary>
Software programs may frequently encounter various errors such as allocation failures. Error handling aims to gracefully deal with the errors to avoid security and reliability issues, thus it is prevalent and vital. However, because of its complexity and corner cases, error handling itself is often erroneous, and prior research has primarily focused on finding bugs in the handling part, such as incorrect error-code returning or missing error propagation.<br/><br/>In this paper, we propose and investigate a class of bugs in error-handling code from a different perspective. In particular, we find that programs often perform "cleanup" operations before the actual error handling, such as freeing memory or decreasing refcount. Critical bugs occur when these operations are performed (1) in an incorrect order, (2) redundantly, or (3) inadequately. We refer to such bugs as Disordered Error Handling (DiEH). Our investigation reveals that DiEH bugs are not only common but can also cause security problems such as privilege escalation, memory corruption, and denial-of-service. Based on the findings from the investigation, we then develop a system, HERO (Handling ERrors Orderly), to automatically detect DiEH. The core of HERO is a novel technique that precisely pairs both common and custom functions based on the unique error-handling structures, which allows us to infer expected cleanup functions. With HERO, we found 239 DiEH bugs in the Linux kernel, the FreeBSD kernel, and OpenSSL, which can cause security and reliability issues. The evaluation results show that DiEH is critical and widely exists in system software, and HERO is effective in detecting DiEH. We also believe that the precise function pairing is of independent interest in other research areas such as temporal-rule inference and race detection.
</details>

### [USENIX Security '21] Detecting Kernel Refcount Bugs with Two-Dimensional Consistency Checking

[paper](https://www.usenix.org/system/files/sec21-tan.pdf) <u>project: CID</u>

<details>
	<summary>Abstract</summary>
In the Linux kernel, reference counting (refcount) has become a default mechanism that manages resource objects. A refcount of a tracked object is incremented when a new reference is assigned and decremented when a reference becomes invalid. Since the kernel manages a large number of shared resources, refcount is prevalent. Due to the inherent complexity of the kernel and resource sharing, developers often fail to properly update refcounts, leading to refcount bugs. Researchers have shown that refcount bugs can cause critical security impacts like privilege escalation; however, the detection of refcount bugs remains an open problem.<br/><br/>In this paper, we propose CID, a new mechanism that employs two-dimensional consistency checking to automatically detect refcount bugs. By checking if callers consistently use a refcount function, CID detects deviating cases as potential bugs, and by checking how a caller uses a refcount function, CID infers the condition-aware rules for the function to correspondingly operate the refcount, and thus a violating case is a potential bug. More importantly, CID's consistency checking does not require complicated semantic understanding, inter-procedural data-flow tracing, or refcount-operation reasoning. CID also features an automated mechanism that systematically identifies refcount fields and functions in the whole kernel. We implement CID and apply it to the Linux kernel. The tool found 44 new refcount bugs that may cause severe security issues, most of which have been confirmed by the maintainers.
</details>

### [USENIX Security '21] PASAN: Detecting Peripheral Access Concurrency Bugs within Bare-Metal Embedded Applications

[paper](https://www.usenix.org/system/files/sec21-kim.pdf) <u>project: PASan</u>

<details>
	<summary>Abstract</summary>
Concurrency bugs might be one of the most challenging software defects to detect and debug due to their non-deterministic triggers caused by task scheduling and interrupt handling. While different tools have been proposed to address concurrency issues, protecting peripherals in embedded systems from concurrent accesses imposes unique challenges. A naïve lock protection on a certain memory-mapped I/O (MMIO) address still allows concurrent accesses to other MMIO addresses of a peripheral. Meanwhile, embedded peripherals such as sensors often employ some internal state machines to achieve certain functionalities. As a result, improper locking can lead to the corruption of peripherals' on-going jobs (we call transaction corruption) thus corrupted sensor values or failed jobs.<br/><br/>In this paper, we propose a static analysis tool namely PASAN to detect peripheral access concurrency issues for embedded systems. PASAN automatically finds the MMIO address range of each peripheral device using the parser-ready memory layout documents, extracts the peripheral's internal state machines using the corresponding device drivers, and detects concurrency bugs of peripheral accesses automatically. We evaluate PASAN on seven different embedded platforms, including multiple real time operating systems (RTOSes) and robotic aerial vehicles (RAVs). PASAN found 17 true positive concurrency bugs in total from three different platforms with the bug detection rates ranging from 40% to 100%. We have reported all our findings to the corresponding parties. To the best of our knowledge, PASAN is the first static analysis tool detecting the intrinsic problems in concurrent peripheral accesses for embedded systems.
</details>

### [USENIX Security '21] Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems

[paper](https://www.usenix.org/system/files/sec21-chen-libo.pdf) <u>project: SaTC</u>

<details>
	<summary>Abstract</summary>
IoT devices have brought invaluable convenience to our daily life. However, their pervasiveness also amplifies the impact of security vulnerabilities. Many popular vulnerabilities of embedded systems reside in their vulnerable web services. Unfortunately, existing vulnerability detection methods cannot effectively nor efficiently analyze such web services: they either introduce heavy execution overheads or have many false positives and false negatives.<br/><br/>In this paper, we propose a novel static taint checking solution, SaTC, to effectively detect security vulnerabilities in web services provided by embedded devices. Our key insight is that, string literals on web interfaces are commonly shared between front-end files and back-end binaries to encode user input. We thus extract such common keywords from the front-end, and use them to locate reference points in the back-end, which indicate the input entry. Then, we apply targeted data-flow analysis to accurately detect dangerous uses of the untrusted user input. We implemented a prototype of SaTC and evaluated it on 39 embedded system firmwares from six popular vendors. SaTC discovered 33 unknown bugs, of which 30 are confirmed by CVE/CNVD/PSV. Compared to the state-of-the-art tool KARONTE, SaTC found significantly more bugs on the test set. It shows that, SaTC is effective in discovering bugs in embedded systems.
</details>

### [CCS '21] Statically Discovering High-Order Taint Style Vulnerabilities in OS Kernels

[paper](https://www.cs.ucr.edu/~zhiyunq/pub/ccs21_static_high_order.pdf) [project: SUTURE](https://github.com/seclab-ucr/SUTURE)

<details>
  <summary>Abstract</summary>
Static analysis is known to yield numerous false alarms when used in bug finding, especially for complex vulnerabilities in large code bases like the Linux kernel. One important class of such complex vulnerabilities is what we call "high-order taint style vulnerability", where the taint flow from the user input to the vulnerable site crosses the boundary of a single entry function invocation (i.e., syscall). Due to the large scope and high precision requirement, few have attempted to solve the problem. In this paper, we present SUTURE, a highly precise and scalable static analysis tool capable of discovering high-order vulnerabilities in OS kernels. SUTURE employs a novel summary-based high-order taint flow construction approach to efficiently enumerate the cross-entry taint flows, while incorporating multiple innovative enhancements on analysis precision that are unseen in existing tools, resulting in a highly precise inter-procedural flow-, context-, field-, index-, and opportunistically path-sensitive static taint analysis. We apply SUTURE to discover high-order taint vulnerabilities in multiple Android kernels from mainstream vendors (e.g., Google, Samsung, Huawei), the results show that SUTURE can both confirm known high-order vulnerabilities and uncover new ones. So far, SUTURE generates 79 true positive warning groups, of which 19 have been confirmed by the vendors, including a high severity vulnerability rated by Google. SUTURE also achieves a reasonable false positive rate (51.23%) perceived by users of our tool.
</details>

### [CCS '21] DoubleX: Statically Detecting Vulnerable Data Flows in Browser Extensions at Scale

[paper](https://swag.cispa.saarland/papers/fass2021doublex.pdf) [project: DoubleX](https://github.com/Aurore54F/DoubleX)

<details>
  <summary>Abstract</summary>
Browser extensions are popular to enhance users' browsing experience. By design, they have access to security- and privacy-critical APIs to perform tasks that web applications cannot traditionally do. Even though web pages and extensions are isolated, they can communicate through messages. Specifically, a vulnerable extension can receive messages from another extension or web page, under the control of an attacker. Thus, these communication channels are a way for a malicious actor to elevate their privileges to the capabilities of an extension, which can lead to, e.g., universal cross-site scripting or sensitive user data exfiltration. To automatically detect such security and privacy threats in benign-but-buggy extensions, we propose our static analyzer DoubleX. DoubleX defines an Extension Dependence Graph (EDG), which abstracts extension code with control and data flows, pointer analysis, and models the message interactions within and outside of an extension. This way, we can leverage this graph to track and detect suspicious data flows between external actors and sensitive APIs in browser extensions. We evaluated DoubleX on 154,484 Chrome extensions, where it flags 278 extensions as having a suspicious data flow. Overall, we could verify that 89% of these flows can be influenced by external actors (i.e., an attacker). Based on our threat model, we subsequently demonstrate exploitability for 184 extensions. Finally, we evaluated DoubleX on a labeled vulnerable extension set, where it accurately detects almost 93% of known flaws.
</details>

### [CCS '21] MirChecker: Detecting Bugs in Rust Programs via Static Analysis

[paper](https://www.cse.cuhk.edu.hk/~cslui/PUBLICATION/CCS2021.pdf) [project: MirChecker](https://github.com/lizhuohua/rust-mir-checker)

<details>
  <summary>Abstract</summary>
Safe system programming is often a crucial requirement due to its critical role in system software engineering. Conventional low-level programming languages such as C and assembly are efficient, but their inherent unsafe nature makes it undesirable for security-critical scenarios. Recently, Rust has become a promising alternative for safe system-level programming. While giving programmers fine-grained hardware control, its strong type system enforces many security properties including memory safety. However, Rust's security guarantee is not a silver bullet. Runtime crashes and memory-safety errors still harass Rust developers, causing damaging exploitable vulnerabilities, as reported by numerous studies.<br/><br/>In this paper, we present and evaluate MirChecker, a fully automated bug detection framework for Rust programs by performing static analysis on Rust's Mid-level Intermediate Representation (MIR). Based on the observation of existing bugs found in Rust codebases, our approach keeps track of both numerical and symbolic information, detects potential runtime crashes and memory-safety errors by using constraint solving techniques, and outputs informative diagnostics to users. We evaluate MirChecker on both buggy code snippets extracted from existing Common Vulnerabilities and Exposures (CVE) and real-world Rust codebases. Our experiments show that MirChecker can detect all the issues in our code snippets, and is capable of performing bug finding in real-world scenarios, where it detected a total of 33 previously unknown bugs including 16 memory-safety issues from 12 Rust packages (crates) with an acceptable false-positive rate.
</details>

### [CCS '21] Detecting Missed Security Operations through Differential Checking of Object-based Similar Paths

[paper](https://nesa.zju.edu.cn/download/ldh_pdf_IPPO.pdf) <u>project: IPPO</u>

<details>
  <summary>Abstract</summary>
Missing a security operation such as a bound check has been a major cause of security-critical bugs. Automatically checking whether the code misses a security operation in large programs is challenging since it has to understand whether the security operation is indeed necessary in the context. Recent methods typically employ cross-checking to identify deviations as security bugs, which collects functionally similar program slices and infers missed security operations through majority-voting. An inherent limitation of such approaches is that they heavily rely on a substantial number of similar code pieces to enable cross-checking. In practice, many code pieces are unique, and thus we may be unable to find adequate similar code snippets to utilize cross-checking. In this paper, we present IPPO (Inconsistent Path Pairs as a bug Oracle), a static analysis framework for detecting security bugs based on differential checking. IPPO defines several novel rules to identify code paths that share similar semantics with respect to an object, and collects them as similar-path pairs. It then investigates the path pairs for identifying inconsistent security operations with respect to the object. If one path in a path pair enforces a security operation while the other does not, IPPO reports it as a potential security bug. By utilizing on object-based path-similarity analysis, IPPO achieves a higher precision, compared to conventional code-similarity analysis methods. Through differential checking of a similar-path pair, IPPO eliminates the requirement of constructing a large number of similar code pieces, addressing the limitation of traditional cross-checking approaches. We implemented IPPO and extensively evaluated it on four widely used open-source programs: Linux kernel, OpenSSL library, FreeBSD kernel, and PHP. IPPO found 154, 5, 1, and 1 new security bugs in the above systems, respectively. We have submitted patches for all these bugs, and 136 of them have been accepted by corresponding maintainers. The results confirm the effectiveness and usefulness of IPPO in practice.
</details>

### [CCS '21] CPscan: Detecting Bugs Caused by Code Pruning in IoT Kernels

[paper](https://www-users.cse.umn.edu/~kjlu/papers/cpscan.pdf) [project: CPscan](https://github.com/zjuArclab/CPscan)

<details>
	<summary>Abstract</summary>
To reduce the development costs, IoT vendors tend to construct IoT kernels by customizing the Linux kernel. Code pruning is common in this customization process. However, due to the intrinsic complexity of the Linux kernel and the lack of long-term effective maintenance, IoT vendors may mistakenly delete necessary security operations in the pruning process, which leads to various bugs such as memory leakage and NULL pointer dereference. Yet detecting bugs caused by code pruning in IoT kernels is difficult. Specifically, (1) a significant structural change makes precisely locating the deleted security operations (DSO ) difficult, and (2) inferring the security impact of a DSO is not trivial since it requires complex semantic understanding, including the developing logic and the context of the corresponding IoT kernel.<br/><br/>In this paper, we present CPscan, a system for automatically detecting bugs caused by code pruning in IoT kernels. First, using a new graph-based approach that iteratively conducts a structure-aware basic block matching, CPscan can precisely and efficiently identify theDSOs in IoT kernels. Then, CPscan infers the security impact of a DSO by comparing the bounded use chains (where and how a variable is used within potentially influenced code segments) of the security-critical variable associated with it. Specifically, CPscan reports the deletion of a security operation as vulnerable if the bounded use chain of the associated security-critical variable remains the same before and after the deletion. This is because the unchanged uses of a security-critical variable likely need the security operation, and removing it may have security impacts. The experimental results on 28 IoT kernels from 10 popular IoT vendors show that CPscan is able to identify 3,193DSO s and detect 114 new bugs with a reasonably low false-positive rate. Many such bugs tend to have a long latent period (up to 9 years and 5 months). We believe CPscan paves a way for eliminating the bugs introduced by code pruning in IoT kernels. We will open-source CPscan to facilitate further research.
</details>

### [NDSS '21] KUBO: Precise and Scalable Detection of User-triggerable Undefined Behavior Bugs in OS Kernel

[paper](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-5_24461_paper.pdf) [project: KUBO](https://github.com/RiS3-Lab/kubo)

<details>
	<summary>Abstract</summary>
Undefined Behavior bugs (UB) often refer to a wide range of programming errors that mainly reside in software implemented in relatively low-level programming languages e.g., C/C++. OS kernels are particularly plagued by UB due to their close interactions with the hardware. A triggered UB can often lead to exploitation from unprivileged userspace programs and cause critical security and reliability issues inside the OS. The previous works on detecting UB in kernels had to sacrifice precision for scalability, and in turn, suffered from extremely high false positives which severely impaired their usability.<br/><br/>We propose a novel static UB detector for Linux kernel, called KUBO which simultaneously achieves high precision and whole-kernel scalability. KUBO is focused on detecting critical UB that can be triggered by userspace input. The high precision comes from KUBO’s verification of the satisfiability of the UB-triggering paths and conditions. The whole-kernel scalability is enabled by an efficient inter-procedural analysis, which incrementally walks backward along callchains in an on-demand manner. We evaluate KUBO on several versions of whole Linux kernels (including drivers). KUBO found 23 critical UBs that were previously unknown in the latest Linux kernel. KUBO’s false detection rate is merely 27.5%, which is significantly lower than that of the state-of-the-art kernel UB detectors (91%). Our evaluation also shows the bug reports generated by KUBO are easy to triage.
</details>

### [NDSS '21] Detecting Kernel Memory Leaks in Specialized Modules with Ownership Reasoning

[paper](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_5B-4_24416_paper.pdf) [project: k-meld](https://github.com/Navidem/k-meld/blob/main/results/FOIs.txt)

<details>
	<summary>Abstract</summary>
The kernel space is shared by hardware and all processes, so its memory usage is more limited, and memory is harder to reclaim, compared to user-space memory; as a result, memory leaks in the kernel can easily lead to high-impact denial of service. The problem is particularly critical in long-running servers. Kernel code makes heavy use of dynamic (heap) allocation, and many code modules within the kernel provide their own abstractions for customized memory management. On the other hand, the kernel code involves highly complicated data flow, so it is hard to determine where an object is supposed to be released. Given the complex and critical nature of OS kernels, as well as the heavy specialization, existing methods largely fail at effectively and thoroughly detecting kernel memory leaks.<br/><br/>In this paper, we present K-MELD, a static detection system for kernel memory leaks. K-MELD features multiple new techniques that can automatically identify specialized allocation/deallocation functions and determine the expected memory-release locations. Specifically, we first develop a usage- and structure-aware approach to effectively identify specialized allocation functions, and employ a new rule-mining approach to identify the corresponding deallocation functions. We then develop a new ownership reasoning mechanism that employs enhanced escape analysis and consumer-function analysis to infer expected release locations. By applying K-MELD to the Linux kernel, we confirm its effectiveness: it finds 218 new bugs, with 41 CVEs assigned. Out of those 218 bugs, 115 are in specialized modules.
</details>

## 2022

### [NDSS '22] Testability Tarpits: the Impact of Code Patterns on the Security Testing of Web Applications

[paper](http://193.55.114.4/docs/ndss22_alkassar.pdf) [project: TestabilityTarpits](https://github.com/enferas/TestabilityTarpits)

<details>
	<summary>Abstract</summary>
While static application security testing tools (SAST) have many known limitations, the impact of coding style on their ability to discover vulnerabilities remained largely unexplored. To fill this gap, in this study we experimented with a combination of commercial and open source security scanners, and compiled a list of over 270 different code patterns that, when present, impede the ability of state-of-the-art tools to analyze PHP and JavaScript code. By discovering the presence of these patterns during the software development lifecycle, our approach can provide important feedback to developers about the testability of their code. It can also help them to better assess the residual risk that the code could still contain vulnerabilities even when static analyzers report no findings. Finally, our approach can also point to alternative ways to transform the code to increase its testability for SAST.
</details>

### [NDSS '22] An In-depth Analysis of Duplicated Linux Kernel Bug Reports

[paper](https://gangw.cs.illinois.edu/ndss22-linux.pdf)

<details>
	<summary>Abstract</summary>
In the past three years, the continuous fuzzing projects Syzkaller and Syzbot have achieved great success in detecting kernel vulnerabilities, finding more kernel bugs than those found in the past 20 years. However, a side effect of continuous fuzzing is that it generates an excessive number of crash reports, many of which are “duplicated” reports caused by the same bug. While Syzbot uses a simple heuristic to group (deduplicate) reports, we find that it is often inaccurate. In this paper, we empirically analyze the duplicated kernel bug reports to understand: (1) the prevalence of duplication; (2) the potential costs introduced by duplication; and (3) the key causes behind the duplication problem. We collected all of the fixed kernel bugs from September 2017 to November 2020, including 3.24 million crash reports grouped by Syzbot under 2,526 bug reports (identified by unique bug titles). We found the bug reports indeed had duplication: 47.1% of the 2,526 bug reports are duplicated with one or more other reports. By analyzing the metadata of these reports, we found undetected duplication introduced extra costs in terms of time and developer efforts. Then we organized Linux kernel experts to analyze a sample of duplicated bugs (375 bug reports, unique 120 bugs) and identified 6 key contributing factors to the duplication. Based on these empirical findings, we proposed and prototyped actionable strategies for bug deduplication. After confirming their effectiveness using a ground-truth dataset, we further applied our methods and identified previously unknown duplication cases among open bugs.
</details>

### [NDSS '22] Progressive Scrutiny: Incremental Detection of UBI bugs in the Linux Kernel

[paper](https://www.cs.ucr.edu/~csong/ndss22-increlux.pdf) [project: IncreLux](https://github.com/seclab-ucr/IncreLux.git)

<details>
	<summary>Abstract</summary>
The Linux kernel has a rapid development cycle, with 10 commits every hour, on average. While these updates provide new features and bug fixes, they can also introduce new bugs and security vulnerabilities. Recent techniques showed how to detect some types of vulnerabilities using static analysis, but these tools cannot run quickly enough to keep up with the pace of kernel development. Ideally, an incremental analysis technique could address this problem, by doing a complete analysis once and then only analyzing changed portions of the code subsequently. However, incremental analysis of the Linux kernel poses unique challenges, due to its enormous scale and the high precision required to reduce false positives.
</details>

# awesome-bug-detection-papers (dynamic)