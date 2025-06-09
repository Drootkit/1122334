# 进程注入POC

## 共有33种手法

参考企业微信的文档。

线程操控：

1. T1055.002 Remote Thread Injection（经典的wpm和远程线程创建）
2. T1055.003 Suspend-Inject-Resume 【THREAD EXECUTION HIJACKING 】（经典的挂起、恢复进程）
3. T1055.004 APC Injection	（经典的利用APC注入的方式）
4. T1055.004 EarlyBird-APC-Injection（利用了进程启动过程中nttestalert来执行apc，对于检测来说缺少了apc的执行原语）
5. T1055.004 Early Cascade APC Injection（缺少了apc的插入过程，第一段shellcode负责在进程中自插入apc，第二段shellcode就是apc要执行的内容）
6. ThreadPool injection 
7. 进程休眠注入poc：https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack（）
8. bh议题，但是过于冷门，而且需要目标进程中有fiber： fiber : FLS Callback Injection
9. bh议题，但是过于冷门，而且需要目标进程中有fiber： Remote Dormant Fiber Injection仅限于自己进程，没有用，并且和后面的两个方法重复 T1055.002 Windows Fibers Injection

Windows Class：

10. （一般用于hook注入）SetwindowshookEx 但是es认为常用
11. 窗口子类化 PROPagate Injection
12. 窗口类 CLIPBRDWNDCLASS Injection
13. 窗口类 eminject
14. 窗口类 Console-Window-Host Injection
15. Tooltip or Common Controls （tooltips_class32 窗口注入）
16. T1055.011 窗口类 SetWindowLong （EWMI）Injection

modify callback 

17. EDR-Preloading Injection（篡改进程中的AvrfpAPILookupCallbackRoutine回调，指向shellcode，利用得当也可阻断edr的客户端dll）
18. T1574.013 KCT(kernel call table) Injection（修改kct表中的回调，涉及到写PEB，可以保留）
19. Service Control Injection（修改内部调度条目里的回调，执行shellcode）
20. Exception-Dispatching injection（VEH、SEH）
21. ctrl Injection（修改目标进程中的handlerlist的指针，修改对应的处理函数，使其指向shellcoce）
22. DNS Client API Callback（利用unt路径处理回调实现注入）
23. T1055.005 Thread Local Storage Injection
24. RICHEDIT Controls Injection（通过发消息实现，实现一个控件的即可）
25. DLL加载回调注入（篡改进程中dll加载回调结构中的指针，来执行shellcode）
26. ALPC Callback
27. WNF Callback
28. Instrumentation Callback
29. Shim Engine Injection
30.  WOW64 Callback Table (FinFisher)
31. Breaking BaDDEr
32. MPR DLL and Shell Notifications
33. Winsock Helper Functions (WSHX) Injection

全局空间

34. Stackbombing
35. Atombombing
36. tagcls injection

hook类型

37. ThreadLess

# 630完成目标

从目前全部收集的POC中，根据

- 热门程度（有ttp编号、攻击组织常用的）
- 实用程度（不是为了注入而注入，使用条件并不苛刻）
- 可用性（Win10上还有这个操作的）

三个方面进行筛选。还是将POC分为线程控制、Windows类控制、回调函数、全局空间四个方面进行分类。

共35个POC，预期实现20个

## 线程操控：

- T1055.002 Remote Thread Injection：经典的wpm和远程线程创建
- T1055.003 Suspend-Inject-Resume 【THREAD EXECUTION HIJACKING 】：经典的挂起、恢复进程
- T1055.004 APC Injection：经典的利用APC注入的方式
  - T1055.004 EarlyBird-APC-Injection：利用了进程启动过程中nttestalert来执行apc，对于检测来说缺少了apc的执行原语
  - T1055.004 Early Cascade APC Injection：缺少了apc的插入过程，第一段shellcode负责在进程中自插入apc，第二段shellcode就是apc要执行的内容
- ThreadPool injection：银狐御用攻击手法
- 进程休眠poc（没有执行原语）：https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack

去除：fiber利用等攻击手法，只存在于bh议题中，需要目标进程中有fiber，并且攻击行为和TLS回调等攻击手法相似。

## Windows 类

该类手法不存在明显的执行原语，

- 窗口类 CLIPBRDWNDCLASS Injection：用自己伪造的iunknown结构强制关联到CLIPBRDWNDCLASS。
- T1055.011 窗口类 SetWindowLong （EWMI）Injection：操作窗口的额外内存空间中

去除：

- SetwindowshookEx：一般用于dll注入或者敲击记录等
- Tooltip or Common Controls （tooltips_class32 窗口注入），本质也是对EWMI的使用

## 回调函数

- 窗口子类化 PROPagate Injection：修改的是窗口子类化的回调指针，用的是getprop
- 窗口类 eminject：sendmsg实现的写原语
- Exception-Dispatching injection（VEH、SEH）：利用异常处理进行注入，新型手法
- EDR-Preloading Injection：篡改进程中的`AvrfpAPILookupCallbackRoutine`回调，指向shellcode，利用得当也可阻断edr在r3加载dll。抑或是进行dll早期注入。
- T1574.013 KCT(kernel call table) Injection：该PEB里的内容。
- T1055.005 Thread Local Storage Injection：修改tls回调指针
- Instrumentation Callback：syscall 回调，也可以用来监控syscall的调用。
- DLL加载回调注入：篡改进程中dll加载回调结构中的指针，来执行shellcode，在进程启动早期篡改PEB里的结构
- ctrl Injection：涉及到地址加密，wpm可能无法关联

去除：

- 窗口类 Console-Window-Host Injection： 也是改回调函数，只不过是回调指针的位置不同
- RICHEDIT Controls Injection：也是通过发消息sendmsg实现
-  本地构造假结构体，和`CLIPBRDWNDCLASS` 思路相同
- Service Control Injection：本地构造假结构体，和`CLIPBRDWNDCLASS` 思路相同
- Winsock Helper Functions (WSHX) Injection：visa之后就过时了
- MPR DLL and Shell Notifications：win10中消失了，利用比较苛刻
- Breaking BaDDEr：2017年微软禁用了
- WOW64 Callback Table (FinFisher)：确实存在，但条件苛刻，需要在64位环境中执行32位
- WNF Callback：Windows信息回调机制，用wpm修改回调指针，和ctrl Injection思路相似
- DNS Client API Callback：利用处理unc路径的回调函数，也是wpm修改回调指针
- ALPC Callback：利用线程对alpc的处理回调，wpm实现，而且和threadpool有些重叠
- Shim Engine Injection：利用兼容模式的回调。和早期级联apc注入相似。

## 全局空间

- Atombombing

去除：tagcls injection，和上述一样，是写全局原子表，只要

## 其他

- Stackbombing：利用栈构造ROP执行shellcode
