Installation:

git clone https://github.com/noahostle/basic-proc-injection
cd basic-proc-injection
make



Usage:

inject.exe <exe name> <full dll path>

eg.
inject.exe notepad.exe C:\path\to\dll.dll




Description:

My first ever process injection script :D
Can either inject assembly straight into proc memory, or can use kernel32 to load a dll as a child thread in a process.
Automatically gets handle on process from its executable name, and can inject a custom dll (must use full path) or hardcoded assembly payload.
Uses Windows API with NO evasion techniques, this is my LITERAL first foray into maldev/game hooking so gomd.
Heres to a long and fruitful career in getting tf out of bug bounty and doing reverse engineering at [REDACTED] >:D

