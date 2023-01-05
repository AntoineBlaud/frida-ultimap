# Frida Ultimap

Frida Ultimap is a Python script that uses Frida to list all function calls of a process, including those that are not exported. It can also dump strings that appear in function arguments.
## Getting Started
### Prerequisites
    - In order to sort functions by type, it is necessary to have IDA Pro software.
    - clone this repository to your local machine:

### Installation

    pip3 install frida psutil


## Usage

1. Use the *exportFuncs.py* script to export the IDA functions. It is recommended to read the notice inside the script before using it.

2. Run ultimap with the --platform argument to specify which platform you want to use

    `python frida-ultimap/ultimap.py --platform windows`

3. A small configuration will be saved the first time the script is run, which can be loaded to avoid filling in some variables.

4. Follow the prompts to configure the script. 

5. Timeout must be greater than 2000

6. Set the "dump string" value to 0 to improve tracing performance.

*The frida script is written inside the metadata directory*
    



## TODO

- Fix the arm Android [bug](https://github.com/frida/frida/issues/2376) if it has not been fixed already (difficulty: hard)
- Write a tool to compare saved traces (e.g. intersection, only in <trace>, etc.) (difficulty: easy)

## Android 

While the issue is still being resolved, I have found a solution for Android users. However, it requires Windows 11. 
Please follow the [installation](https://forum.xda-developers.com/t/wsa-build-2211-based-on-android-13-with-magisk-root-and-google-play-store.4535473/) instructions provided and then install the APK and Frida. Once completed, you should be able to use Frida without encountering any crashes due to the x64-x86 architecture.



## Limitation

1. There is an issue with Android where function hooking causes a crash. See this [issue](https://github.com/frida/frida/issues/2376) for more information.

2. If the process is spawned, it must be running for at least 10 seconds.

3. Library backtraces are not reliable, so the script only prints the library function name

4. Backend scripts are written in Quick JavaScript, which leads to a loss of performance compared to native gum-js

