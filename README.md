# Frida Ultimap

Frida Ultimap is a Python script that uses Frida to list all function calls of a process, including those that are not exported. It can also dump strings that appear in function arguments.
## Getting Started
### Prerequisites

    Clone this repository to your local machine:
    Navigate to the directory where you cloned the repository

### Installation

    pip3 install frida psutil


## Usage

1. Use the *exportFuncs.py* script to export the IDA functions. It is recommended to read the notice inside the script before using it.

2. Run the script with the --platform argument to specify which platform you want to use

3. A small configuration will be saved the first time the script is run, which can be loaded to avoid filling in some variables.

4. Follow the prompts to configure the script. 

5. Timeout must be greater than 2000

6. Set the "dump string" value to 0 to improve tracing performance.
    



## TODO

- Fix the android bug if nobody does it (hard)
- write a small tool to diff saved trace (intersection, only in <trace>, etc ...) (easy)



## Limitation

1. There is an issue with Android where function hooking causes a crash. See this [issue](https://github.com/frida/frida/issues/2376) for more information.

2. If process is spawn it must live at least 10 secondes

3. Library backtrace is not great, so the script just printing the library function name

4. Scripts are written in JavaScript, which leads to a loss of performance compared to native gum-js

