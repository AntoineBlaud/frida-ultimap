from common import *
import argparse
import scriptcore
import os
import sys

extraDelayToWait = 4  # time to wait after the script is loaded to give time to the process to load the dlls
trueStdoutDescriptor = sys.stdout
metadataFolder = "metadata"

parser = argparse.ArgumentParser(description="Frida Ultimap. A script to trace functions calls")
parser.add_argument(
    "--platform",
    choices=["windows", "linux", "android"],
    default="windows",
    help="platform",
)
parser.add_argument("--config", required=False)
args = parser.parse_args()

print("Welcome to Ultimap, a Frida script to trace functions calls")
print("[INFO] Starting setup ...")

if args.config:
    processname, filename, exportedbase = load_config(args.config)
else:
    processname, filename, exportedbase = get_config_from_user()

isdesktop = any([args.platform == "windows", args.platform == "linux"])
functionsexported = load_exported_functions(filename)
realprocessname = processname
maindirectory = f"{metadataFolder}/{processname}"
session = None
todrop = set()

if not os.path.exists(metadataFolder):
    os.mkdir(metadataFolder)

if not os.path.exists(maindirectory):
    os.mkdir(maindirectory)

# save global params
with open(f"{metadataFolder}/{processname}/config", "w") as f:
    f.write("::".join([processname, filename, exportedbase]))

while True:
    # wait until enter is pressed
    wait(session)
    # ask the user for the timeout
    TIMEOUT = ask_timeout(default=8000)
    # ask the user if he wants to drop previous functions registered
    todrop = ask_drop(maindirectory, todrop)
    # drop previous functions
    functionsexported = load_exported_functions(filename, todrop)
    # ask the user for the trace description
    traceDescription = input("[>] Name the current record : ")
    askdump = input(
        "[>] Number of times to dump strings (default 20) : "
    )
    # build dictionary of variables that must be replaced in the script
    TIMETODUMPSTRING = "20" if askdump == "" else askdump
    MODULE_NAME = processname
    REGISTER_FUNC = functionsexported
    IDA_BASE = exportedbase
    dic_vars = {
        "$$MODULE_NAME$$": MODULE_NAME,
        "$$REGISTER_FUNC$$": REGISTER_FUNC,
        "$$TIMEOUT$$": str(TIMEOUT),
        "$$IDA_BASE$$": IDA_BASE,
        "$$DUMPSTRINGTIMES$$": TIMETODUMPSTRING,
    }
    # build script
    script = scriptcore.build_script(args, dic_vars)
    with open(f"{metadataFolder}/{processname}/script.js", "w") as f:
        f.write(script)
    # attach to process
    session, pid = find_process(processname, isdesktop)
    attach_script(script, pid, session)

    timeoutSeconds = TIMEOUT / 1000
    capture_results(
        extraDelayToWait,
        trueStdoutDescriptor,
        metadataFolder,
        processname,
        timeoutSeconds,
        traceDescription,
    )
