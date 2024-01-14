# Ghidra plugin for Malcore API to run dynamic emulation on files
# @author Internet 2.0, Ltd
# @category Analysis
# @keybinding shift M
# @toolbar malcore.png

import json
import os
import sys
import time
import tempfile
import urllib


PLATFORM = ""


# fixes the Ghidra variables and appends the working OS Python path to them
if (os.name == "Posix" or os.name.getshadow() == "posix") and (("Linux") in os.uname()):
    PLATFORM = "linux"
    sys.path.append('/usr/lib/python2.7/dist-packages')
    sys.path.append('/usr/local/lib/python2.7/dist-packages')
    sys.path.append(os.path.expanduser('~') + '/.local/lib/python2.7/site-packages')
elif "Darwin" in os.uname():
    PLATFORM = "macos"
    sys.path.append('/System/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages')
    sys.path.append('/System/Library/Frameworks/Python.framework/Versions/2.7/lib/site-python')
    sys.path.append('/Library/Python/2.7/site-packages')
    sys.path.append(os.path.expanduser('~') + '/Library/Python/2.7/lib/python/site-packages')
elif os.name == "nt" or "windows" in java.lang.System.getProperty("os.name").lower():
    PLATFORM = "windows"
    sys.path.append('C:\\Python27')
    sys.path.append('C:\\Python27\\Lib\\site-packages')
elif os.name == "java":
    PLATFORM = "other"
    sys.path.append('/usr/lib/python2.7/dist-packages')
    sys.path.append('/usr/local/lib/python2.7/dist-packages')
    sys.path.append('/usr/local/lib/python2.7/site-packages')
else:
    print("failed to add correct PATH, unable to detect platform")
    exit(1)



class Formatter(object):

    """
    class to format the output from the dynamic analysis results.
    """

    total_suspicious_calls = 0

    def __init__(self, dynamic_results):
        self.dynamic_results = dynamic_results
        self.emulation_results = []

    def build_map(self):
        """
        builds a list containing the information we'll need to output
        """
        log("building output map from emulation results", "debug")
        for data in self.dynamic_results["parsed_output"]:
            self.emulation_results.append([
                data['dll_name'],
                data['function_called'],
                data['arguments_passed'],
                data['function_return_value'],
                data['known_suspicious_function'],
                data['location']
            ])

    def build_output_table(self):
        """
        formats the list that was initialized above
        """
        log("attempting to build output from emulation", "debug")
        split_string = "*" * 85
        print("\n\nDYNAMIC EMULATION REPORT:")
        print("{}\n".format(split_string))
        for row in self.emulation_results:
            if row[4] != 0:
                self.total_suspicious_calls += 1
            output_string = "({})>>> {} --> {}.{}".format(row[4], row[-1], row[0], row[1])
            if len(row[2]) != 0:
                output_string += "("
                for i, arg in enumerate(row[2], start=1):
                    if i != len(row[2]):
                        output_string += '{},'.format(arg)
                    else:
                        output_string += '{}'.format(arg)
                output_string += ")"
            else:
                output_string += "()"
            output_string += " => {}".format(row[3])
            print(output_string)
        print("\n{}\nFormat: (SUSPICION LEVEL)>>> ADDRESS --> DLL-NAME.FUNCTION-NAME(ARGS) => RETURN-VALUE\n\n".format(
            split_string
        ))


class ApiHandler(object):

    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key

    def dynamic_emulation(self, file_path):
        """
        responsible for the request to the API for analysis
        """
        headers = {
            "apiKey": self.api_key,
            "User-Agent": "Malcore Ghidra Plugin"
        }
        emulate_url = "{}/api/dynamicanalysis".format(self.base_url)
        data = {"filename1": open(file_path, "rb")}
        try:
            req = urllib.Request(emulate_url, data=data, headers=headers, method="POST")
            is_error = req.json()["data"]["isError"]
            if not is_error:
                results = req.json()["data"]["response"]
            else:
                error_msg = req.json()["data"]["error"]
                log(
                    "caught error ({}) while making request to the API returning empty dict".format(error_msg),
                    "error"
                )
                results = {}
        except:
            results = {}
        temp = tempfile.NamedTemporaryFile(delete=False, prefix="malcore_results_", suffix=".json")
        if len(results) != 0:
            json.dump(results, temp, indent=4)
            log("full dynamic emulation results saved to: {}".format(temp.name), "info")
        else:
            log("error during analysis will not save empty file", "info")
        temp.close()
        return results


class MalcoreDynamicEmulationPlugin(object):

    base_url = "https://api.malcore.io"

    def __init__(self, api_key):
        self.api_key = api_key

    def run(self):
        """
        this function is responsible for running the analysis and performing all other
        operations of the plugin
        """
        path = currentProgram.getExecutablePath()
        if PLATFORM == "windows":
            # fix the path so we don't get a leading "/" in it on Windows
            path = path[1:]
        file_size = os.stat(path)
        # 25MB is the max file size this plugin can handle
        if file_size.st_size > 26214400:
            log("only able to handle up to 25mb files", "error")
            return
        if not is_pe(path):
            log("can only handle Windows PE files for emulation", "error")
            return
        program_name = currentProgram.getName()
        creation_date = currentProgram.getCreationDate()
        language_id = currentProgram.getLanguageID()
        compiler_spec_id = currentProgram.getCompilerSpec().getCompilerSpecID()
        log("current file path: {}".format(path), level="debug")
        if not path:
            log("file path does not exist".format(path), level="error")
            return
        log("current program name: {}".format(program_name), level="debug")
        log("database creation date: {}".format(creation_date), level="debug")
        log("file language ID: {}".format(language_id), level="debug")
        log("compiler information: {}".format(compiler_spec_id), level="debug")
        log("sending file: {} to start emulation".format(path), level="INFO")
        emulator = ApiHandler(self.base_url, self.api_key)
        results = emulator.dynamic_emulation(path)
        if len(results) == 0:
            log("dynamic emulation was not successful", "error")
        return results


TOTAL_SUSPICIOUS_CALLS = 0
VERSION = "0.1"
VERSION_STRING = "dev" if VERSION.count(".") > 3 else "stable"
URL = "https://malcore.io"
LOGO = """    __  ___      __                   
   /  |/  /___ _/ /________  ________ 
  / /|_/ / __ `/ / ___/ __ \/ ___/ _ \\
 / /  / / /_/ / / /__/ /_/ / /  /  __/
/_/  /_/\\__,_/_/\\___/\\____/_/   \\___/ 
Malware analysis made simple. v{}({})
\t{}
\tInternet 2.0, Ltd""".format(VERSION, VERSION_STRING, URL)


def log(log_string, level="info"):
    """
    logs information to the screen:
    """
    print("[{}][{}] {}".format(
        time.strftime("%H-%M-%S"), level.upper(), log_string
    ))


def get_api_key():
    """
    gathers the API key from the associated environment variable
    """
    env = os.environ.get('MALCORE_API_KEY')
    if not env:
        log("MALCORE_API_KEY environment variable is not set with associated API key", "error")
    return env


def is_pe(filename):
    """
    simple check to determine if a file is a Windows PE file or not
    """
    with open(filename, "rb") as fh:
        if fh.read(2) == b"MZ":
            return True
    return False


def post_analysis_report(dynamic_results, formatter_class_obj):
    """
    creates a post analysis report that provides information after runtime
    """
    data = dynamic_results["dynamic_analysis"][0]
    total_emulation_runtime = data["emulation_total_runtime"]
    architecture_run_as = data['arch']
    os_run = data["os_run"]
    api_hash_calculated = data['entry_points'][0]['apihash']
    print(
        "POST ANALYSIS REPORT:\n"
        "{}\nTotal runtime: {}\n"
        "Architecture: {}\n"
        "OS run: {}\n"
        "Total suspicious calls: {}\nAPI hash: {}\n".format(
            "*" * 21,
            total_emulation_runtime,
            architecture_run_as,
            os_run,
            formatter_class_obj.total_suspicious_calls,
            api_hash_calculated
        )
    )


def main():
    """
    main function
    """
    print("\n{}\n\n".format(LOGO))
    api_key = get_api_key()
    if api_key is None:
        exit(1)
    results = MalcoreDynamicEmulationPlugin(api_key).run()
    if not len(results) == 0:
        format_ = Formatter(results)
        format_.build_map()
        format_.build_output_table()
        post_analysis_report(results, format_)
    log("emulation performed successfully", "info")


if __name__ == "__main__":
    # call it into a single wrapped function
    main()
