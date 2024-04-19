# CaptainHook

A tool that makes use of [Frida](https://frida.re/) API hooking and code tracing functionalities to try to detect and in most cases bypass many of the evasive techniques, such as Anti-VM or Anti-Debugging techniques, commonly used by Windows malware or software protectors. This tool was developed as part of my Master's Thesis project with the aim of studying the usage of evasive techniques among commercial packers/protectors.

:warning: **Warning**: *The tool will execute any program you will feed it without notice. I take no responsibilities for any damage it may cause.*

## Installation

Run the following command from the installation directory:

```sh
pip install -r requirements.txt
```

### Usage

Run `python3 captainhook.py -h` for help.

#### Development

To extend the tool, simply create a new file or edit any file under the `__handlers__` directory and add your hooks there (or change the existing ones if you prefer). You should also install [Frida Node.js bindings](https://github.com/frida/frida-node) to benefit from syntax highlighting on editors like VS Code.
