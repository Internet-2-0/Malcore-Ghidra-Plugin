# Malcore Dynamic Emulation Ghidra Plugin

This plugin allows you to run dynamic emulation using the Malcore API. It provides an emulation of the program run in a Windows environment and allows you to understand how the program runs dynamically without the need for a sandbox.

![Run](https://user-images.githubusercontent.com/14183473/204192515-fbfd29c2-d53b-43f7-94a9-f27f959c9d72.gif)

### Dependencies

#### Libraries

This plugin attempts to incorporate your installed version of Python and its site-packages into Ghidras environment automatically. However, if this does not work installation steps are below:

This plugin requires the requests library version 2.27.1. You can install this library by running:

```
pip2 install --user requests==2.27.1
```

If you do not have `pip` installed for Python 2.x you can get pip from the following script: https://bootstrap.pypa.io/pip/2.7/get-pip.py

#### API Key

In order to run this plugin you need a Malcore API key, you can get one from https://malcore.io. The API key will need to be set inside an environment variable called `MALCORE_API_KEY`

### Installation

This plugin was tested from Ghidra version 9.2.3 - 10.1.4

To install the plugin you will need to do the following:

1. Clone the repository into a path of your desire
2. From inside the CodeBrowser click Window > Bundle Manager as seen below:

![installation_step_1](https://user-images.githubusercontent.com/14183473/204193086-689c6c0a-dbbe-42f6-abe4-908e8f5daa0d.jpg)

3. From inside the bundle manager click the green `+` and navigate to the location you cloned this repository to as seen below:

![installation_step_2](https://user-images.githubusercontent.com/14183473/204194399-7fe159b5-9f41-41df-bbc8-3ce7134e269a.jpg)

4. Make sure that your path is checked and close the bundle manager window
5. Now go to the script manager

![installation_step_3](https://user-images.githubusercontent.com/14183473/204193660-b2f76114-ecda-4ef8-9b5b-5dc3f3090c72.jpg)

6. Search for Malcore and check the "In Tool" box to activate the toolbar button and the Shift-M keybinding

![installation_step_4](https://user-images.githubusercontent.com/14183473/204193855-68bd016b-dbec-4f59-8c4a-752b50b0302d.jpg)

After this the plugin should be installed and able to be run.