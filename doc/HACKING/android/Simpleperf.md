# Using `simpleperf` to collect CPU profiling on Android

This document describes how you can use Android's `simpleperf`
command-line tool to get CPU profiling information from Tor via the
Orbot application. The tool is particularly useful for Tor development
because it is able to profile native applications on the platform
whereas a lot of the normal tooling for the Android platform is only
able to collect information from Java-based applications.

## Prerequisites

Before using `simpleperf` there is a couple of steps that must be
followed. You should make sure you have both a recent installation of
the Android Software Development Kit (SDK) and Native Development Kit
(NDK) installed. These can be found on the Android Developers website.

1. Follow the build instructions from the `BUILD` file in the Orbot
   repository and build an Orbot APK (Android Package) file with
   debugging enabled. Make sure that when you build the native content of
   the Orbot application that you run the `make -C external` command with
   an additional `DEBUG=1` as parameter to ensure that the Orbot build
   process does not strip the debug symbols from the Tor binary.

2. (Optional) Uninstall and clean-up your old Orbot installation that
   is most likely downloaded from Google's Play Store or via fdroid:

       $ adb shell pm clear org.torproject.android
       $ adb uninstall org.torproject.android

3. Install the Android Package you generated in step 1:

```bash
       $ adb install /path/to/your/app-fullperm-debug.apk
```

4. Check on your device that the newly installed Orbot actually works
   and behaves in the way you expect it to.

## Profiling using `simpleperf`

The `simpleperf` tool can be found in the `simpleperf/` directory in
the directory where you installed the Android NDK to. In this
directory there is a set of Python files that will help you deploy the
tool to a device and collect the measurement data such that you can
analyze the results on your computer rather than on your phone.

1. Change directory to the location of the `simpleperf` directory.
2. Open the `app_profiler.config` file and change
   `app_package_name` to `org.torproject.android`, `apk_file_path` to
   the path of your Orbot Android Package (APK file).
3. Optionally change the duration parameter in the `record_options`
   variable in `app_profiler.config` to the duration which you would like
   to collect samples in. The value is specified in seconds.
4. Run the app profiler using `python app_profiler.py`. This helper
   script will push the `simpleperf` tool to your device, start the
   profiler, and once it has completed copy the generated `perf.data`
   file over to your computer with the results.

### Analyzing the results

You can inspect your resulting `perf.data` file via a simple GUI
program `python report.py` or via the command-line tool `simpleperf
report`. I've found the GUI tool to be easier to navigate around with
than the command-line tool.

The `-g` option can be passed to the command line `simpleperf report`
tool allows you to see the call graph of functions and how much time
was spend on the call.

## Tips & Tricks

- When you have installed Orbot the first time, you will notice that
  if you get a shell on the Android device that there is no Tor binary
  available. This is because Orbot unpacks the Tor binary first time it
  is executed and places it under the `app_bin/` directory on the
  device.

  To access binaries, `torrc` files, and other useful information on
  the device do the following:

```console
      $ adb shell
      (device):/ $ run-as org.torproject.android
      (device):/data/data/org.torproject.android $ ls
      app_bin app_data cache databases files lib shared_prefs
```

  Descriptors, control authentication cookie, state, and other files can be
  found in the `app_data` directory. The `torrc` can be found in the `app_bin/`
  directory.

- You can enable logging in Tor via the syslog (or android) log
  mechanism with:

```console
      $ adb shell
      (device):/ $ run-as org.torproject.android
      (device):/data/data/org.torproject.android $ echo -e "\nLog info syslog" >> app_bin/torrc
```

  Start Tor the normal way via Orbot and collect the logs from your computer using

```console
      $ adb logcat
```
