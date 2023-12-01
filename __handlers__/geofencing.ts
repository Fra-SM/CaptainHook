/*
 * Auto-generated by Frida. Please modify to match the signature of printf.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

{
    /**
     * Called synchronously when about to call printf.
     *
     * @this {object} - Object allowing you to store state for use in onLeave.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {array} args - Function arguments represented as an array of NativePointer objects.
     * For example use args[0].readCString() if the first argument is a pointer to a C string encoded as UTF-8.
     * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
     * @param {object} state - Object allowing you to keep state across function calls.
     * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
     * However, do not use this to store function arguments across onEnter/onLeave, but instead
     * use "this" which is an object for keeping state local to an invocation.
     */

    const programPath = Process.enumerateModules()[0].path;
    const appModules = new ModuleMap(m => m.path.startsWith(programPath));

    const GetSystemDefaultLangID = Module.getExportByName("Kernel32.dll", 'GetSystemDefaultLangID');
    Interceptor.attach(GetSystemDefaultLangID, {
      onLeave(retval) {
        if (!appModules.has(this.returnAddress))
            return;
        retval.replace(ptr(1033)); //EN-US LANGID
        send("[Geofencing] GetSystemDefaultLangID");
      }
    });

    const GetUserDefaultLangID = Module.getExportByName("Kernel32.dll", 'GetUserDefaultLangID');
    Interceptor.attach(GetUserDefaultLangID, {
      onLeave(retval) {
        if (!appModules.has(this.returnAddress))
            return;
        retval.replace(ptr(1033)); //EN-US LANGID
        send("[Geofencing] GetUserDefaultLangID");
      }
    });

    const GetSystemDefaultUILanguage = Module.getExportByName("Kernel32.dll", 'GetSystemDefaultUILanguage');
    Interceptor.attach(GetSystemDefaultUILanguage, {
      onLeave(retval) {
        if (!appModules.has(this.returnAddress))
            return;
        retval.replace(ptr(1033)); //EN-US LANGID
        send("[Geofencing] GetSystemDefaultUILanguage");
      }
    });

    const GetUserDefaultUILanguage = Module.getExportByName("Kernel32.dll", 'GetUserDefaultUILanguage');
    Interceptor.attach(GetUserDefaultUILanguage, {
      onLeave(retval) {
        if (!appModules.has(this.returnAddress))
            return;
        retval.replace(ptr(1033)); //EN-US LANGID
        send("[Geofencing] GetUserDefaultUILanguage");
      }
    });

    const GetUserGeoID = Module.getExportByName('Kernel32.dll', 'GetUserGeoID');
    Interceptor.attach(GetUserGeoID, {
      onEnter(args) {
        this.geoClass = args[0].toUInt32(); //DWORD GEOCLASS (nation=16, region= 14)
      },

      onLeave(retval) {
        if (!appModules.has(this.returnAddress))
          return;
        send("[Geofencing] GetUserGeoID");
        if (this.geoClass === 16)
          retval.replace(ptr(244)); //US geoid
        if (this.geoClass === 14)
          retval.replace(ptr(39070)); //World geoid
      }
    });

    const GetKeyboardLayout = Module.getExportByName('User32.dll', 'GetKeyboardLayout');
    Interceptor.attach(GetKeyboardLayout, {
      onLeave(retval) {
        if (!appModules.has(this.returnAddress))
          return;
        send("[Geofencing] GetKeyboardLayout");
        retval.replace(ptr(0x00000409)); //EN-US LANGID
      }
    });

    const GetKeyboardLayoutList = Module.getExportByName('User32.dll', 'GetKeyboardLayoutList');
    Interceptor.attach(GetKeyboardLayoutList, {
      onEnter(args) {
        this.layouts = args[1]; //HKL* lpList
      },
      onLeave() {
        if (!appModules.has(this.returnAddress))
          return;
        send("[Geofencing] GetKeyboardLayoutList");
        this.layouts.writePointer(ptr(0x00000409)); //EN-US LANGID
      }
    });

    const GetLocaleInfoA = Module.getExportByName('Kernel32.dll', 'GetLocaleInfoA');
    Interceptor.attach(GetLocaleInfoA, {
      onEnter() {
        if (!appModules.has(this.returnAddress))
            return;
        send("[Geofencing] GetLocaleInfoA");
      }
    });

    const GetLocaleInfoW = Module.getExportByName('Kernel32.dll', 'GetLocaleInfoW');
    Interceptor.attach(GetLocaleInfoW, {
      onEnter() {
        if (!appModules.has(this.returnAddress))
            return;
        send("[Geofencing] GetLocaleInfoW");
      }
    });

    const GetLocaleInfoEx = Module.getExportByName('Kernel32.dll', 'GetLocaleInfoEx');
    Interceptor.attach(GetLocaleInfoEx, {
      onEnter() {
        if (!appModules.has(this.returnAddress))
            return;
        send("[Geofencing] GetLocaleInfoEx");
      }
    });

    /**
     * Called synchronously when about to return from printf.
     *
     * See onEnter for details.
     *
     * @this {object} - Object allowing you to access state stored in onEnter.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {NativePointer} retval - Return value represented as a NativePointer object.
     * @param {object} state - Object allowing you to keep state across function calls.
     */
  }