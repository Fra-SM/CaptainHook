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
    
    //explicit parameter typing breaks the code?
    function getRandomInt(max) {
        return Math.floor(Math.random() * max);
    }

    const programPath = Process.enumerateModules()[0].path;
    const appModules = new ModuleMap(m => m.path.startsWith(programPath));
    const onlyAppCode = true;

    const MessageBoxA = Module.getExportByName('User32.dll', 'MessageBoxA');
    const MessageBoxW = Module.getExportByName('User32.dll', 'MessageBoxW');
    const MessageBoxExA = Module.getExportByName('User32.dll', 'MessageBoxExA');
    const MessageBoxExW = Module.getExportByName('User32.dll', 'MessageBoxExW');
    /* Interceptor.replace(MessageBoxA, new NativeCallback((hWND, lpText, lpCaption, uType) => {send("[Human Interaction] MessageBoxA - " + lpText.readAnsiString());return 0;}, 'int', ['pointer', 'pointer', 'pointer', 'uint']));
    Interceptor.replace(MessageBoxW, new NativeCallback((hWND, lpText, lpCaption, uType) => {send("[Human Interaction] MessageBoxW - " + lpText.readUtf16String());return 0;}, 'int', ['pointer', 'pointer', 'pointer', 'uint']));
    Interceptor.replace(MessageBoxExA, new NativeCallback((hWND, lpText, lpCaption, uType, wLanguageId) => {send("[Human Interaction] MessageBoxExA - " + lpText.readAnsiString());return 0;}, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'uint16']));
    Interceptor.replace(MessageBoxExW, new NativeCallback((hWND, lpText, lpCaption, uType, wLanguageId) => {send("[Human Interaction] MessageBoxExW - " + lpText.readUtf16String());return 0;}, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'uint16'])); */

    /* typedef struct tagPOINT {
        LONG x; offset 0
        LONG y; offset 4
      } POINT, *PPOINT, *NPPOINT, *LPPOINT; */
    //a lot of noise on Enigma
    const GetCursorPos = Module.getExportByName('User32.dll', 'GetCursorPos');
    Interceptor.attach(GetCursorPos, {
      onEnter(args) {
        this.pointx = args[0]; //nativepointer to struct (LONG x)
        this.pointy = this.pointx.add(4); //LONG y NB: LONG is 4 bytes, not 8 like in Frida's docs
      },

      onLeave() {
        if (!appModules.has(this.returnAddress) && onlyAppCode)
            return;
        send("[Human Interaction] GetCursorPos");
        this.pointx.writeInt(getRandomInt(500));
        //console.log(this.pointx.readInt());
        this.pointy.writeInt(getRandomInt(500));
        //console.log(this.pointy.readInt());
      }
    });

    /* typedef struct tagLASTINPUTINFO {
    UINT  cbSize;
    DWORD dwTime;
    } LASTINPUTINFO, *PLASTINPUTINFO; */
    const GetLastInputInfo = Module.getExportByName('User32.dll', 'GetLastInputInfo');
    Interceptor.attach(GetLastInputInfo, {
      onEnter(args) {
        this.lastInputTick = args[0].add(4); //DWORD dwTime
      },

      onLeave() {
        if (!appModules.has(this.returnAddress) && onlyAppCode)
            return;
        send("[Human Interaction] GetLastInputInfo");
        this.lastInputTick.writeUInt(getRandomInt(500));
        //console.log(this.lastInputTick.readInt());
      }
    });

    //can't hook the ret value since it may be used for benign purposes
    const GetForegroundWindow = Module.getExportByName('User32.dll', 'GetForegroundWindow');
    Interceptor.attach(GetForegroundWindow, {
      onEnter() {
        if (!appModules.has(this.returnAddress) && onlyAppCode)
            return;
        send("[Human Interaction] GetForegroundWindow");
      }
      //should return a random handle to avoid evasion, but it may break some program's functionality
    });

    //can't hook the ret value since it may be used for benign purposes
    const GetAsyncKeyState = Module.getExportByName('User32.dll', 'GetAsyncKeyState');
    Interceptor.attach(GetAsyncKeyState, {
      onEnter() {
        if (!appModules.has(this.returnAddress) && onlyAppCode)
            return;
        send("[Human Interaction] GetAsyncKeyState");
      }
    });

    const SetWindowsHookExA = Module.getExportByName('User32.dll', 'SetWindowsHookExA');
    Interceptor.attach(SetWindowsHookExA, {
      onEnter(args) {
        if (!appModules.has(this.returnAddress) && onlyAppCode)
            return;
        let hookId = args[0].toInt32(); //int idHook
        send("[Human Interaction] SetWindowsHookEx");
        if (hookId === 7 || hookId === 14)
            console.log('Mouse events have been hooked');
      }
    });

    const SetWindowsHookExW = Module.getExportByName('User32.dll', 'SetWindowsHookExW');
    Interceptor.attach(SetWindowsHookExW, {
      onEnter(args) {
        if (!appModules.has(this.returnAddress) && onlyAppCode)
            return;
        let hookId = args[0].toInt32(); //int idHook
        send("[Human Interaction] SetWindowsHookEx");
        if (hookId === 7 || hookId === 14)
            console.log('Mouse events have been hooked');
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