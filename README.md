# code
Various projects.
note: Crc32.h is not made by me.

Implemented ideas:

- Threading - 
description: You can create a subclass of the Thread class to run your own code. Support for calling Qt signals/slots is provided.
usage: create a ThreadList and pass it to a subclass of Thread. Override ThreadEntry and call start() to start the thread.

- Virtual File System -
Can be used
not multi-threading safe, make sure to use a mutex to properly manage access.

- Tools - 
various tools for Windows that i've made in my spare time. Some interesting things i've done is retrieving the profile picture(note: Windows 7-: requires admin rights).

- Registry -
Provides a modern C++ api wrapper for registry access on Windows. Supports access to both 32-bit & 64-bit views of the registry.

- Pipe -
provides an ugly anonymous pipe client/server(for access from dlls injected into UWP apps, programs running on guest etc). note: Calling pipe::server::accept will call WaitForSingleObject for 1s.
Very very ugly, will have to improve in the future.

- Crypto - 
Lovely c++ Wincrypt api wrapper.
Supports AES, RSA, etc.

- Memory Writer -
allows you to append data to a vector, can be used for writing settings, etc.

bitflg.hpp:
Provides bit flags, check http://www.cplusplus.com/forum/general/1590/#msg5591

win10.manifest:
embed in Visual Studio 2015 applications, or VS projects using Windows SDK Version < 10. This allows IsWindows10OrGreater() to return true if on Windows 10.
I'm not good on explaining things, you'll probably know what I mean if you call IsWindows10OrGreater() on a Win10 computer using a VS program built w/ Win 8 SDK.

Improvements and suggestions are welcome.