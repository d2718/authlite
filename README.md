# authlite
A lightweight, non-critical authorization library that stores data in CSV
files.

`authlite` is a simple, lightweight authorization library for small systems
that don't need enterprise-grade security. It will store (and test)
username/password combinations, and also issue (and test) temporary
user-specific "session keys". It stores usernames and hashed passwords, as
well as issued session keys in plain text (`.csv` files).

All access to shared state is protected appropriately by mutices, so the
library is thread-safe, _except_ for the call to `Configure()`. I feel like
this is reasonable; `Configure()` should only be called once at the very
beginning of your program. If you need to reconfigure `authlite` in the
middle of your program, you'll either need to stop all other threads that
use it, or add some mutex dancing to this function yourself.

The code is pretty well commented, and `godoc` produces useful information.
See the `test.conf` file for an example configuration file (and explanation
of the configuration options).
