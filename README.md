# X-CASH

Copyright (c) 2018 X-CASH Project, Derived from 2014-2018, The Monero Project 
Portions Copyright (c) 2012-2013 The Cryptonote developers.

## Development resources

- Web: [x-cash.org](https://x-cash.org)
- Explorer: [explorer.x-cash.org](https://explorer.x-cash.org)
- Official Mining Pool: [minexcash.com](http://minexcash.com)
- Bitcointalk: [Bitcointalk](https://bitcointalk.org/index.php?topic=4781246.0)
- Reddit: [xcash](https://www.reddit.com/r/xcash/)
- Twitter: [XCashCrypto](https://twitter.com/XCashCrypto/)
- Telegram: [xcashglobal](https://t.me/xcashglobal)
- Discord: [x-cash](https://discord.gg/4CAahnd)
- Medium: [x-cash](https://medium.com/x-cash)
- Mail: [accounts@x-cash.org](mailto:accounts@x-cash.org)
- GitHub: [https://github.com/X-CASH-official/X-CASH](https://github.com/X-CASH-official/X-CASH)

## Introduction

X-CASH is a cryptocurrency built using the Cryptonight v8 (CNv2) algorithm, using a variation called CN/DOUBLE, with the aim to become and standard in digital payment and transaction settlement. We believe privacy is very important when it comes to managing personal finances, but at the same time banks and institutions need to know the source of the funds for KYC purposes. Therefore, we plan on leaving the users the choice of whether or not they want their transaction to be public. Because we are implementing a worldwide network of dedicated servers, we hope to make the synchronization of the blockchain faster than other cryptocurrencies as well as reducing transaction latency. We believe this network will be a key component in the deployment of the future improvements we plan on adding to the core code. The main characteristics of X-CASH are detailed below:

-    Total Supply: 100,000,000,000

-    Block Time: 2 minute

-    Algorithm: CN/DOUBLE (Cryptonight v8 (scratchpad of 2MB) with double the iterations, and some minor changes)

-    Reward: ~100,000 XCA at inception

-    Emission structure: logarithmic until max supply is reached in 2022. For more information: https://www.x-cash.org

We developed the FlexPrivacy feature, giving the opportunity to the user to chose between sending their transaction privately or publicly, from the same account, on the same blockchain, and on a per transaction basis. This is the first Cryptonight coin showing this hybrid feature, resembling the current cash system:
- make a transaction using a check, credit card, bank transfer etc… and leave a transaction trail (public transaction)
- pay with cash from person to person, without any outside party witnessing the transaction (private transaction)
Either way, similar to the fiat system, there is no need to have multiple accounts to pay with cash or check. Your account balance, as well as the receiver’s account balance, is never made public.

## License

See [LICENSE](LICENSE).

## Contributing

If you want to help out, see [CONTRIBUTING](CONTRIBUTING.md) for a set of guidelines.

## Scheduled software upgrades

| Software upgrade block height | Date       | Fork version | Details                                                                            |  
| ------------------------------ | -----------| ----------------- | ---------------------------------------------------------------------------------- |
| 0                       | 22-07-2018 | v1                 |  Genesis block       |
| 1                       | 22-07-2018 | v7                 |  Start of the blockchain       |
| 95085                   | 08-10-2018 | v8                 | Changing difficulty algorithm to [LWMA-2 developed by Zawy12](https://github.com/zawy12/difficulty-algorithms/issues/3)       |
| 106000                  | 16-10-2018 | v9                 | Adjusting the new difficulty algorithm       |
| 136000                  | 06-11-2018 | v10                 | Adding public transactions, bullet proofs, fixed ring size of 21 and more!       |
| 137000                  | 07-11-2018 | v11                 | This version makes sure that all non bullet proof transactions are confirmed before bullet proofs transactions are required.       |
| 281000                  | 15-02-2019 | v12                 | This version changes the proof of work algorithm to CN/DOUBLE, and changes the block time to 2 minutes.     |

Note future releases block heights and dates may change, so make sure to frequently check github, our website, the forums, etc. for the most up to date information.

## Compiling X-CASH from source

### Dependencies

The following table summarizes the tools and libraries required to build. A
few of the libraries are also included in this repository (marked as
"Vendored"). By default, the build uses the library installed on the system,
and ignores the vendored sources. However, if no library is found installed on
the system, then the vendored source will be built and used. The vendored
sources are also used for statically-linked builds because distribution
packages often include only shared library binaries (`.so`) but not static
library archives (`.a`).

| Dep          | Min. version  | Vendored | Debian/Ubuntu pkg  | Arch pkg     | Fedora            | Optional | Purpose        |
| ------------ | ------------- | -------- | ------------------ | ------------ | ----------------- | -------- | -------------- |
| GCC          | 4.7.3         | NO       | `build-essential`  | `base-devel` | `gcc`             | NO       |                |
| CMake        | 3.0.0         | NO       | `cmake`            | `cmake`      | `cmake`           | NO       |                |
| pkg-config   | any           | NO       | `pkg-config`       | `base-devel` | `pkgconf`         | NO       |                |
| Boost        | 1.58          | NO       | `libboost-all-dev` | `boost`      | `boost-devel`     | NO       | C++ libraries  |
| OpenSSL      | basically any | NO       | `libssl-dev`       | `openssl`    | `openssl-devel`   | NO       | sha256 sum     |
| libzmq       | 3.0.0         | NO       | `libzmq3-dev`      | `zeromq`     | `cppzmq-devel`    | NO       | ZeroMQ library |
| libunbound   | 1.4.16        | YES      | `libunbound-dev`   | `unbound`    | `unbound-devel`   | NO       | DNS resolver   |
| libsodium    | ?             | NO       | `libsodium-dev`    | ?            | `libsodium-devel` | NO       | libsodium      |
| libminiupnpc | 2.0           | YES      | `libminiupnpc-dev` | `miniupnpc`  | `miniupnpc-devel` | YES      | NAT punching   |
| libunwind    | any           | NO       | `libunwind8-dev`   | `libunwind`  | `libunwind-devel` | YES      | Stack traces   |
| liblzma      | any           | NO       | `liblzma-dev`      | `xz`         | `xz-devel`        | YES      | For libunwind  |
| libreadline  | 6.3.0         | NO       | `libreadline6-dev` | `readline`   | `readline-devel`  | YES      | Input editing  |
| ldns         | 1.6.17        | NO       | `libldns-dev`      | `ldns`       | `ldns-devel`      | YES      | SSL toolkit    |
| expat        | 1.1           | NO       | `libexpat1-dev`    | `expat`      | `expat-devel`     | YES      | XML parsing    |
| GTest        | 1.5           | YES      | `libgtest-dev`^    | `gtest`      | `gtest-devel`     | YES      | Test suite     |
| Doxygen      | any           | NO       | `doxygen`          | `doxygen`    | `doxygen`         | YES      | Documentation  |
| Graphviz     | any           | NO       | `graphviz`         | `graphviz`   | `graphviz`        | YES      | Documentation  |
| pcsclite     | ?             | NO       | `libpcsclite-dev`  | ?            | `pcsc-lite pcsc-lite-devel` | NO | Ledger     |          


[^] On Debian/Ubuntu `libgtest-dev` only includes sources and headers. You must
build the library binary manually. This can be done with the following command ```sudo apt-get install libgtest-dev && cd /usr/src/gtest && sudo cmake . && sudo make && sudo mv libg* /usr/lib/ ```

####Note: If you want to build with unit test (make instead of make release) you need libgtest to be compiled with fPIC
To do this, install libgtest using your package manager
then run the following command to rebuild using fPIC
```cd /usr/src/gtest && sudo sed -i 's/CMAKE_CXX_FLAGS:STRING=/CMAKE_CXX_FLAGS:STRING=-fPIC/g' CMakeCache.txt && sudo sed -i 's/CMAKE_C_FLAGS:STRING=/CMAKE_C_FLAGS:STRING=-fPIC/g' CMakeCache.txt && sudo cmake . && sudo make && sudo mv libg* /usr/lib/```

### Cloning the repository

`$ git clone https://github.com/X-CASH-official/X-CASH`

### Build instructions

X-CASH uses the CMake build system and a top-level [Makefile](Makefile) that
invokes cmake commands as needed.

#### On Linux and OS X

* Install the dependencies
* Change to the root of the source code directory and build:

        cd X-CASH
        make

    *Optional*: If your machine has several cores and enough memory, enable
    parallel build by running `make -j<number of threads>` instead of `make`. For
    this to be worthwhile, the machine should have one core and about 2GB of RAM
    available per thread.

    *Note*: If cmake can not find zmq.hpp file on OS X, installing `zmq.hpp` from
    https://github.com/zeromq/cppzmq to `/usr/local/include` should fix that error.

* The resulting executables can be found in `build/release/bin`

* Add `PATH="$PATH:$HOME/X-CASH/build/release/bin"` to `.profile`

* Run X-CASH with `xcash --detach`

* **Optional**: build and run the test suite to verify the binaries:

        make release-test

    *NOTE*: `core_tests` test may take a few hours to complete.

* **Optional**: to build binaries suitable for debugging:

         make debug

* **Optional**: to build statically-linked binaries:

         make release-static

Dependencies need to be built with -fPIC. Static libraries usually aren't, so you may have to build them yourself with -fPIC. Refer to their documentation for how to build them.

* **Optional**: build documentation in `doc/html` (omit `HAVE_DOT=YES` if `graphviz` is not installed):

        HAVE_DOT=YES doxygen Doxyfile

#### On Windows:

Binaries for Windows are built on Windows using the MinGW toolchain within
[MSYS2 environment](http://msys2.github.io). The MSYS2 environment emulates a
POSIX system. The toolchain runs within the environment and *cross-compiles*
binaries that can run outside of the environment as a regular Windows
application.

**Preparing the build environment**

* Download and install the [MSYS2 installer](http://msys2.github.io), either the 64-bit or the 32-bit package, depending on your system.
* Open the MSYS shell via the `MSYS2 Shell` shortcut
* Update packages using pacman:  

        pacman -Syuu  

* Exit the MSYS shell using Alt+F4  
* Edit the properties for the `MSYS2 Shell` shortcut changing "msys2_shell.bat" to "msys2_shell.cmd -mingw64" for 64-bit builds or "msys2_shell.cmd -mingw32" for 32-bit builds
* Restart MSYS shell via modified shortcut and update packages again using pacman:  

        pacman -Syuu  


* Install dependencies:

    To build for 64-bit Windows:

        pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium

    To build for 32-bit Windows:
 
        pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium

* Open the MingW shell via `MinGW-w64-Win64 Shell` shortcut on 64-bit Windows
  or `MinGW-w64-Win64 Shell` shortcut on 32-bit Windows. Note that if you are
  running 64-bit Windows, you will have both 64-bit and 32-bit MinGW shells.

**Building**

* If you are on a 64-bit system, run:

        make release-static-win64

* If you are on a 32-bit system, run:

        make release-static-win32

* The resulting executables can be found in `build/release/bin`

### Building portable statically linked binaries

By default, in either dynamically or statically linked builds, binaries target the specific host processor on which the build happens and are not portable to other processors. Portable binaries can be built using the following targets:

* ```make release-static-linux-x86_64``` builds binaries on Linux on x86_64 portable across POSIX systems on x86_64 processors
* ```make release-static-linux-i686``` builds binaries on Linux on x86_64 or i686 portable across POSIX systems on i686 processors
* ```make release-static-linux-armv8``` builds binaries on Linux portable across POSIX systems on armv8 processors
* ```make release-static-linux-armv7``` builds binaries on Linux portable across POSIX systems on armv7 processors
* ```make release-static-linux-armv6``` builds binaries on Linux portable across POSIX systems on armv6 processors
* ```make release-static-win64``` builds binaries on 64-bit Windows portable across 64-bit Windows systems
* ```make release-static-win32``` builds binaries on 64-bit or 32-bit Windows portable across 32-bit Windows systems

## Running xcashd

The build places the binary in `bin/` sub-directory within the build directory
from which cmake was invoked (repository root by default). To run in
foreground:

    ./bin/xcashd

To list all available options, run `./bin/xcashd --help`.  Options can be
specified either on the command line or in a configuration file passed by the
`--config-file` argument.  To specify an option in the configuration file, add
a line with the syntax `argumentname=value`, where `argumentname` is the name
of the argument without the leading dashes, for example `log-level=1`.

To run in background:

    ./bin/xcashd --log-file xcashd.log --detach

To run as a systemd service, copy
[xcashd.service](utils/systemd/xcashd.service) to `/etc/systemd/system/` and
[xcashd.conf](utils/conf/xcashd.conf) to `/etc/`. The [example
service](utils/systemd/xcashd.service) assumes that the user `xcash` exists
and its home is the data directory specified in the [example
config](utils/conf/xcashd.conf).

If you're on Mac, you may need to add the `--max-concurrency 1` option to
xcash-wallet-cli, and possibly xcashd, if you get crashes refreshing.
