<div align=middle>

<a align="center" href="https://x-network.io/xcash"><img src="header.png" alt="X-Cash Core"></a>

[![Release](https://img.shields.io/github/v/release/X-CASH-official/xcash-core)](https://github.com/X-CASH-official/X-CASH/releases)
[![Gitter](https://badges.gitter.im/xcash-foundation/xcash-core.svg)](https://gitter.im/xcash-foundation/xcash-core?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![chat](https://img.shields.io/discord/470575102203920395?logo=discord)](https://discordapp.com/invite/4CAahnd)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](https://opensource.org/licenses/MIT)

</div>

# X-Cash Core Blockchain

⛓ [**X-CASH**](https://x-network.io/xcash) is a ***community driven*** and ***open-source project*** developing the new standard of digital payment. Unique blockchain network with ***public and private transactions***, custom ***DPOS consensus***, and soon ***sidechains***.

> ⚠ We are switching from CryptoNight PoW consensus algorithm to our own Delegated-Proof-of-Private-Stake (DPOPS) !</br>
> 👉 Follow the development on the [`xcash-dpops`](https://github.com/X-CASH-official/xcash-dpops) repository.

## Table of Content 

  - [Table of Content](#table-of-content)
  - [Features](#features)
  - [License](#license)
  - [Contributing](#contributing)
  - [Documentation](#documentation)
  - [Security](#security)
  - [Installation](#installation)
  - [Important Links](#important-links)

## Features

Based and improved upon the renowned [CryptoNote](https://github.com/cryptonotefoundation/cryptonote) protocol, **X-Cash** aims at becoming the standard in digital payment and transaction settlement:

### **FlexPrivacy** 
**X-Cash** proposes the flexibility to send a transaction **privately or publicly**, directly from your wallet by toggling a simple switch, **without compromising your privacy.** 

> *Have a look at our* 📜 *[Hybrid Transactions'](https://x-network.io/whitepaper/XCASH_Yellowpaper_Hybrid-tx.pdf) yellow paper to learn more about the technology behind it.*

### **Delegated Proof of Private Stake (DPOPS)**  
To tackle scalability and future upgrades while reducing the energy comsuption of the network, we are developing a customized and unique DPOS consensus that **can be implemented in any privacy coin**.  

> *Interested ? Read more about our* 📜 *[Delegated Proof-of-Private-Stake](https://x-network.io/whitepaper/XCASH_Yellowpaper_DPoPS.pdf) yellow paper to learn more about the technical challenge of integrating this consensus on a Monero-based privacy coin.*

### **Sidechains**  
Delegates will be able to host **sidechains** on the X-Cash network, providing an **easy, secured, economical and customizable blockchain** solution to match your project needs.


## License

**X-Cash is an open-source project managed by the X-Cash Foundation**.  
We are operating under the [MIT License](LICENSE).

## Contributing

**Thank you for thinking of contributing! 😃**   
If you want to help out, check [CONTRIBUTING](https://github.com/X-CASH-official/.github/blob/master/CONTRIBUTING.md) for a set of guidelines and check our [opened issues](https://github.com/X-CASH-official/xcash-core/issues).

## Documentation

We are hosting our documentation on **GitBook** 👉 [**docs.xcash.foundation**](https://docs.xcash.foundation/)

> You can contribute directly on our [`gitbook-docs`](https://github.com/X-CASH-official/gitbook-docs) repository.

## Security 

If you discover a security vulnerability, please send an e-mail to [security@xcash.foundation](mailto:security@xcash.foundation).  
All security vulnerabilities concerning the X-Cash blockchain will be promply addressed.

## Installation

### Dependencies

The following table summarizes the tools and libraries required to build.  
A few of the libraries are also included in this repository (marked as "Vendored").  

> By default, the build uses the library installed on the system, and ignores the vendored sources. However, if no library is found installed on the system, then the vendored source will be built and used. The vendored sources are also used for statically-linked builds because distribution packages often include only shared library binaries (`.so`) but not static library archives (`.a`).

If you need to build statically linked linux binaries, please refer to [Build Statically Linked Linux Binaries guide](#build-statically-linked-linux-binaries) before you install any packages

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


**^** On Debian/Ubuntu, `libgtest-dev` only includes sources and headers. You must
build the library binary manually. This can be done with the following command:

```shell
sudo apt-get install libgtest-dev && cd /usr/src/gtest && sudo cmake . && sudo make && sudo mv libg* /usr/lib/
```

> **Note:** If you want to build with unit test (`make` instead of `make release`) you need `libgtest` to be compiled with fPIC. To do this, install libgtest using your package manager then run the following command to rebuild using fPIC:

```shell
cd /usr/src/gtest && sudo sed -i 's/CMAKE_CXX_FLAGS:STRING=/CMAKE_CXX_FLAGS:STRING=-fPIC/g' CMakeCache.txt && sudo sed -i 's/CMAKE_C_FLAGS:STRING=/CMAKE_C_FLAGS:STRING=-fPIC/g' CMakeCache.txt && sudo cmake . && sudo make && sudo mv libg* /usr/lib/
```

### Cloning the repository

```shell
$ git clone https://github.com/X-CASH-official/xcash-core
```

### Build instructions

**X-CASH** uses the CMake build system and a top-level [makefile](Makefile) that
invokes cmake commands as needed.

#### Linux and OS X

* Install the [dependencies](#dependencies)
* Change to the root of the source code directory and build:
  
```shell
cd X-CASH
make
```

> *Optional*: If your machine has several cores and enough memory, enable parallel build by running `make -j<number of threads>` instead of `make`.  
*For this to be worthwhile, the machine should have one core and about 2GB of RAM available per thread.*

> *Note*: If `cmake` can not find `zmq.hpp` file on OS X, installing `zmq.hpp` from https://github.com/zeromq/cppzmq to `/usr/local/include` should fix that error.

* The resulting executables can be found in `build/release/bin`

* Add `PATH="$PATH:$HOME/X-CASH/build/release/bin"` to `.profile`

* Run X-CASH with `xcash --detach`

* *(optional)* Build and run the test suite to verify the binaries:
```shell
make release-test
```

> *Note*: `core_tests` test may take a few hours to complete.

* *(optional)* To build binaries suitable for debugging:
```shell
make debug
```

* *(optional)* To build statically-linked binaries:
```shell
make release-static
```

> Dependencies need to be built with `-fPIC`. Static libraries usually aren't, so you may have to build them yourself with `-fPIC`.  
> Refer to their documentation for how to build them, as well as refer to the [Build Statically Linked Linux Binaries guide](#build-statically-linked-linux-binaries)


#### Build Statically Linked Linux Binaries

> **Note**: this guide is only for Ubuntu

- Only install the following packages from the package manager if you want to build statically linked linux binaries:
```shell
sudo apt update
sudo apt install -y build-essential cmake pkg-config libunbound-dev libsodium-dev libldns-dev libexpat1-dev doxygen graphviz
sudo apt-get -y install libgtest-dev && cd /usr/src/gtest && sudo cmake . && sudo make && sudo mv libg* /usr/lib/
```

- You will also need to install these additional packages
```shell
sudo apt install -y libsystemd-dev libudev-dev libtool-bin autoconf
```

- Download and extract the latest version of [Boost](https://www.boost.org/users/download/), [OpenSSL 1.1](https://www.openssl.org/source/), [PCSC-lite](https://pcsclite.apdu.fr/files/) and [libzmq](https://github.com/zeromq/libzmq/releases)

- Create build directories for `boost`, `openssl` and `pcsclite`. The reason these are not installed in the system directory is so you can keep your systems install, and have these at the same time. You can create these folders wherever and name them whatever.
```shell
mkdir BOOST_BUILD_DIR
mkdir OPENSSL_BUILD_DIR
mkdir PCSC_LITE_BUILD_DIR
```

- Install them:

- - `boost`
```shell
cd BOOST_DIRECTORY
./bootstrap.sh --prefix=BOOST_BUILD_DIR
sudo ./b2 cxxflags=-fPIC cflags=-fPIC -a install -j `nproc`
```

- - `openssl`
```shell
cd OPENSSL_DIRECTORY
./config -fPIC --prefix=OPENSSL_BUILD_DIR --openssldir=OPENSSL_BUILD_DIR
make depend
make -j `nproc`
sudo make install
```

- - `pcsc-lite`
```shell
cd PCSC-LITE_DIRECTORY
./configure CPPFLAGS=-DPIC CFLAGS=-fPIC CXXFLAGS=-fPIC LDFLAGS=-fPIC --enable-static --prefix=PCSC_LITE_BUILD_DIR
make -j `nproc`
sudo make install
```

- - `libzmq`
```shell
cd LIBZMQ_DIRECTORY
/autogen.sh
./configure CPPFLAGS=-DPIC CFLAGS=-fPIC CXXFLAGS=-fPIC LDFLAGS=-fPIC
make -j `nproc`
sudo make install
sudo ldconfig
cd /usr/local/include/
wget -q https://raw.githubusercontent.com/zeromq/cppzmq/master/zmq.hpp
```

- Now you can build the binaries statically using the following commands
```shell
cd X-CASH
rm -r build
mkdir -p build/release
cd build/release
cmake -D STATIC=ON -D ARCH="x86-64" -D BUILD_64=ON -D BUILD_TESTS=ON -D BOOST_ROOT=BOOST_BUILD_DIR -D OPENSSL_ROOT_DIR=OPENSSL_BUILD_DIR -D USE_READLINE=OFF -D CMAKE_BUILD_TYPE=release ../..
cd ../../
make -IBOOST_BUILD_DIR/include -IOPENSSL_BUILD_DIR/include -IPCSC_LITE_BUILD_DIR/include LDFLAGS="-LBOOST_BUILD_DIR/lib -LOPENSSL_BUILD_DIR/lib -LPCSC_LITE_BUILD_DIR/lib" -j `nproc`
```


#### Windows

Binaries are built on Windows using the MinGW toolchain within [MSYS2 environment](http://msys2.github.io). The MSYS2 environment emulates a POSIX system. The toolchain runs within the environment and *cross-compiles* binaries that can run outside of the environment as a regular Windows
application.

##### Preparing the build environment

* Download and install the [MSYS2 installer](http://msys2.github.io), either the 64-bit or the 32-bit package, depending on your system.
  
* Open the MSYS shell via the `MSYS2 Shell` shortcut.
  
* Update packages using pacman:  
```shell
pacman -Syuu
``` 

* Exit the MSYS shell using Alt+F4  
  
* Edit the properties for the `MSYS2 Shell` shortcut changing "`msys2_shell.bat`" to "`msys2_shell.cmd -mingw64`" for 64-bit builds or "`msys2_shell.cmd -mingw32`" for 32-bit builds
  
* Restart MSYS shell via modified shortcut and update packages again using pacman:  
```shell
pacman -Syuu
```

* Install dependencies:

- - Build for 64-bit Windows:
```shell
pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium
```

- - Build for 32-bit Windows:
```shell
pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium
```

* Open the MingW shell via `MinGW-w64-Win64 Shell` shortcut on 64-bit Windows
  or `MinGW-w64-Win64 Shell` shortcut on 32-bit Windows.  
> *Note*: If you are running 64-bit Windows, you will have both 64-bit and 32-bit MinGW shells.

##### Building

* For 64-bit system, run:
```shell
make release-static-win64
```

* For 32-bit system, run:
```shell
make release-static-win32
```

* The resulting executables can be found in `build/release/bin`

### Building portable binaries

> By default, in either dynamically or statically linked builds, binaries target the specific host processor on which the build happens and are not portable to other processors.
 
<summary> Build commands: </summary>

```bash
# Build binaries on Linux on x86_64 portable across POSIX systems on x86_64 processors
make release-static-linux-x86_64

# Builds binaries on Linux on x86_64 or i686 portable across POSIX systems on i686 processors
make release-static-linux-i686

# Builds binaries on Linux portable across POSIX systems on armv8 processors
make release-static-linux-armv8

# Builds binaries on Linux portable across POSIX systems on armv7 processors
make release-static-linux-armv7

# Builds binaries on Linux portable across POSIX systems on armv6 processors
make release-static-linux-armv6

# Builds binaries on 64-bit Windows portable across 64-bit Windows systems
make release-static-win64

# Builds binaries on 64-bit or 32-bit Windows portable across 32-bit Windows systems
make release-static-win32
```

</details>

### Running `xcashd` daemon

The build places the binary in `bin/` sub-directory within the build directory
from which `cmake` was invoked (*repository root by default*). To run in
foreground:
```shell
./bin/xcashd
```

To list all available options, run: 
```shell
./bin/xcashd --help
```

Options can be
specified either on the command line or in a configuration file passed by the
`--config-file` argument.  To specify an option in the configuration file, add
a line with the syntax `argumentname=value`, where `argumentname` is the name
of the argument without the leading dashes, for example `log-level=1`.

To run in background:
```shell
./bin/xcashd --log-file xcashd.log --detach
```

To run as a ```systemd``` service, copy
[xcashd.service](utils/systemd/xcashd.service) to `/etc/systemd/system/` and
[xcashd.conf](utils/conf/xcashd.conf) to `/etc/`. The [example
service](utils/systemd/xcashd.service) assumes that the user `xcash` exists
and its home is the data directory specified in the [example
config](utils/conf/xcashd.conf).

> If you're on Mac, you may need to add the `--max-concurrency 1` option to `xcash-wallet-cli`, and possibly `xcashd`, if you get crashes refreshing.

## Important Links

### 🔗 MAIN LINKS
- **X-Network**: [x-network.io](https://x-network.io/)
- **X-Cash**: [x-network.io/xcash](https://x-network.io/xcash)
- **Block explorer**: [explorer.x-cash.org](https://explorer.x-cash.org/Explorer)
- **Medium**: [medium.com/x-cash](https://medium.com/x-cash)
- **Help Center**: [Help Portal](https://xcashteam.atlassian.net/servicedesk/)
- **Mining**: [/xcash/mining/](https://x-network.io/xcash/mining/)

### 👛 WALLET
- **Download**: [Official Download Page](https://x-network.io/xcash/downloads/)  
- **Paper wallet**: [X-Cash Paper Wallet Generator](https://x-network.io/xcash/paper-wallet-generator/)  
- **Online wallet**: [X-Bank](https://x-bank.io)

### 💱 SUPPORTED EXCHANGES
- **STEX**: [STEX.com](https://www.stex.com/)  
- **GRAVIEX**: [graviex.net](https://graviex.net/)  
- **CITEX**: [citex.co.kr](https://www.citex.co.kr/)  

### 🌍 COMMUNITY
- **Twitter**: [@xcashcrypto](https://twitter.com/XCashCrypto)  
- **Discord**: [discord.gg/4CAahnd](https://discord.gg/4CAahnd)  
- **BitcoinTalk**: [bitcointalk.org/index.php?topic=4781246](https://bitcointalk.org/index.php?topic=4781246)  
- **Reddit**: [r/xcash/](https://www.reddit.com/r/xcash)  
- **Telegram**: [t.me/xcashglobal](https://t.me/xcashglobal)