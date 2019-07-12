Aphory Core integration/staging tree
=====================================

https://aphory.io

What is Aphory?
----------------

An open source, decentralized privacy platform
built for global person to person eCommerce and affiliate marketing.

For more information, as well as an immediately useable, binary version of
the Aphory Core software, see https://aphory.io.


Getting Started
---------------

A new Aphory wallet will need an HD master key loaded and an initial account
derived before it will be functional.

The GUI programs will guide you through the initial setup.

It is recommended to use a mnemonic passphrase.
To generate a new passphrase see the mnemonic rpc command.
Loading the new mnemonic with the extkeyimportmaster command will setup the
master HD key and first account.

To create an initial new HD master key and account from random data, start
aphoryd or aphory-qt with the parameter: -createdefaultmasterkey.

Remember to backup your passphrase and/or wallet.dat file!

License
-------

Aphory Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/aphory/aphory-core/tags) are created
regularly to indicate new official, stable release versions of Aphory Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

