# [Blockchain Commons SLIP-39](https://github.com/BlockchainCommons/bc-slip39)

### _by [Wolf McNally](https://www.github.com/wolfmcnally) and [Christopher Allen](https://www.github.com/ChristopherA) with [Chris Howe](https://www.github.com/howech)_

* <img src="https://github.com/BlockchainCommons/crypto-commons/blob/master/images/logos/crypto-commons-super-simple.png" width=16 valign="bottom">&nbsp;&nbsp; ***part of the [crypto commons](https://github.com/BlockchainCommons/crypto-commons/blob/master/README.md) technology family***

**Implementation of SLIP-39 Shamir Secret Sharing standard for use in [Blockchain Commons](https://www.BlockchainCommons.com) Software Projects**

_This library has been deprecated due to the fact that SLIP-39 does not round trip with BIP-39. For Shamir's Secret Sharing, we have replaced this with the newer [bc-sskr](https://github.com/BlockchainCommons/bc-sskr) library, which has received a full [security review](https://github.com/BlockchainCommons/bc-sskr/blob/master/SECURITY-REVIEW.md) and is ready for production deployment._

## Prerequisites

* If [`bc-crypto-base`](https://github.com/blockchaincommons/bc-crypto-base) is not installed, the `configure` step below will fail.
* If [`bc-shamir`](https://github.com/blockchaincommons/bc-shamir) is not installed, the `configure` step below will fail.

## Installation Instructions

This sequence also runs the module's unit tests.

### MacOS

```bash
$ ./configure
$ make check
$ sudo make install
```

### Linux

Make sure you have llvm/clang.

#### Ubuntu and Debian

```bash
$ sudo apt-get install make

$ wget https://apt.llvm.org/llvm.sh
$ chmod +x llvm.sh
$ sudo ./llvm.sh 10  # version 10
```

```bash
$ export CC="clang-10" && ./configure
$ make check
$ sudo make install
```

## Usage Instructions

1. Link against `libbc-slip39.a`, `libbc-shamir.a` and `libbc-crypto-base.a`.
2. Include the umbrella header in your code:

```c
#include <bc-slip39/bc-slip39.h>
```

## Notes for Maintainers

Before accepting a PR that can affect build or unit tests, make sure the following sequence of commands succeeds:

```bash
$ ./configure
$ make distcheck
$ make distclean
```

`make distcheck` builds a distribution tarball, unpacks it, then configures, builds, and runs unit tests from it, then performs an install and uninstall from a non-system directory and makes sure the uninstall leaves it clean. `make distclean` removes all known byproduct files, and unless you've added files of your own, should leave the directory in a state that could be tarballed for distribution. After a `make distclean` you'll have to run `./configure` again.

## Origin, Authors, Copyright & Licenses

Unless otherwise noted (either in this [/README.md](./README.md) or in the file's header comments) the contents of this repository are Copyright © 2020 by Blockchain Commons, LLC, and are [licensed](./LICENSE) under the [spdx:BSD-2-Clause Plus Patent License](https://spdx.org/licenses/BSD-2-Clause-Patent.html).

In most cases, the authors, copyright, and license for each file reside in header comments in the source code. When it does not we have attempted to attribute it accurately in the table below.

This table below also establishes provenance (repository of origin, permalink, and commit id) for files included from repositories that are outside of this repository. Contributors to these files are listed in the commit history for each repository, first with changes found in the commit history of this repo, then in changes in the commit history of their repo of their origin.

| File      | From                                                         | Commit                                                       | Authors & Copyright (c)                                | License                                                     |
| --------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------ | ----------------------------------------------------------- |
| exception-to-the-rule.c or exception-folder | [https://github.com/community/repo-name/PERMALINK](https://github.com/community/repo-name/PERMALINK) | [https://github.com/community/repo-name/commit/COMMITHASH]() | 2020 Exception Author  | [MIT](https://spdx.org/licenses/MIT)                        |

### Used with…

These are other projects that work with or leverage `$projectname`:

- [community/repo-name/](https://github.com/community/repo-name) — Repo that does what, by [developer](https://github.com/developer)  or from  [community](https://community.com).

### Derived from…

This  `$projectname` project is either derived from or was inspired by:

- [community/repo-name/](https://github.com/community/repo-name) — Repo that does what, by [developer](https://github.com/developer)  or from  [community](https://community.com).

### Dependencies

To build the  `$projectname` you'll need to use the following tools:

- autotools - Gnu Build System from Free Software Foundation ([intro](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)).

### Known Issues

#### ⚠️ Warning: Lack of Round-trip Compatibility between BIP-39 and SLIP-39

At first glance, BIP-39 and SLIP-39 both appear to be means of converting a binary seed to a set of backup words and back. You might assume you could simply convert a BIP-39 backup to a binary seed, from that binary seed to SLIP-39, and then use the SLIP-39 backup to recover the same wallet as the original BIP-39 backup, but this is **NOT** the case. This is because the SLIP-39 algorithm that SatoshiLabs uses in their Trezor wallet does not derive the master secret in the same way as their BIP-39 algorithm does.

Currently Blockchain Commons is investigating an alternative to SLIP-39 that allows round-trips with BIP-39. We want to ensure that the same seed will result in the same derived keys using either BIP-39 or our alternative approach.

As SLIP-39 is not round-trip compatible with BIP-39, and SLIP-39 is under the control of SatoshiLabs and does not appear to be a fully community-controlled standard, Blockchain Commons is no longer endorsing SLIP-39.

* This issue is being tracked [here](https://github.com/BlockchainCommons/bc-lethekit/issues/38).

## Financial Support

*Blockchain Commons SLIP-39* is a project of [Blockchain Commons](https://www.blockchaincommons.com/). We are proudly a "not-for-profit" social benefit corporation committed to open source & open development. Our work is funded entirely by donations and collaborative partnerships with people like you. Every contribution will be spent on building open tools, technologies, and techniques that sustain and advance blockchain and internet security infrastructure and promote an open web.

To financially support further development of *Blockchain Commons SLIP-39* and other projects, please consider becoming a Patron of Blockchain Commons through ongoing monthly patronage as a [GitHub Sponsor](https://github.com/sponsors/BlockchainCommons). You can also support Blockchain Commons with bitcoins at our [BTCPay Server](https://btcpay.blockchaincommons.com/).

## Contributing

We encourage public contributions through issues and pull-requests! Please review [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our development process. All contributions to this repository require a GPG signed [Contributor License Agreement](./CLA.md).

### Discussions

The best place to talk about Blockchain Commons and its projects is in our GitHub Discussions areas.

[**Wallet Standard Discussions**](https://github.com/BlockchainCommons/AirgappedSigning/discussions). For standards and open-source developers who want to talk about wallet standards, please use the Discussions area of the [Airgapped Signing repo](https://github.com/BlockchainCommons/AirgappedSigning). This is where you can talk about projects like our [LetheKit](https://github.com/BlockchainCommons/bc-lethekit) and command line tools such as [seedtool](https://github.com/BlockchainCommons/bc-seedtool-cli), both of which are intended to testbed wallet technologies, plus the libraries that we've built to support your own deployment of wallet technology such as [bc-bip39](https://github.com/BlockchainCommons/bc-bip39), [bc-slip39](https://github.com/BlockchainCommons/bc-slip39), [bc-shamir](https://github.com/BlockchainCommons/bc-shamir), [Shamir Secret Key Recovery](https://github.com/BlockchainCommons/bc-sskr), [bc-ur](https://github.com/BlockchainCommons/bc-ur), and the [bc-crypto-base](https://github.com/BlockchainCommons/bc-crypto-base). If it's a wallet-focused technology or a more general discussion of wallet standards,discuss it here.

[**Blockchain Commons Discussions**](https://github.com/BlockchainCommons/Community/discussions). For developers, interns, and patrons of Blockchain Commons, please use the discussions area of the [Community repo](https://github.com/BlockchainCommons/Community) to talk about general Blockchain Commons issues, the intern program, or topics other than the [Gordian System](https://github.com/BlockchainCommons/Gordian/discussions) or the [wallet standards](https://github.com/BlockchainCommons/AirgappedSigning/discussions), each of which have their own discussion areas.

### Other Questions & Problems

As an open-source, open-development community, Blockchain Commons does not have the resources to provide direct support of our projects. Please consider the discussions area as a locale where you might get answers to questions. Alternatively, please use this repository's [issues](./issues) feature. Unfortunately, we can not make any promises on response time.

If your company requires support to use our projects, please feel free to contact us directly about options. We may be able to offer you a contract for support from one of our contributors, or we might be able to point you to another entity who can offer the contractual support that you need.


### Credits

The following people directly contributed to this repository. You can add your name here by getting involved — the first step is to learn how to contribute from our [CONTRIBUTING.md](./CONTRIBUTING.md) documentation.

| Name              | Role                | Github                                            | Email                                 | GPG Fingerprint                                    |
| ----------------- | ------------------- | ------------------------------------------------- | ------------------------------------- | -------------------------------------------------- |
| Christopher Allen | Principal Architect | [@ChristopherA](https://github.com/ChristopherA) | \<ChristopherA@LifeWithAlacrity.com\> | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |
| Wolf McNally      | Project Lead        | [@WolfMcNally](https://github.com/wolfmcnally)    | \<Wolf@WolfMcNally.com\>              | 9436 52EE 3844 1760 C3DC  3536 4B6C 2FCF 8947 80AE |
| Chris Howe     | Occasional Contributor | [@howech](https://github.com/howech)               | \<chris@howeville.com\>               | 7C3D D38E 16D0 0275 5C0B  82B4 709C 6DA6 EAD3 99A7 |

## Responsible Disclosure

We want to keep all our software safe for everyone. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner. We are unfortunately not able to offer bug bounties at this time.

We do ask that you offer us good faith and use best efforts not to leak information or harm any user, their data, or our developer community. Please give us a reasonable amount of time to fix the issue before you publish it. Do not defraud our users or us in the process of discovery. We promise not to bring legal action against researchers who point out a problem provided they do their best to follow the these guidelines.

### Reporting a Vulnerability

Please report suspected security vulnerabilities in private via email to ChristopherA@BlockchainCommons.com (do not use this email for support). Please do NOT create publicly viewable issues for suspected security vulnerabilities.

The following keys may be used to communicate sensitive information to developers:

| Name              | Fingerprint                                        |
| ----------------- | -------------------------------------------------- |
| Christopher Allen | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |

You can import a key by running the following command with that individual’s fingerprint: `gpg --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints that contain spaces.
