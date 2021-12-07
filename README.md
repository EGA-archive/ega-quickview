# EGA-QuickView

EGA-QuickView is a FUSE file system to access EGA files remotely. It
works on Linux and macOS 12.  (macOS 11 has
[bugs](https://github.com/osxfuse/osxfuse/issues/779#issuecomment-772890544),
and on M1, [it seems you need to run in "reduced security mode",
otherwise third-party kernel extensions cannot be
loaded](https://github.com/osxfuse/osxfuse/issues/779#issuecomment-801761709)).

From the [libfuse description](https://github.com/libfuse/libfuse/blob/master/README.md):

> FUSE (Filesystem in Userspace) is an interface for userspace
> programs to export a filesystem to the Linux kernel. The FUSE
> project consists of two components: the fuse kernel module
> (maintained in the regular kernel repositories) and the libfuse
> userspace library (maintained in [this repository](https://github.com/libfuse/libfuse)). libfuse provides
> the reference implementation for communicating with the FUSE kernel
> module.

EGA-QuickView is a combination of sshfs and crypt4ghfs. That is, we
communicate with the EGA distribution servers over ssh, download files
(chunk by chunk) in Crypt4GH format and decrypt them transparently.

It is useful for a user to quickly browse through a file, without
downloading it entirely before being able to open it. It looses its
purpose if the user plans on scanning the entire file. For that
latter, it is more appropriate to download the files using the Aspera
solution, and decrypt the files locally with [Crypt4GH](https://crypt4gh.readthedocs.io).

## Installation

We need a few required packages (gcc, make, libsodium, libfuse, autoconf...)

	apt install autoconf gcc make git meson pkg-config xutils-dev libssl-dev libsodium-dev libglib2.0-dev

To install [libfuse (version 3.10.5)](https://github.com/libfuse/libfuse):

	git clone --branch fuse-3.10.5 https://github.com/libfuse/libfuse.git /var/src/libfuse
	mkdir /var/src/libfuse/build
	pushd /var/src/libfuse/build
	meson ..
	#python3 -m pytest test/ # optional
	ninja install
	popd
	ldconfig -v | grep libfuse3

If the ldconfig command doesn't print the name `libfuse3.so`, you probably need to update a file in `/etc/ld.so.conf.d/` with the path to where the library was install (for example: in `/usr/local/lib64`).


> Note: [Security implications for fusermount3](https://github.com/libfuse/libfuse/tree/fuse-3.10.5#security-implications)


We then need to handle the Crypt4GH keys. The code for them is externalized in libc4gh-keys, or available in the submodule [./keys](./keys)

	pushd ./keys
	autoreconf
	./configure    # you might need to adjust the location of OpenSSL with --with-openssl=<path>
	make
	make install   # optional. We'll find the library in this directory if you don't install it
	popd

Finally, you can compile the EGA-qv code with:

	autoreconf
	./configure
	make
	make install

On macOS, if you can't find Openssl, please use pkg-config and adjust the `PKG_CONFIG_PATH` like:

	export PKG_CONFIG_PATH="$(brew --prefix openssl@1.1)/lib/pkgconfig:$PKG_CONFIG_PATH"

## Example

EGA-QuickView works over SSH and uses Crypt4GH. It therefore needs a Crypt4GH-compatible key.
2 arguments are required: the location of the EGA server and a mountpoint.
Credentials to connect to the EGA server can be passed similarly to a classic SSH connection.
The Crypt4GH key must be passed as a `-o` argument, in the options list.

	ega-qv [options] <EGA-server> <mountpoint>
	
For example, the user silverdaz can connect (if it is an EGA user), using:

	ega-qv -o seckey=~/.ssh/c4gh.key silverdaz@outbox.ega-archive.org ~/EGA
	
You will get prompted for the Crypt4GH passphrase

## Todo


- [ ] Compile for MacOS
- [ ] Create documentation on ReadTheDocs
- [ ] Handle the SSH/Crypt4GH keys internally or externally?
- [ ] Remove the passphrase prompt if the key is not locked (Not recommended).
