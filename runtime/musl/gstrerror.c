/* gstrerror.c -- musl's strerror() message table.
 *
 * `%m` in a format string prints strerror(errno), and musl's messages are not
 * the host's: musl says "No such file or directory" where glibc says the same
 * thing but "Not a tty" where glibc says "Inappropriate ioctl for device", and
 * so on down the list.  The guest is a musl binary, so musl's wording is what
 * a `%m` in it produces, and vfprintf.c calls this rather than the host's
 * strerror.
 *
 * The NUMBERS are musl's generic set (arch/generic/bits/errno.h), which is
 * what an AArch64 musl uses.  They agree with Linux's, and therefore with
 * glibc's, so an errno that reached the port from a host system call on Linux
 * lands on the right message.  ON WINDOWS THEY DO NOT AGREE past the first ~40
 * values -- MSVCRT reuses the numbers above 42 for entirely different
 * conditions -- so a `%m` after a failed Windows call can name the wrong
 * error.  That is left as it is deliberately: the alternative is to translate
 * the host's errno into musl's, and the port has no way to know whether a
 * given errno reached the guest from a host call or was set by the guest
 * itself, which would make the translation wrong half the time.  Nothing in
 * the shader compiler formats %m; this exists so that the conversion is not
 * silently missing if something ever does.
 *
 * This file is MECHANICALLY produced from musl's arch/generic/bits/errno.h and
 * src/errno/__strerror.h by tools/mkstrerror.py -- the messages and the
 * numbers are musl's own, not retyped.
 *
 * `static inline` for the same reason as the rest of runtime/musl/: the file is
 * #included, not compiled on its own.
 */
#ifndef GSTRERROR_C
#define GSTRERROR_C

static const char *const guest_errmsg[] = {
	[0] = "No error information",
	[1] = "Operation not permitted",  /* EPERM */
	[2] = "No such file or directory",  /* ENOENT */
	[3] = "No such process",  /* ESRCH */
	[4] = "Interrupted system call",  /* EINTR */
	[5] = "I/O error",  /* EIO */
	[6] = "No such device or address",  /* ENXIO */
	[7] = "Argument list too long",  /* E2BIG */
	[8] = "Exec format error",  /* ENOEXEC */
	[9] = "Bad file descriptor",  /* EBADF */
	[10] = "No child process",  /* ECHILD */
	[11] = "Resource temporarily unavailable",  /* EAGAIN */
	[12] = "Out of memory",  /* ENOMEM */
	[13] = "Permission denied",  /* EACCES */
	[14] = "Bad address",  /* EFAULT */
	[15] = "Block device required",  /* ENOTBLK */
	[16] = "Resource busy",  /* EBUSY */
	[17] = "File exists",  /* EEXIST */
	[18] = "Cross-device link",  /* EXDEV */
	[19] = "No such device",  /* ENODEV */
	[20] = "Not a directory",  /* ENOTDIR */
	[21] = "Is a directory",  /* EISDIR */
	[22] = "Invalid argument",  /* EINVAL */
	[23] = "Too many open files in system",  /* ENFILE */
	[24] = "No file descriptors available",  /* EMFILE */
	[25] = "Not a tty",  /* ENOTTY */
	[26] = "Text file busy",  /* ETXTBSY */
	[27] = "File too large",  /* EFBIG */
	[28] = "No space left on device",  /* ENOSPC */
	[29] = "Invalid seek",  /* ESPIPE */
	[30] = "Read-only file system",  /* EROFS */
	[31] = "Too many links",  /* EMLINK */
	[32] = "Broken pipe",  /* EPIPE */
	[33] = "Domain error",  /* EDOM */
	[34] = "Result not representable",  /* ERANGE */
	[35] = "Resource deadlock would occur",  /* EDEADLK */
	[36] = "Filename too long",  /* ENAMETOOLONG */
	[37] = "No locks available",  /* ENOLCK */
	[38] = "Function not implemented",  /* ENOSYS */
	[39] = "Directory not empty",  /* ENOTEMPTY */
	[40] = "Symbolic link loop",  /* ELOOP */
	[42] = "No message of desired type",  /* ENOMSG */
	[43] = "Identifier removed",  /* EIDRM */
	[60] = "Device not a stream",  /* ENOSTR */
	[61] = "No data available",  /* ENODATA */
	[62] = "Device timeout",  /* ETIME */
	[63] = "Out of streams resources",  /* ENOSR */
	[67] = "Link has been severed",  /* ENOLINK */
	[71] = "Protocol error",  /* EPROTO */
	[72] = "Multihop attempted",  /* EMULTIHOP */
	[74] = "Bad message",  /* EBADMSG */
	[75] = "Value too large for data type",  /* EOVERFLOW */
	[77] = "File descriptor in bad state",  /* EBADFD */
	[84] = "Illegal byte sequence",  /* EILSEQ */
	[88] = "Not a socket",  /* ENOTSOCK */
	[89] = "Destination address required",  /* EDESTADDRREQ */
	[90] = "Message too large",  /* EMSGSIZE */
	[91] = "Protocol wrong type for socket",  /* EPROTOTYPE */
	[92] = "Protocol not available",  /* ENOPROTOOPT */
	[93] = "Protocol not supported",  /* EPROTONOSUPPORT */
	[94] = "Socket type not supported",  /* ESOCKTNOSUPPORT */
	[95] = "Not supported",  /* ENOTSUP */
	[96] = "Protocol family not supported",  /* EPFNOSUPPORT */
	[97] = "Address family not supported by protocol",  /* EAFNOSUPPORT */
	[98] = "Address in use",  /* EADDRINUSE */
	[99] = "Address not available",  /* EADDRNOTAVAIL */
	[100] = "Network is down",  /* ENETDOWN */
	[101] = "Network unreachable",  /* ENETUNREACH */
	[102] = "Connection reset by network",  /* ENETRESET */
	[103] = "Connection aborted",  /* ECONNABORTED */
	[104] = "Connection reset by peer",  /* ECONNRESET */
	[105] = "No buffer space available",  /* ENOBUFS */
	[106] = "Socket is connected",  /* EISCONN */
	[107] = "Socket not connected",  /* ENOTCONN */
	[108] = "Cannot send after socket shutdown",  /* ESHUTDOWN */
	[110] = "Operation timed out",  /* ETIMEDOUT */
	[111] = "Connection refused",  /* ECONNREFUSED */
	[112] = "Host is down",  /* EHOSTDOWN */
	[113] = "Host is unreachable",  /* EHOSTUNREACH */
	[114] = "Operation already in progress",  /* EALREADY */
	[115] = "Operation in progress",  /* EINPROGRESS */
	[116] = "Stale file handle",  /* ESTALE */
	[121] = "Remote I/O error",  /* EREMOTEIO */
	[122] = "Quota exceeded",  /* EDQUOT */
	[123] = "No medium found",  /* ENOMEDIUM */
	[124] = "Wrong medium type",  /* EMEDIUMTYPE */
	[125] = "Operation canceled",  /* ECANCELED */
	[126] = "Required key not available",  /* ENOKEY */
	[127] = "Key has expired",  /* EKEYEXPIRED */
	[128] = "Key has been revoked",  /* EKEYREVOKED */
	[129] = "Key was rejected by service",  /* EKEYREJECTED */
	[130] = "Previous owner died",  /* EOWNERDEAD */
	[131] = "State not recoverable",  /* ENOTRECOVERABLE */
};

static inline const char *guest_strerror(int e) {
	/* musl's rule: anything outside the table, including a negative value,
	 * gets entry 0.  The gaps in the table are the codes musl's own
	 * __strerror.h does not enumerate, and musl maps those to entry 0 too --
	 * its errmsgidx[] leaves them zero, which is the offset of str0. */
	if (e < 0 || (size_t)e >= sizeof guest_errmsg / sizeof *guest_errmsg
	    || !guest_errmsg[e])
		return guest_errmsg[0];
	return guest_errmsg[e];
}

#endif /* GSTRERROR_C */
