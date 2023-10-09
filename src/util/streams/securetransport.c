/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "streams/securetransport.h"

#ifdef GIT_HTTPS_SECURETRANSPORT

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecureTransport.h>
#include <Security/SecCertificate.h>

#include "git2/transport.h"

#include "streams/socket.h"

static int securetransport_error(OSStatus ret)
{
	CFStringRef message;

	if (ret == noErr || ret == errSSLClosedGraceful) {
		git_error_clear();
		return 0;
	}

#if !TARGET_OS_IPHONE
	message = SecCopyErrorMessageString(ret, NULL);
	GIT_ERROR_CHECK_ALLOC(message);

	git_error_set(GIT_ERROR_NET, "SecureTransport error: %s", CFStringGetCStringPtr(message, kCFStringEncodingUTF8));
	CFRelease(message);
#else
	git_error_set(GIT_ERROR_NET, "SecureTransport error: OSStatus %d", (unsigned int)ret);
	GIT_UNUSED(message);
#endif

	return -1;
}

typedef struct {
	git_stream parent;
	git_stream *io;
	int owned;
	int error;
	SSLContextRef ctx;
	CFDataRef der_data;
	git_cert_x509 cert_info;
} securetransport_stream;

static int securetransport_certificate(git_cert **out, git_stream *stream)
{
	securetransport_stream *st = (securetransport_stream *) stream;
	SecTrustRef trust = NULL;
	SecCertificateRef sec_cert;
	OSStatus ret;

	if ((ret = SSLCopyPeerTrust(st->ctx, &trust)) != noErr)
		return securetransport_error(ret);

	sec_cert = SecTrustGetCertificateAtIndex(trust, 0);
	st->der_data = SecCertificateCopyData(sec_cert);
	CFRelease(trust);

	if (st->der_data == NULL) {
		git_error_set(GIT_ERROR_SSL, "retrieved invalid certificate data");
		return -1;
	}

	st->cert_info.parent.cert_type = GIT_CERT_X509;
	st->cert_info.data = (void *) CFDataGetBytePtr(st->der_data);
	st->cert_info.len = CFDataGetLength(st->der_data);

	*out = (git_cert *)&st->cert_info;
	return 0;
}

/*
 * Contrary to typical network IO callbacks, Secure Transport write callback is
 * expected to write *all* passed data, not just as much as it can, and any
 * other case would be considered a failure.
 *
 * This behavior is actually not specified in the Apple documentation, but is
 * required for things to work correctly (and incidentally, that's also how
 * Apple implements it in its projects at opensource.apple.com).
 *
 * Libgit2 streams happen to already have this very behavior so this is just
 * passthrough.
 */
static OSStatus write_cb(SSLConnectionRef conn, const void *data, size_t *len)
{
	securetransport_stream *st = (securetransport_stream *)conn;
	git_stream *io = st->io;
	OSStatus ret;

	st->error = 0;

	ret = git_stream__write_full(io, data, *len, 0);

	if (ret < 0) {
		st->error = ret;
		return (ret == GIT_TIMEOUT) ?
		       -9853 /* errSSLNetworkTimeout */:
		       -36 /* ioErr */;
	}

	return noErr;
}

static ssize_t securetransport_write(
	git_stream *stream,
	const char *data,
	size_t len,
	int flags)
{
	securetransport_stream *st = (securetransport_stream *) stream;
	size_t data_len, processed;
	OSStatus ret;

	GIT_UNUSED(flags);

	data_len = min(len, SSIZE_MAX);
	if ((ret = SSLWrite(st->ctx, data, data_len, &processed)) != noErr) {
		if (st->error == GIT_TIMEOUT)
			return GIT_TIMEOUT;

		return securetransport_error(ret);
	}

	GIT_ASSERT(processed < SSIZE_MAX);
	return (ssize_t)processed;
}

/*
 * Contrary to typical network IO callbacks, Secure Transport read callback is
 * expected to read *exactly* the requested number of bytes, not just as much
 * as it can, and any other case would be considered a failure.
 *
 * This behavior is actually not specified in the Apple documentation, but is
 * required for things to work correctly (and incidentally, that's also how
 * Apple implements it in its projects at opensource.apple.com).
 */
static OSStatus read_cb(SSLConnectionRef conn, void *data, size_t *len)
{
	securetransport_stream *st = (securetransport_stream *)conn;
	git_stream *io = st->io;
	OSStatus error = noErr;
	size_t off = 0;
	ssize_t ret;

	st->error = 0;

	do {
		ret = git_stream_read(io, data + off, *len - off);

		if (ret < 0) {
			st->error = ret;
			error = (ret == GIT_TIMEOUT) ?
			        -9853 /* errSSLNetworkTimeout */:
			        -36 /* ioErr */;
			break;
		} else if (ret == 0) {
			error = errSSLClosedGraceful;
			break;
		}

		off += ret;
	} while (off < *len);

	*len = off;
	return error;
}

static ssize_t securetransport_read(
	git_stream *stream,
	void *data,
	size_t len)
{
	securetransport_stream *st = (securetransport_stream *)stream;
	size_t processed;
	OSStatus ret;

	if ((ret = SSLRead(st->ctx, data, len, &processed)) != noErr) {
		if (st->error == GIT_TIMEOUT)
			return GIT_TIMEOUT;

		return securetransport_error(ret);
	}

	return processed;
}

static int securetransport_create_context(
	securetransport_stream *st,
	const char *host)
{
	SecTrustRef trust = NULL;
	SecTrustResultType sec_res;
	OSStatus ret;
	int error = -1;

	st->ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);

	if (!st->ctx) {
		git_error_set(GIT_ERROR_NET, "failed to create SSL context");
		return -1;
	}

	/* Set up context */

	if ((ret = SSLSetIOFuncs(st->ctx, read_cb, write_cb)) != noErr ||
	    (ret = SSLSetConnection(st->ctx, st)) != noErr ||
	    (ret = SSLSetSessionOption(st->ctx, kSSLSessionOptionBreakOnServerAuth, true)) != noErr ||
	    (ret = SSLSetProtocolVersionMin(st->ctx, kTLSProtocol1)) != noErr ||
	    (ret = SSLSetProtocolVersionMax(st->ctx, kTLSProtocol12)) != noErr ||
	    (ret = SSLSetPeerDomainName(st->ctx, host, strlen(host))) != noErr) {
		error = securetransport_error(ret);
		goto on_error;
	}

	/* Connect */

	ret = SSLHandshake(st->ctx);

	if (ret != errSSLServerAuthCompleted && st->error != 0) {
		error = -1;
		goto on_error;
	} else if (ret != errSSLServerAuthCompleted) {
		git_error_set(GIT_ERROR_SSL, "unexpected return value from ssl handshake %d", (int)ret);
		error = -1;
		goto on_error;
	}

	if ((ret = SSLCopyPeerTrust(st->ctx, &trust)) != noErr) {
		error = securetransport_error(ret);
		goto on_error;
	}

	if (!trust)
		return GIT_ECERTIFICATE;

	if ((ret = SecTrustEvaluate(trust, &sec_res)) != noErr) {
		error = securetransport_error(ret);
		goto on_error;
	}

	CFRelease(trust);

	if (sec_res == kSecTrustResultInvalid ||
	    sec_res == kSecTrustResultOtherError) {
		git_error_set(GIT_ERROR_SSL, "internal security trust error");
		error = -1;
		goto on_error;
	}

	if (sec_res == kSecTrustResultDeny ||
	    sec_res == kSecTrustResultRecoverableTrustFailure ||
	    sec_res == kSecTrustResultFatalTrustFailure) {
		git_error_set(GIT_ERROR_SSL, "untrusted connection error");
		return GIT_ECERTIFICATE;
	}

	return 0;

on_error:
	if (trust)
		CFRelease(trust);

	if (st->ctx) {
		CFRelease(st->ctx);
		st->ctx = NULL;
	}

	return error;
}

int securetransport_connect(
	git_stream *stream,
	const char *host,
	const char *port,
	const git_stream_connect_options *opts)
{
	securetransport_stream *st = (securetransport_stream *)stream;

	GIT_ASSERT_ARG(stream);
	GIT_ASSERT_ARG(host);
	GIT_ASSERT_ARG(port);

	if (git_stream_socket_new(&st->io) < 0)
		return -1;

	st->owned = 1;

	if (git_stream_connect(st->io, host, port, opts) < 0)
		return -1;

	return securetransport_create_context(st, host);
}

int securetransport_wrap(
	git_stream *stream,
	git_stream *in,
	const char *host)
{
	securetransport_stream *st = (securetransport_stream *)stream;

	GIT_ASSERT_ARG(stream);
	GIT_ASSERT_ARG(in);
	GIT_ASSERT_ARG(host);

	st->io = in;
	st->owned = 0;

	return securetransport_create_context(st, host);
}

static int securetransport_close(git_stream *stream)
{
	securetransport_stream *st = (securetransport_stream *)stream;
	OSStatus ret;

	ret = SSLClose(st->ctx);

	if (ret != noErr && ret != errSSLClosedGraceful)
		return securetransport_error(ret);

	return st->owned ? git_stream_close(st->io) : 0;
}

static void securetransport_free(git_stream *stream)
{
	securetransport_stream *st = (securetransport_stream *)stream;

	if (st->owned)
		git_stream_free(st->io);

	if (st->ctx)
		CFRelease(st->ctx);

	if (st->der_data)
		CFRelease(st->der_data);

	git__free(st);
}

int git_stream_securetransport_new(git_stream **out)
{
	securetransport_stream *st;

	GIT_ASSERT_ARG(out);

	st = git__calloc(1, sizeof(securetransport_stream));
	GIT_ERROR_CHECK_ALLOC(st);

	st->parent.version = GIT_STREAM_VERSION;
	st->parent.encrypted = 1;
	st->parent.connect = securetransport_connect;
	st->parent.wrap = securetransport_wrap;
	st->parent.certificate = securetransport_certificate;
	st->parent.read = securetransport_read;
	st->parent.write = securetransport_write;
	st->parent.close = securetransport_close;
	st->parent.free = securetransport_free;

	*out = (git_stream *)st;
	return 0;
}

#endif
