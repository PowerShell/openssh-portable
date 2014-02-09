/*
 * Copyright (c) 2023 Colin Watson.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI

#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"

static int
ssh_null_equal(const struct sshkey *a, const struct sshkey *b)
{
	return 1;
}

static int
ssh_null_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}

static int
ssh_null_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}

static int
ssh_null_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}

static int
ssh_null_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}

static int
ssh_null_copy_public(const struct sshkey *from, struct sshkey *to)
{
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}

static int
ssh_null_verify(const struct sshkey *key, const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}

static const struct sshkey_impl_funcs sshkey_null_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	NULL,
	/* .equal = */		ssh_null_equal,
	/* .ssh_serialize_public = */ ssh_null_serialize_public,
	/* .ssh_deserialize_public = */ ssh_null_deserialize_public,
	/* .ssh_serialize_private = */ ssh_null_serialize_private,
	/* .ssh_deserialize_private = */ ssh_null_deserialize_private,
	/* .generate = */	NULL,
	/* .copy_public = */	ssh_null_copy_public,
	/* .sign = */		NULL,
	/* .verify = */		ssh_null_verify,
};

const struct sshkey_impl sshkey_null_impl = {
	/* .name = */		"null",
	/* .shortname = */	"null",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_NULL,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_null_funcs,
};

#endif /* GSSAPI */
