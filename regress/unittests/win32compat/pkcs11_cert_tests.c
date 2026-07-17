/*
 * Copyright (c) 2026 Sebastian Ott.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include "authfd.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"
#include "xmalloc.h"

#include "contrib/win32/win32compat/pkcs11-cert.h"
#include "../test_helper/test_helper.h"
#include "tests.h"

#define TEST_CERT \
    "ecdsa-sha2-nistp256-cert-v01@openssh.com " \
    "AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg" \
    "OtFRnMigkGliaYfPmX5IidVWfV3tRH6lqRXv0l8bvKoAAAAIbmlzdHAyNTYAAABB" \
    "BAxZW5ZDq1vcnSlYbTPvQGN3PbGgRO0ht5Rcd/JwWr5AAw2iPY4d/5Lxvybfb6" \
    "ZttqsKJJUwhg38wpF5CCmlpQcAAAAAAAAABwAAAAIAAAAGanVsaXVzAAAAEgAAAA" \
    "Vob3N0MQAAAAVob3N0MgAAAAA2jAHwAAAAAE0eYHAAAAAAAAAAAAAAAAAAAABoAA" \
    "AAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxZW5ZDq1vcnS" \
    "lYbTPvQGN3PbGgRO0ht5Rcd/JwWr5AAw2iPY4d/5Lxvybfb6ZttqsKJJUwhg38w" \
    "pF5CCmlpQcAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIHbxGwTnu" \
    "e7KxhHXGFvRcxBnekhQ3Qx84vV/Vs4oVCrpAAAAIQC7vk2+d14aS7td7kVXLQn3" \
    "92oALjEBzMZoDvT1vT/zOA== test"

static struct sshkey *
load_test_cert(void)
{
	struct sshkey *key = NULL;
	char *line = NULL, *cp;

	line = xstrdup(TEST_CERT);
	cp = line;
	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL || sshkey_read(key, &cp) != 0) {
		sshkey_free(key);
		key = NULL;
	}
	free(line);
	return key;
}

static int
put_associated_certs(struct sshbuf *m, int cert_only,
    struct sshkey *cert, size_t ncerts)
{
	struct sshbuf *b = NULL;
	size_t i;
	int r;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	for (i = 0; i < ncerts; i++) {
		if ((r = sshkey_puts(cert, b)) != 0)
			goto out;
	}
	if ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(m,
	    "associated-certs-v00@openssh.com")) != 0 ||
	    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
	    (r = sshbuf_put_stringb(m, b)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}

static void
test_pkcs11_cert_constraints_valid(void)
{
	struct sshbuf *m = NULL;
	struct sshkey *cert = NULL, **certs = NULL;
	size_t ncerts = 0;
	int cert_only = 0, r;

	TEST_START("PKCS11 associated certificate constraint");
	ASSERT_PTR_NE(cert = load_test_cert(), NULL);
	ASSERT_PTR_NE(m = sshbuf_new(), NULL);
	ASSERT_INT_EQ(put_associated_certs(m, 1, cert, 1), 0);
	ASSERT_INT_EQ(r = parse_pkcs11_add_constraints(m, &cert_only,
	    &certs, &ncerts), 0);
	ASSERT_INT_EQ(cert_only, 1);
	ASSERT_SIZE_T_EQ(ncerts, 1);
	ASSERT_INT_EQ(sshkey_equal(cert, certs[0]), 1);
	free_pkcs11_certs(certs, ncerts);
	sshkey_free(cert);
	sshbuf_free(m);
	TEST_DONE();
}

static void
test_pkcs11_cert_constraints_compatible(void)
{
	struct sshbuf *m = NULL, *destinations = NULL;
	struct sshkey *cert = NULL, **certs = NULL;
	size_t ncerts = 0;
	int cert_only = 0;

	TEST_START("PKCS11 certificate with existing constraints");
	ASSERT_PTR_NE(cert = load_test_cert(), NULL);
	ASSERT_PTR_NE(m = sshbuf_new(), NULL);
	ASSERT_PTR_NE(destinations = sshbuf_new(), NULL);
	ASSERT_INT_EQ(sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(m, 60), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_EXTENSION), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(m,
	    "restrict-destination-v00@openssh.com"), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(m, destinations), 0);
	ASSERT_INT_EQ(put_associated_certs(m, 1, cert, 1), 0);
	ASSERT_INT_EQ(parse_pkcs11_add_constraints(m, &cert_only,
	    &certs, &ncerts), 0);
	ASSERT_INT_EQ(cert_only, 1);
	ASSERT_SIZE_T_EQ(ncerts, 1);
	free_pkcs11_certs(certs, ncerts);
	sshkey_free(cert);
	sshbuf_free(destinations);
	sshbuf_free(m);
	TEST_DONE();
}

static void
test_pkcs11_cert_identity_name(void)
{
	struct sshkey *cert = NULL, *plain = NULL;
	u_char *cert_blob = NULL, *plain_blob = NULL;
	size_t cert_blob_len = 0, plain_blob_len = 0;
	char *cert_name = NULL, *cert_name_again = NULL, *plain_name = NULL;

	TEST_START("distinct PKCS11 certificate registry identity");
	ASSERT_PTR_NE(cert = load_test_cert(), NULL);
	ASSERT_INT_EQ(sshkey_from_private(cert, &plain), 0);
	ASSERT_INT_EQ(sshkey_drop_cert(plain), 0);
	ASSERT_INT_EQ(sshkey_to_blob(cert, &cert_blob, &cert_blob_len), 0);
	ASSERT_INT_EQ(sshkey_to_blob(plain, &plain_blob, &plain_blob_len), 0);
	ASSERT_PTR_NE(cert_name = pkcs11_identity_name(cert, cert_blob,
	    cert_blob_len), NULL);
	ASSERT_PTR_NE(cert_name_again = pkcs11_identity_name(cert, cert_blob,
	    cert_blob_len), NULL);
	ASSERT_PTR_NE(plain_name = pkcs11_identity_name(plain, plain_blob,
	    plain_blob_len), NULL);
	ASSERT_INT_EQ(strncmp(cert_name, "cert-", 5), 0);
	ASSERT_STRING_EQ(cert_name, cert_name_again);
	ASSERT_STRING_NE(cert_name, plain_name);
	free(plain_name);
	free(cert_name_again);
	free(cert_name);
	free(plain_blob);
	free(cert_blob);
	sshkey_free(plain);
	sshkey_free(cert);
	TEST_DONE();
}

static void
test_pkcs11_cert_constraints_duplicate(void)
{
	struct sshbuf *m = NULL;
	struct sshkey *cert = NULL, **certs = NULL;
	size_t ncerts = 0;
	int cert_only = 0;

	TEST_START("duplicate PKCS11 certificate constraint");
	ASSERT_PTR_NE(cert = load_test_cert(), NULL);
	ASSERT_PTR_NE(m = sshbuf_new(), NULL);
	ASSERT_INT_EQ(put_associated_certs(m, 0, cert, 1), 0);
	ASSERT_INT_EQ(put_associated_certs(m, 0, cert, 1), 0);
	ASSERT_INT_NE(parse_pkcs11_add_constraints(m, &cert_only,
	    &certs, &ncerts), 0);
	free_pkcs11_certs(certs, ncerts);
	sshkey_free(cert);
	sshbuf_free(m);
	TEST_DONE();
}

static void
test_pkcs11_cert_constraints_truncated(void)
{
	struct sshbuf *m = NULL;
	struct sshkey **certs = NULL;
	size_t ncerts = 0;
	int cert_only = 0;

	TEST_START("truncated PKCS11 certificate constraint");
	ASSERT_PTR_NE(m = sshbuf_new(), NULL);
	ASSERT_INT_EQ(sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_EXTENSION), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(m,
	    "associated-certs-v00@openssh.com"), 0);
	ASSERT_INT_NE(parse_pkcs11_add_constraints(m, &cert_only,
	    &certs, &ncerts), 0);
	free_pkcs11_certs(certs, ncerts);
	sshbuf_free(m);
	TEST_DONE();
}

static void
test_pkcs11_cert_constraints_malformed(void)
{
	struct sshbuf *m = NULL, *b = NULL;
	struct sshkey **certs = NULL;
	size_t ncerts = 0;
	int cert_only = 0;

	TEST_START("malformed PKCS11 certificate constraint");
	ASSERT_PTR_NE(m = sshbuf_new(), NULL);
	ASSERT_PTR_NE(b = sshbuf_new(), NULL);
	ASSERT_INT_EQ(sshbuf_put_string(b, "bad", 3), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_EXTENSION), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(m,
	    "associated-certs-v00@openssh.com"), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(m, 0), 0);
	ASSERT_INT_EQ(sshbuf_put_stringb(m, b), 0);
	ASSERT_INT_NE(parse_pkcs11_add_constraints(m, &cert_only,
	    &certs, &ncerts), 0);
	free_pkcs11_certs(certs, ncerts);
	sshbuf_free(b);
	sshbuf_free(m);
	TEST_DONE();
}

static void
test_pkcs11_cert_constraints_oversized(void)
{
	struct sshbuf *m = NULL;
	struct sshkey *cert = NULL, **certs = NULL;
	size_t ncerts = 0;
	int cert_only = 0;

	TEST_START("oversized PKCS11 certificate constraint");
	ASSERT_PTR_NE(cert = load_test_cert(), NULL);
	ASSERT_PTR_NE(m = sshbuf_new(), NULL);
	ASSERT_INT_EQ(put_associated_certs(m, 0, cert,
	    AGENT_MAX_EXT_CERTS + 1), 0);
	ASSERT_INT_NE(parse_pkcs11_add_constraints(m, &cert_only,
	    &certs, &ncerts), 0);
	free_pkcs11_certs(certs, ncerts);
	sshkey_free(cert);
	sshbuf_free(m);
	TEST_DONE();
}

void
pkcs11_cert_tests(void)
{
	test_pkcs11_cert_constraints_valid();
	test_pkcs11_cert_constraints_compatible();
	test_pkcs11_cert_identity_name();
	test_pkcs11_cert_constraints_duplicate();
	test_pkcs11_cert_constraints_truncated();
	test_pkcs11_cert_constraints_malformed();
	test_pkcs11_cert_constraints_oversized();
}
