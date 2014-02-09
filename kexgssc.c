/*
 * Copyright (c) 2001-2009 Simon Wilkinson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
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

#if defined(GSSAPI) && defined(WITH_OPENSSL)

#include "includes.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include <string.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssh2.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "digest.h"
#include "ssherr.h"

#include "ssh-gss.h"

int
kexgss_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER,
	    recv_tok = GSS_C_EMPTY_BUFFER, gssbuf = GSS_C_EMPTY_BUFFER,
	    msg_tok = GSS_C_EMPTY_BUFFER, *token_ptr;
	Gssctxt *ctxt;
	OM_uint32 maj_status, min_status, ret_flags;
	struct sshbuf *server_blob = NULL;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	struct sshbuf *empty = NULL;
	u_char *msg;
	int type = 0;
	int first = 1;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;
	u_char c;
	int r;

	/* Initialise our GSSAPI world */
	ssh_gssapi_build_ctx(&ctxt);
	if (ssh_gssapi_id_kex(ctxt, kex->name, kex->kex_type)
	    == GSS_C_NO_OID)
		fatal("Couldn't identify host exchange");

	if (ssh_gssapi_import_name(ctxt, kex->gss_host))
		fatal("Couldn't import hostname");

	if (kex->gss_client &&
	    ssh_gssapi_client_identity(ctxt, kex->gss_client))
		fatal("Couldn't acquire client credentials");

	/* Step 1 */
	switch (kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
	case KEX_GSS_GRP14_SHA1:
	case KEX_GSS_GRP14_SHA256:
	case KEX_GSS_GRP16_SHA512:
		r = kex_dh_keypair(kex);
		break;
	case KEX_GSS_NISTP256_SHA256:
		r = kex_ecdh_keypair(kex);
		break;
	case KEX_GSS_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		break;
	default:
		fatal_f("Unexpected KEX type %d", kex->kex_type);
	}
	if (r != 0)
		return r;

	token_ptr = GSS_C_NO_BUFFER;

	do {
		debug("Calling gss_init_sec_context");

		maj_status = ssh_gssapi_init_ctx(ctxt,
		    kex->gss_deleg_creds, token_ptr, &send_tok,
		    &ret_flags);

		if (GSS_ERROR(maj_status)) {
			/* XXX Useles code: Missing send? */
			if (send_tok.length != 0) {
				if ((r = sshpkt_start(ssh,
				        SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
				        send_tok.length)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
			}
			fatal("gss_init_context failed");
		}

		/* If we've got an old receive buffer get rid of it */
		if (token_ptr != GSS_C_NO_BUFFER)
			gss_release_buffer(&min_status, &recv_tok);

		if (maj_status == GSS_S_COMPLETE) {
			/* If mutual state flag is not true, kex fails */
			if (!(ret_flags & GSS_C_MUTUAL_FLAG))
				fatal("Mutual authentication failed");

			/* If integ avail flag is not true kex fails */
			if (!(ret_flags & GSS_C_INTEG_FLAG))
				fatal("Integrity check failed");
		}

		/*
		 * If we have data to send, then the last message that we
		 * received cannot have been a 'complete'.
		 */
		if (send_tok.length != 0) {
			if (first) {
				if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_INIT)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
				        send_tok.length)) != 0 ||
				    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0)
					fatal("failed to construct packet: %s", ssh_err(r));
				first = 0;
			} else {
				if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
				        send_tok.length)) != 0)
					fatal("failed to construct packet: %s", ssh_err(r));
			}
			if ((r = sshpkt_send(ssh)) != 0)
				fatal("failed to send packet: %s", ssh_err(r));
			gss_release_buffer(&min_status, &send_tok);

			/* If we've sent them data, they should reply */
			do {
				type = ssh_packet_read(ssh);
				if (type == SSH2_MSG_KEXGSS_HOSTKEY) {
					debug("Received KEXGSS_HOSTKEY");
					if (server_host_key_blob)
						fatal("Server host key received more than once");
					if ((r = sshpkt_getb_froms(ssh, &server_host_key_blob)) != 0)
						fatal("Failed to read server host key: %s", ssh_err(r));
				}
			} while (type == SSH2_MSG_KEXGSS_HOSTKEY);

			switch (type) {
			case SSH2_MSG_KEXGSS_CONTINUE:
				debug("Received GSSAPI_CONTINUE");
				if (maj_status == GSS_S_COMPLETE)
					fatal("GSSAPI Continue received from server when complete");
				if ((r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
				        &recv_tok)) != 0 ||
				    (r = sshpkt_get_end(ssh)) != 0)
					fatal("Failed to read token: %s", ssh_err(r));
				break;
			case SSH2_MSG_KEXGSS_COMPLETE:
				debug("Received GSSAPI_COMPLETE");
				if (msg_tok.value != NULL)
				        fatal("Received GSSAPI_COMPLETE twice?");
				if ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
				    (r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
				        &msg_tok)) != 0)
					fatal("Failed to read message: %s", ssh_err(r));

				/* Is there a token included? */
				if ((r = sshpkt_get_u8(ssh, &c)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
				if (c) {
					if ((r = ssh_gssapi_sshpkt_get_buffer_desc(
					    ssh, &recv_tok)) != 0)
						fatal("Failed to read token: %s", ssh_err(r));
					/* If we're already complete - protocol error */
					if (maj_status == GSS_S_COMPLETE)
						ssh_packet_disconnect(ssh, "Protocol error: received token when complete");
				} else {
					/* No token included */
					if (maj_status != GSS_S_COMPLETE)
						ssh_packet_disconnect(ssh, "Protocol error: did not receive final token");
				}
				if ((r = sshpkt_get_end(ssh)) != 0) {
					fatal("Expecting end of packet.");
				}
				break;
			case SSH2_MSG_KEXGSS_ERROR:
				debug("Received Error");
				if ((r = sshpkt_get_u32(ssh, &maj_status)) != 0 ||
				    (r = sshpkt_get_u32(ssh, &min_status)) != 0 ||
				    (r = sshpkt_get_string(ssh, &msg, NULL)) != 0 ||
				    (r = sshpkt_get_string(ssh, NULL, NULL)) != 0 || /* lang tag */
				    (r = sshpkt_get_end(ssh)) != 0)
					fatal("sshpkt_get failed: %s", ssh_err(r));
				fatal("GSSAPI Error: \n%.400s", msg);
			default:
				ssh_packet_disconnect(ssh, "Protocol error: didn't expect packet type %d",
				    type);
			}
			token_ptr = &recv_tok;
		} else {
			/* No data, and not complete */
			if (maj_status != GSS_S_COMPLETE)
				fatal("Not complete, and no token output");
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	/*
	 * We _must_ have received a COMPLETE message in reply from the
	 * server, which will have set server_blob and msg_tok
	 */

	if (type != SSH2_MSG_KEXGSS_COMPLETE)
		fatal("Didn't receive a SSH2_MSG_KEXGSS_COMPLETE when I expected it");

	/* compute shared secret */
	switch (kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
	case KEX_GSS_GRP14_SHA1:
	case KEX_GSS_GRP14_SHA256:
	case KEX_GSS_GRP16_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_GSS_C25519_SHA256:
		if (sshbuf_ptr(server_blob)[sshbuf_len(server_blob)] & 0x80)
			fatal("The received key has MSB of last octet set!");
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_GSS_NISTP256_SHA256:
		if (sshbuf_len(server_blob) != 65)
			fatal("The received NIST-P256 key did not match"
			    "expected length (expected 65, got %zu)", sshbuf_len(server_blob));

		if (sshbuf_ptr(server_blob)[0] != POINT_CONVERSION_UNCOMPRESSED)
			fatal("The received NIST-P256 key does not have first octet 0x04");

		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r != 0)
		goto out;

	if ((empty = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	hashlen = sizeof(hash);
	if ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    (server_host_key_blob ? server_host_key_blob : empty),
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		fatal_f("Unexpected KEX type %d", kex->kex_type);

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	/* Verify that the hash matches the MIC we just got. */
	if (GSS_ERROR(ssh_gssapi_checkmic(ctxt, &gssbuf, &msg_tok)))
		ssh_packet_disconnect(ssh, "Hash's MIC didn't verify");

	gss_release_buffer(&min_status, &msg_tok);

	if (kex->gss_deleg_creds)
		ssh_gssapi_credentials_updated(ctxt);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else
		ssh_gssapi_delete_ctx(&ctxt);

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);

out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(kex->c25519_client_key, sizeof(kex->c25519_client_key));
	sshbuf_free(empty);
	sshbuf_free(server_host_key_blob);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = NULL;
	return r;
}

int
kexgssgex_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER,
	    recv_tok = GSS_C_EMPTY_BUFFER, gssbuf = GSS_C_EMPTY_BUFFER,
	    msg_tok = GSS_C_EMPTY_BUFFER, *token_ptr;
	Gssctxt *ctxt;
	OM_uint32 maj_status, min_status, ret_flags;
	struct sshbuf *shared_secret = NULL;
	BIGNUM *p = NULL;
	BIGNUM *g = NULL;
	struct sshbuf *buf = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	struct sshbuf *server_blob = NULL;
	BIGNUM *dh_server_pub = NULL;
	u_char *msg;
	int type = 0;
	int first = 1;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;
	const BIGNUM *pub_key, *dh_p, *dh_g;
	int nbits = 0, min = DH_GRP_MIN, max = DH_GRP_MAX;
	struct sshbuf *empty = NULL;
	u_char c;
	int r;

	/* Initialise our GSSAPI world */
	ssh_gssapi_build_ctx(&ctxt);
	if (ssh_gssapi_id_kex(ctxt, kex->name, kex->kex_type)
	    == GSS_C_NO_OID)
		fatal("Couldn't identify host exchange");

	if (ssh_gssapi_import_name(ctxt, kex->gss_host))
		fatal("Couldn't import hostname");

	if (kex->gss_client &&
	    ssh_gssapi_client_identity(ctxt, kex->gss_client))
		fatal("Couldn't acquire client credentials");

	debug("Doing group exchange");
	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_GROUPREQ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("Failed to construct a packet: %s", ssh_err(r));

	type = ssh_packet_read(ssh);
	if (type != SSH2_MSG_KEXGSS_GROUP)
		ssh_packet_disconnect(ssh,
		    "Protocol error: expected packet type %d, got %d",
		    SSH2_MSG_KEXGSS_GROUP, type);

	if ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal("shpkt_get_bignum2 failed: %s", ssh_err(r));

	if (BN_num_bits(p) < min || BN_num_bits(p) > max)
		fatal("GSSGRP_GEX group out of range: %d !< %d !< %d",
		    min, BN_num_bits(p), max);

	if ((kex->dh = dh_new_group(g, p)) == NULL)
		fatal("dn_new_group() failed");
	p = g = NULL; /* belong to kex->dh now */

	if ((r = dh_gen_key(kex->dh, kex->we_need * 8)) != 0)
		goto out;
	DH_get0_key(kex->dh, &pub_key, NULL);

	token_ptr = GSS_C_NO_BUFFER;

	do {
		/* Step 2 - call GSS_Init_sec_context() */
		debug("Calling gss_init_sec_context");

		maj_status = ssh_gssapi_init_ctx(ctxt,
		    kex->gss_deleg_creds, token_ptr, &send_tok,
		    &ret_flags);

		if (GSS_ERROR(maj_status)) {
			/* XXX Useles code: Missing send? */
			if (send_tok.length != 0) {
				if ((r = sshpkt_start(ssh,
				        SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
				        send_tok.length)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
			}
			fatal("gss_init_context failed");
		}

		/* If we've got an old receive buffer get rid of it */
		if (token_ptr != GSS_C_NO_BUFFER)
			gss_release_buffer(&min_status, &recv_tok);

		if (maj_status == GSS_S_COMPLETE) {
			/* If mutual state flag is not true, kex fails */
			if (!(ret_flags & GSS_C_MUTUAL_FLAG))
				fatal("Mutual authentication failed");

			/* If integ avail flag is not true kex fails */
			if (!(ret_flags & GSS_C_INTEG_FLAG))
				fatal("Integrity check failed");
		}

		/*
		 * If we have data to send, then the last message that we
		 * received cannot have been a 'complete'.
		 */
		if (send_tok.length != 0) {
			if (first) {
				if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_INIT)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
				        send_tok.length)) != 0 ||
				    (r = sshpkt_put_bignum2(ssh, pub_key)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
				first = 0;
			} else {
				if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
				    (r = sshpkt_put_string(ssh,send_tok.value,
				        send_tok.length)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
			}
			if ((r = sshpkt_send(ssh)) != 0)
				fatal("sshpkt_send failed: %s", ssh_err(r));
			gss_release_buffer(&min_status, &send_tok);

			/* If we've sent them data, they should reply */
			do {
				type = ssh_packet_read(ssh);
				if (type == SSH2_MSG_KEXGSS_HOSTKEY) {
					debug("Received KEXGSS_HOSTKEY");
					if (server_host_key_blob)
						fatal("Server host key received more than once");
					if ((r = sshpkt_getb_froms(ssh, &server_host_key_blob)) != 0)
						fatal("sshpkt failed: %s", ssh_err(r));
				}
			} while (type == SSH2_MSG_KEXGSS_HOSTKEY);

			switch (type) {
			case SSH2_MSG_KEXGSS_CONTINUE:
				debug("Received GSSAPI_CONTINUE");
				if (maj_status == GSS_S_COMPLETE)
					fatal("GSSAPI Continue received from server when complete");
				if ((r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
				        &recv_tok)) != 0 ||
				    (r = sshpkt_get_end(ssh)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
				break;
			case SSH2_MSG_KEXGSS_COMPLETE:
				debug("Received GSSAPI_COMPLETE");
				if (msg_tok.value != NULL)
				        fatal("Received GSSAPI_COMPLETE twice?");
				if ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
				    (r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
				        &msg_tok)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));

				/* Is there a token included? */
				if ((r = sshpkt_get_u8(ssh, &c)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
				if (c) {
					if ((r = ssh_gssapi_sshpkt_get_buffer_desc(
					        ssh, &recv_tok)) != 0 ||
					    (r = sshpkt_get_end(ssh)) != 0)
						fatal("sshpkt failed: %s", ssh_err(r));
					/* If we're already complete - protocol error */
					if (maj_status == GSS_S_COMPLETE)
						ssh_packet_disconnect(ssh, "Protocol error: received token when complete");
				} else {
					/* No token included */
					if (maj_status != GSS_S_COMPLETE)
						ssh_packet_disconnect(ssh, "Protocol error: did not receive final token");
				}
				break;
			case SSH2_MSG_KEXGSS_ERROR:
				debug("Received Error");
				if ((r = sshpkt_get_u32(ssh, &maj_status)) != 0 ||
				    (r = sshpkt_get_u32(ssh, &min_status)) != 0 ||
				    (r = sshpkt_get_string(ssh, &msg, NULL)) != 0 ||
				    (r = sshpkt_get_string(ssh, NULL, NULL)) != 0 || /* lang tag */
				    (r = sshpkt_get_end(ssh)) != 0)
					fatal("sshpkt failed: %s", ssh_err(r));
				fatal("GSSAPI Error: \n%.400s", msg);
			default:
				ssh_packet_disconnect(ssh, "Protocol error: didn't expect packet type %d",
				    type);
			}
			token_ptr = &recv_tok;
		} else {
			/* No data, and not complete */
			if (maj_status != GSS_S_COMPLETE)
				fatal("Not complete, and no token output");
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	/*
	 * We _must_ have received a COMPLETE message in reply from the
	 * server, which will have set dh_server_pub and msg_tok
	 */

	if (type != SSH2_MSG_KEXGSS_COMPLETE)
		fatal("Didn't receive a SSH2_MSG_KEXGSS_COMPLETE when I expected it");

	/* 7. C verifies that the key Q_S is valid */
	/* 8. C computes shared secret */
	if ((buf = sshbuf_new()) == NULL ||
	    (r = sshbuf_put_stringb(buf, server_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_server_pub)) != 0)
		goto out;
	sshbuf_free(buf);
	buf = NULL;

	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = kex_dh_compute_key(kex, dh_server_pub, shared_secret)) != 0)
		goto out;
	if ((empty = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);
	hashlen = sizeof(hash);
	if ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    (server_host_key_blob ? server_host_key_blob : empty),
 	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_key,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		fatal("Failed to calculate hash: %s", ssh_err(r));

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	/* Verify that the hash matches the MIC we just got. */
	if (GSS_ERROR(ssh_gssapi_checkmic(ctxt, &gssbuf, &msg_tok)))
		ssh_packet_disconnect(ssh, "Hash's MIC didn't verify");

	gss_release_buffer(&min_status, &msg_tok);

	if (kex->gss_deleg_creds)
		ssh_gssapi_credentials_updated(ctxt);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else
		ssh_gssapi_delete_ctx(&ctxt);

	/* Finally derive the keys and send them */
	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	sshbuf_free(buf);
	sshbuf_free(server_blob);
	sshbuf_free(empty);
	explicit_bzero(hash, sizeof(hash));
	DH_free(kex->dh);
	kex->dh = NULL;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_key_blob);
	return r;
}
#endif /* defined(GSSAPI) && defined(WITH_OPENSSL) */
