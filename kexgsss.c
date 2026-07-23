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

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssh2.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"
#include "misc.h"      /* servconf.h needs misc.h for struct ForwardOptions */
#include "servconf.h"
#include "ssh-gss.h"
#include "digest.h"
#include "ssherr.h"

extern ServerOptions options;

int
kexgss_server(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	OM_uint32 maj_status, min_status;

	/*
	 * Some GSSAPI implementations use the input value of ret_flags (an
	 * output variable) as a means of triggering mechanism specific
	 * features. Initializing it to zero avoids inadvertently
	 * activating this non-standard behaviour.
	 */

	OM_uint32 ret_flags = 0;
	gss_buffer_desc gssbuf = GSS_C_EMPTY_BUFFER,
	    recv_tok = GSS_C_EMPTY_BUFFER, msg_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	Gssctxt *ctxt = NULL;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *client_pubkey = NULL;
	struct sshbuf *server_pubkey = NULL;
	struct sshbuf *empty = sshbuf_new();
	int type = 0;
	gss_OID oid;
	char *mechs;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;
	int r;

	/* Initialise GSSAPI */

	/* If we're rekeying, privsep means that some of the private structures
	 * in the GSSAPI code are no longer available. This kludges them back
	 * into life
	 */
	if (!ssh_gssapi_oid_table_ok()) {
		mechs = ssh_gssapi_server_mechanisms();
		free(mechs);
	}

	debug2_f("Identifying %s", kex->name);
	oid = ssh_gssapi_id_kex(NULL, kex->name, kex->kex_type);
	if (oid == GSS_C_NO_OID)
	   fatal("Unknown gssapi mechanism");

	debug2_f("Acquiring credentials");

	if (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, oid)))
		fatal("Unable to acquire credentials for the server");

	do {
		debug("Wait SSH2_MSG_KEXGSS_INIT");
		type = ssh_packet_read(ssh);
		switch(type) {
		case SSH2_MSG_KEXGSS_INIT:
			if (client_pubkey != NULL)
				fatal("Received KEXGSS_INIT after initialising");
			if ((r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
			        &recv_tok)) != 0 ||
			    (r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
			    (r = sshpkt_get_end(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));

			switch (kex->kex_type) {
			case KEX_GSS_GRP1_SHA1:
			case KEX_GSS_GRP14_SHA1:
			case KEX_GSS_GRP14_SHA256:
			case KEX_GSS_GRP16_SHA512:
				r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
				    &shared_secret);
				break;
			case KEX_GSS_NISTP256_SHA256:
				r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
				    &shared_secret);
				break;
			case KEX_GSS_C25519_SHA256:
				r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
				    &shared_secret);
				break;
			default:
				fatal_f("Unexpected KEX type %d", kex->kex_type);
			}
			if (r != 0)
				goto out;

			/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			break;
		case SSH2_MSG_KEXGSS_CONTINUE:
			if ((r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
			        &recv_tok)) != 0 ||
			    (r = sshpkt_get_end(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));
			break;
		default:
			ssh_packet_disconnect(ssh,
			    "Protocol error: didn't expect packet type %d",
			    type);
		}

		maj_status = mm_ssh_gssapi_accept_ctx(ctxt, &recv_tok,
		    &send_tok, &ret_flags);

		gss_release_buffer(&min_status, &recv_tok);

		if (maj_status != GSS_S_COMPLETE && send_tok.length == 0)
			fatal("Zero length token output when incomplete");

		if (client_pubkey == NULL)
			fatal("No client public key");

		if (maj_status & GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value, send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));
			gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status)) {
		if (send_tok.length > 0) {
			if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value, send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));
		}
		fatal("accept_ctx died");
	}

	if (!(ret_flags & GSS_C_MUTUAL_FLAG))
		fatal("Mutual Authentication flag wasn't set");

	if (!(ret_flags & GSS_C_INTEG_FLAG))
		fatal("Integrity flag wasn't set");

	hashlen = sizeof(hash);
	if ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    empty,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		goto out;

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	if (GSS_ERROR(mm_ssh_gssapi_sign(ctxt, &gssbuf, &msg_tok)))
		fatal("Couldn't get MIC");

	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_COMPLETE)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, msg_tok.value, msg_tok.length)) != 0)
		fatal("sshpkt failed: %s", ssh_err(r));

	if (send_tok.length != 0) {
		if ((r = sshpkt_put_u8(ssh, 1)) != 0 || /* true */
		    (r = sshpkt_put_string(ssh, send_tok.value, send_tok.length)) != 0)
			fatal("sshpkt failed: %s", ssh_err(r));
	} else {
		if ((r = sshpkt_put_u8(ssh, 0)) != 0) /* false */
			fatal("sshpkt failed: %s", ssh_err(r));
	}
	if ((r = sshpkt_send(ssh)) != 0)
		fatal("sshpkt_send failed: %s", ssh_err(r));

	gss_release_buffer(&min_status, &send_tok);
	gss_release_buffer(&min_status, &msg_tok);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else
		ssh_gssapi_delete_ctx(&ctxt);

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);

	/* If this was a rekey, then save out any delegated credentials we
	 * just exchanged.  */
	if (options.gss_store_rekey)
		ssh_gssapi_rekey_creds();
out:
	sshbuf_free(empty);
	explicit_bzero(hash, sizeof(hash));
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	return r;
}

int
kexgssgex_server(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	OM_uint32 maj_status, min_status;

	/*
	 * Some GSSAPI implementations use the input value of ret_flags (an
	 * output variable) as a means of triggering mechanism specific
	 * features. Initializing it to zero avoids inadvertently
	 * activating this non-standard behaviour.
	 */

	OM_uint32 ret_flags = 0;
	gss_buffer_desc gssbuf = GSS_C_EMPTY_BUFFER,
	    recv_tok = GSS_C_EMPTY_BUFFER, msg_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	Gssctxt *ctxt = NULL;
	struct sshbuf *shared_secret = NULL;
	int type = 0;
	gss_OID oid;
	char *mechs;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;
	BIGNUM *dh_client_pub = NULL;
	const BIGNUM *pub_key, *dh_p, *dh_g;
	int min = -1, max = -1, nbits = -1;
	int cmin = -1, cmax = -1; /* client proposal */
	struct sshbuf *empty = sshbuf_new();
	int r;

	/* Initialise GSSAPI */

	/* If we're rekeying, privsep means that some of the private structures
	 * in the GSSAPI code are no longer available. This kludges them back
	 * into life
	 */
	if (!ssh_gssapi_oid_table_ok())
		if ((mechs = ssh_gssapi_server_mechanisms()))
			free(mechs);

	debug2_f("Identifying %s", kex->name);
	oid = ssh_gssapi_id_kex(NULL, kex->name, kex->kex_type);
	if (oid == GSS_C_NO_OID)
	   fatal("Unknown gssapi mechanism");

	debug2_f("Acquiring credentials");

	if (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, oid)))
		fatal("Unable to acquire credentials for the server");

	/* 5. S generates an ephemeral key pair (do the allocations early) */
	debug("Doing group exchange");
	type = ssh_packet_read(ssh);
	if (type != SSH2_MSG_KEXGSS_GROUPREQ)
		ssh_packet_disconnect(ssh,
		    "Protocol error: expected packet type %d, got %d",
		    SSH2_MSG_KEXGSS_GROUPREQ, type);
	/* store client proposal to provide valid signature */
	if ((r = sshpkt_get_u32(ssh, &cmin)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &cmax)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal("sshpkt failed: %s", ssh_err(r));
	kex->nbits = nbits;
	kex->min = cmin;
	kex->max = cmax;
	min = MAX(DH_GRP_MIN, cmin);
	max = MIN(DH_GRP_MAX, cmax);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);
	if (max < min || nbits < min || max < nbits)
		fatal("GSS_GEX, bad parameters: %d !< %d !< %d",
		    min, nbits, max);
	kex->dh = mm_choose_dh(min, nbits, max);
	if (kex->dh == NULL) {
		ssh_packet_disconnect(ssh, "Protocol error: no matching group found");
	}

	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("sshpkt failed: %s", ssh_err(r));

	if ((r = ssh_packet_write_wait(ssh)) != 0)
		fatal("ssh_packet_write_wait: %s", ssh_err(r));

	/* Compute our exchange value in parallel with the client */
	if ((r = dh_gen_key(kex->dh, kex->we_need * 8)) != 0)
		goto out;

	do {
		debug("Wait SSH2_MSG_GSSAPI_INIT");
		type = ssh_packet_read(ssh);
		switch(type) {
		case SSH2_MSG_KEXGSS_INIT:
			if (dh_client_pub != NULL)
				fatal("Received KEXGSS_INIT after initialising");
			if ((r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
			        &recv_tok)) != 0 ||
			    (r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
			    (r = sshpkt_get_end(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));

			/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			break;
		case SSH2_MSG_KEXGSS_CONTINUE:
			if ((r = ssh_gssapi_sshpkt_get_buffer_desc(ssh,
			        &recv_tok)) != 0 ||
			    (r = sshpkt_get_end(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));
			break;
		default:
			ssh_packet_disconnect(ssh,
			    "Protocol error: didn't expect packet type %d",
			    type);
		}

		maj_status = mm_ssh_gssapi_accept_ctx(ctxt, &recv_tok,
		    &send_tok, &ret_flags);

		gss_release_buffer(&min_status, &recv_tok);

		if (maj_status != GSS_S_COMPLETE && send_tok.length == 0)
			fatal("Zero length token output when incomplete");

		if (dh_client_pub == NULL)
			fatal("No client public key");

		if (maj_status & GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value, send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));
			gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status)) {
		if (send_tok.length > 0) {
			if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value, send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal("sshpkt failed: %s", ssh_err(r));
		}
		fatal("accept_ctx died");
	}

	if (!(ret_flags & GSS_C_MUTUAL_FLAG))
		fatal("Mutual Authentication flag wasn't set");

	if (!(ret_flags & GSS_C_INTEG_FLAG))
		fatal("Integrity flag wasn't set");

	/* calculate shared secret */
	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = kex_dh_compute_key(kex, dh_client_pub, shared_secret)) != 0)
		goto out;

	DH_get0_key(kex->dh, &pub_key, NULL);
	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);
	hashlen = sizeof(hash);
	if ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    empty,
	    cmin, nbits, cmax,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_key,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		fatal("kexgex_hash failed: %s", ssh_err(r));

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	if (GSS_ERROR(mm_ssh_gssapi_sign(ctxt, &gssbuf, &msg_tok)))
		fatal("Couldn't get MIC");

	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_COMPLETE)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_key)) != 0 ||
	    (r = sshpkt_put_string(ssh, msg_tok.value, msg_tok.length)) != 0)
		fatal("sshpkt failed: %s", ssh_err(r));

	if (send_tok.length != 0) {
		if ((r = sshpkt_put_u8(ssh, 1)) != 0 || /* true */
		    (r = sshpkt_put_string(ssh, send_tok.value, send_tok.length)) != 0)
			fatal("sshpkt failed: %s", ssh_err(r));
	} else {
		if ((r = sshpkt_put_u8(ssh, 0)) != 0) /* false */
			fatal("sshpkt failed: %s", ssh_err(r));
	}
	if ((r = sshpkt_send(ssh)) != 0)
		fatal("sshpkt failed: %s", ssh_err(r));

	gss_release_buffer(&min_status, &send_tok);
	gss_release_buffer(&min_status, &msg_tok);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else
		ssh_gssapi_delete_ctx(&ctxt);

	/* Finally derive the keys and send them */
	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);

	/* If this was a rekey, then save out any delegated credentials we
	 * just exchanged.  */
	if (options.gss_store_rekey)
		ssh_gssapi_rekey_creds();
out:
	sshbuf_free(empty);
	explicit_bzero(hash, sizeof(hash));
	DH_free(kex->dh);
	kex->dh = NULL;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	return r;
}
#endif /* defined(GSSAPI) && defined(WITH_OPENSSL) */
