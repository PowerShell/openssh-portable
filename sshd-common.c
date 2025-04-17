
static void recv_config_state(int fd, struct sshbuf *conf) {
	recv_rexec_state(fd, conf);
}

static void recv_rexec_state(int fd, struct sshbuf *conf) {

}

static void send_config_state(int fd, struct sshbuf *conf) {
	send_rexec_state(fd, conf);
}

static void send_rexec_state(int fd, struct sshbuf *conf) {
	struct sshbuf *m = NULL, *inc = NULL, *hostkeys = NULL;
	struct include_item *item = NULL;
	int r, sz;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(conf));

	if ((m = sshbuf_new()) == NULL ||
	    (inc = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		if ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	hostkeys = pack_hostkeys();

	/*
	 * Protocol from reexec master to child:
	 *	string	configuration
	 *	uint64	timing_secret
	 *	string	host_keys[] {
	 *		string private_key
	 *		string public_key
	 *		string certificate
	 *	}
	 *	string	included_files[] {
	 *		string	selector
	 *		string	filename
	 *		string	contents
	 *	}
	 */
	if ((r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	/* We need to fit the entire message inside the socket send buffer */
	sz = ROUNDUP(sshbuf_len(m) + 5, 16*1024);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz) == -1)
		fatal_f("setsockopt SO_SNDBUF: %s", strerror(errno));

	if (ssh_msg_send(fd, 0, m) == -1)
		error_f("ssh_msg_send failed");

	sshbuf_free(m);
	sshbuf_free(inc);
	sshbuf_free(hostkeys);

	debug3_f("done");
}
