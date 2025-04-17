
static void recv_config_state(int fd, struct sshbuf *conf);
static void recv_rexec_state(int fd, struct sshbuf *conf);
static void send_config_state(int fd, struct sshbuf *conf);
static void send_rexec_state(int fd, struct sshbuf *conf);