int connection_ext_or_start_auth(or_connection_t *or_conn);

ext_or_cmd_t *ext_or_cmd_new(uint16_t len);
void ext_or_cmd_free(ext_or_cmd_t *cmd);
void connection_or_set_ext_or_identifier(or_connection_t *conn);
void connection_or_remove_from_ext_or_id_map(or_connection_t *conn);
void connection_or_clear_ext_or_id_map(void);

int connection_ext_or_finished_flushing(or_connection_t *conn);
int connection_ext_or_process_inbuf(or_connection_t *or_conn);

int init_ext_or_cookie_authentication(int is_enabled);
char *get_ext_or_auth_cookie_file(void);

