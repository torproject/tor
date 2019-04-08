/**
 * \file crypt_path.h
 * \brief Header file for crypt_path.c.
 **/

/* rename */
void assert_cpath_layer_ok(const crypt_path_t *cp);

/* rename */
void assert_cpath_ok(const crypt_path_t *cp);

/* rename */
int onion_append_hop(crypt_path_t **head_ptr, extend_info_t *choice);

/* rename */
void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop);

