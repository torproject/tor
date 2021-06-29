#include "core/or/or.h"

#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/extendinfo.h"
#include "core/or/policies.h"
#include "feature/client/bridges.h"
#include "feature/control/control_events.h"
#include "feature/dirauth/authmode.h"
#include "feature/dirauth/process_descs.h"
#include "feature/dirauth/reachability.h"
#include "feature/dircache/dirserv.h"
#include "feature/dirclient/dirclient.h"
#include "feature/dirclient/dirclient_modes.h"
#include "feature/dirclient/dlstatus.h"
#include "feature/dircommon/directory.h"
#include "feature/nodelist/authcert.h"
#include "feature/nodelist/describe.h"
#include "feature/nodelist/dirlist.h"
#include "feature/nodelist/microdesc.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/node_select.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo.h"
#include "feature/nodelist/routerlist.h"
#include "feature/dirparse/routerparse.h"
#include "feature/nodelist/routerset.h"
#include "feature/nodelist/torcert.h"
#include "feature/relay/routermode.h"
#include "feature/relay/relay_find_addr.h"
#include "feature/stats/rephist.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/crypt_ops/crypto_rand.h"

#include "feature/dircommon/dir_connection_st.h"
#include "feature/dirclient/dir_server_st.h"
#include "feature/nodelist/document_signature_st.h"
#include "feature/nodelist/extrainfo_st.h"
#include "feature/nodelist/networkstatus_st.h"
#include "feature/nodelist/networkstatus_voter_info_st.h"
#include "feature/nodelist/node_st.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/nodelist/routerlist_st.h"
#include "feature/nodelist/vote_routerstatus_st.h"

#include "lib/crypt_ops/digestset.h"

int fuzz_init(void)
{
 return 0;
}

int fuzz_cleanup(void)
{
 return 0;
}

int fuzz_main(const uint8_t *data, size_t sz)
{
	char *fuzzing_data = tor_memdup_nulterm(data, sz);
	char digest[20];

	hexdigest_to_digest(fuzzing_data, digest);
	tor_free(fuzzing_data);
	return 0;
}
