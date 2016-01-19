/* Trial fallbacks for 0.2.8.1-alpha with ADDRESS_AND_PORT_STABLE_DAYS = 30
 * This works around an issue where relays post a descriptor without a DirPort
 * when restarted. If these relays stay up, they will have been up for 120 days
 * by the 0.2.8 stable release -- teor */
/* Whitelist & blacklist excluded 1070 of 1091 candidates. */
/*
Fallback Directory Summary
Final Count:  21 (Eligible 21, Usable 21, Target 290 (1454 * 0.200000), Clamped to 500)
*/
/* Ignore low fallback numbers in alpha builds -- teor
#error Fallback Count 21 is too low. Must be at least 100 for diversity. Try adding entries to the whitelist, or setting INCLUDE_UNLISTED_ENTRIES = True.
*/
/*
Final Weight: 491920 (Eligible 546000)
Max Weight:   43680 (8.879%) (Clamped to 10.000%)
Min Weight:   8080 (1.643%) (Clamped to 0.100%)
Clamped:   54080 (10.994%) Excess Weight, 4 High Weight Fallbacks (19.0%)
*/
/*
Onionoo Source: details Date: 2016-01-18 00:00:00 Version: 3.0
URL: https://onionoo.torproject.org/details?fields=fingerprint%2Cnickname%2Ccontact%2Clast_changed_address_or_port%2Cconsensus_weight%2Cor_addresses%2Cdir_address%2Crecommended_version%2Cflags&flag=V2Dir&type=relay&last_seen_days=-7&first_seen_days=30-
*/
/*
Onionoo Source: uptime Date: 2016-01-18 00:00:00 Version: 3.0
URL: https://onionoo.torproject.org/uptime?first_seen_days=30-&flag=V2Dir&type=relay&last_seen_days=-7
*/
/*
wagner
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 43680 / 491920 (8.879%)
Consensus Weight: 62600 / 546000 (11.465%)
Rarely used email <trff914 AT gmail DOT com>
*/
"5.175.233.86:80 orport=443 id=5525D0429BFE5DC4F1B0E9DE47A4CFA169661E33"
" weight=43680",
/*
kitten2
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 43680 / 491920 (8.879%)
Consensus Weight: 59100 / 546000 (10.824%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"62.210.124.124:9130 orport=9101 id=2EBD117806EE43C3CC885A8F1E4DC60F207E7D3E"
" ipv6=[2001:bc8:3f23:100::1]:9101"
" weight=43680",
/*
kitten1
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 43680 / 491920 (8.879%)
Consensus Weight: 57600 / 546000 (10.549%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"62.210.124.124:9030 orport=9001 id=86E78DD3720C78DA8673182EF96C54B162CD660C"
" ipv6=[2001:bc8:3f23:100::1]:9001"
" weight=43680",
/*
fluxe4
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 43680 / 491920 (8.879%)
Consensus Weight: 49500 / 546000 (9.066%)
Sebastian <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
*/
"131.188.40.188:443 orport=80 id=EBE718E1A49EE229071702964F8DB1F318075FF8"
" weight=43680",
/*
BabylonNetwork03
Flags: Exit Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 38700 / 491920 (7.867%)
Babylon Network | noc <AT> babylon <DOT> network | PGP 0x2A540FA5 | 1HiSG8pia5DdDLUMyYNkF9sicGozojZLnH
*/
"193.111.136.162:80 orport=443 id=C79552275DFCD486B942510EF663ED36ACA1A84B"
" ipv6=[2001:4ba0:cafe:10d0::1]:443"
" weight=38700",
/*
tornoderdednl
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 33000 / 491920 (6.708%)
0x4871E82F Thom Wiggers <thom @AT@ RDED POINT NL> BTC 1DLyDFV13zhCWJYHMh5bk5C58yYvpxqxfQ
*/
"178.62.199.226:80 orport=443 id=CBEFF7BA4A4062045133C053F2D70524D8BBE5BE"
" ipv6=[2a03:b0c0:2:d0::b7:5001]:443"
" weight=33000",
/*
fluxe3
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 31500 / 491920 (6.403%)
Sebastian <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
*/
"78.47.18.110:443 orport=80 id=F8D27B163B9247B232A2EEE68DD8B698695C28DE"
" weight=31500",
/*
BabylonNetwork02
Flags: Exit Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 27300 / 491920 (5.550%)
Babylon Network | noc <AT> babylon <DOT> network | PGP 0x2A540FA5 | 1HiSG8pia5DdDLUMyYNkF9sicGozojZLnH
*/
"149.202.98.161:80 orport=443 id=54660C671B47E6986B465B80444414BD19E5A34B"
" ipv6=[2001:41d0:8:4528::161]:443"
" weight=27300",
/*
coby
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 20400 / 491920 (4.147%)
c0by <coby AT 127001 dot ovh>
*/
"51.255.33.237:9091 orport=9001 id=A360C21FA87FFA2046D92C17086A6B47E5C68109"
" weight=20400",
/*
kili
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 19300 / 491920 (3.923%)
0x49CBC553 Joost Rijneveld <joost AT joostrijneveld dot nl>
*/
"178.62.173.203:9030 orport=9001 id=DD85503F2D1F52EF9EAD621E942298F46CD2FC10"
" ipv6=[2a03:b0c0:0:1010::a4:b001]:9001"
" weight=19300",
/*
Logforme
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 18600 / 491920 (3.781%)
Logforme <m7527 AT abc dot se>
*/
"84.219.173.60:9030 orport=443 id=855BC2DABE24C861CD887DB9B2E950424B49FC34"
" weight=18600",
/*
eriador
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 17400 / 491920 (3.537%)
hwertiout695@safe-mail.net
*/
"85.25.138.93:9030 orport=4029 id=6DE61A6F72C1E5418A66BFED80DFB63E4C77668F"
" weight=17400",
/*
Doedel24
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 17000 / 491920 (3.456%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.20.134:9030 orport=9001 id=2CE96A8A1DA032664C90F574AFFBECE18A6E8DFC"
" weight=17000",
/*
GrmmlLitavis
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 15500 / 491920 (3.151%)
<tor AT grmml DOT eu>
*/
"5.39.88.19:9030 orport=9001 id=7CB8C31432A796731EA7B6BF4025548DFEB25E0C"
" ipv6=[2001:41d0:8:9a13::1]:9050"
" weight=15500",
/*
Doedel21
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 13800 / 491920 (2.805%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.44.135:80 orport=443 id=AE6A8C18E7499B586CD36246AC4BCAFFBBF93AB2"
" weight=13800",
/*
Unnamed
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 13400 / 491920 (2.724%)
monitor0penmailbox0rg
*/
"217.12.199.208:80 orport=443 id=DF3AED4322B1824BF5539AE54B2D1B38E080FF05"
" weight=13400",
/*
Doedel26
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 12800 / 491920 (2.602%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.20.134:80 orport=443 id=9F5068310818ED7C70B0BC4087AB55CB12CB4377"
" weight=12800",
/*
Doedel22
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 12000 / 491920 (2.439%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.44.135:9030 orport=9001 id=8FA37B93397015B2BC5A525C908485260BE9F422"
" weight=12000",
/*
kitten4
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 10100 / 491920 (2.053%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"212.47.237.95:9130 orport=9101 id=6FB38EB22E57EF7ED5EF00238F6A48E553735D88"
" weight=10100",
/*
Binnacle
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 8320 / 491920 (1.691%)
starlight dot YYYYqQ at binnacle dot cx
*/
"108.53.208.157:80 orport=443 id=4F0DB7E687FC7C0AE55C8F243DA8B0EB27FBF1F2"
" weight=8320",
/*
PedicaboMundi
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 8080 / 491920 (1.643%)
0x43DE8191 - 12LiRiasTEL346ZFjgCh5e3nBexQuvDBTg
*/
"144.76.14.145:110 orport=143 id=14419131033443AE6E21DA82B0D307F7CAE42BDB"
" ipv6=[2a01:4f8:190:9490::dead]:443"
" weight=8080",
