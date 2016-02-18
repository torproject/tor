/* Trial fallbacks for 0.2.8.2-alpha with ADDRESS_AND_PORT_STABLE_DAYS = 7
 * This works around an issue where relays post a descriptor without a DirPort
 * when restarted. The flag CUTOFFs ensure sufficient relay stability. -- teor
 */
/* Whitelist & blacklist excluded 1380 of 1412 candidates. */
/*
Fallback Directory Summary
Final Count:  32 (Eligible 32, Usable 32, Target 335 (1679 * 0.200000), Clamped to 500)
*/
/* Ignore low fallback numbers in alpha builds -- teor
#error Fallback Count 32 is too low. Must be at least 50 for diversity. Try adding entries to the whitelist, or setting INCLUDE_UNLISTED_ENTRIES = True.
*/
/*
Final Weight: 704514 (Eligible 712270)
Max Weight:   56981 (8.088%) (Clamped to 10.000%)
Min Weight:   4450 (0.632%) (Clamped to 0.100%)
Clamped:   7755 (1.101%) Excess Weight, 3 High Weight Fallbacks (9.4%)
*/
/*
Onionoo Source: details Date: 2016-02-27 07:00:00 Version: 3.1
URL: https://onionoo.torproject.org/details?fields=fingerprint%2Cnickname%2Ccontact%2Clast_changed_address_or_port%2Cconsensus_weight%2Cor_addresses%2Cdir_address%2Crecommended_version%2Cflags&flag=V2Dir&type=relay&last_seen_days=-7&first_seen_days=7-
*/
/*
Onionoo Source: uptime Date: 2016-02-27 07:00:00 Version: 3.1
URL: https://onionoo.torproject.org/uptime?first_seen_days=7-&flag=V2Dir&type=relay&last_seen_days=-7
*/
/*
kitten1
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 56981 / 704514 (8.088%)
Consensus Weight: 61100 / 712270 (8.578%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"62.210.124.124:9030 orport=9001 id=86E78DD3720C78DA8673182EF96C54B162CD660C"
" ipv6=[2001:bc8:3f23:100::1]:9001"
" weight=56981",
/*
fluxe4
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 56981 / 704514 (8.088%)
Consensus Weight: 59800 / 712270 (8.396%)
Sebastian <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
*/
"131.188.40.188:443 orport=80 id=EBE718E1A49EE229071702964F8DB1F318075FF8"
" weight=56981",
/*
kitten2
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 56981 / 704514 (8.088%)
Consensus Weight: 57800 / 712270 (8.115%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"62.210.124.124:9130 orport=9101 id=2EBD117806EE43C3CC885A8F1E4DC60F207E7D3E"
" ipv6=[2001:bc8:3f23:100::1]:9101"
" weight=56981",
/*
fluxe3
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 54800 / 704514 (7.778%)
Sebastian <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
*/
"78.47.18.110:443 orport=80 id=F8D27B163B9247B232A2EEE68DD8B698695C28DE"
" weight=54800",
/*
tornoderdednl
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 50500 / 704514 (7.168%)
0x4871E82F Thom Wiggers <thom @AT@ RDED POINT NL> BTC 1DLyDFV13zhCWJYHMh5bk5C58yYvpxqxfQ
*/
"178.62.199.226:80 orport=443 id=CBEFF7BA4A4062045133C053F2D70524D8BBE5BE"
" ipv6=[2a03:b0c0:2:d0::b7:5001]:443"
" weight=50500",
/*
pixelminer
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 44800 / 704514 (6.359%)
Christian Sturm <reezer AT pixelminers dot net> - 1Q3PQJTELv33S1nruGcTUMQ7CuWxXmnjkZ
*/
"81.7.14.246:80 orport=443 id=CE75BF0972ADD52AF8807602374E495C815DB304"
" ipv6=[2a02:180:a:51::dead]:443"
" weight=44800",
/*
bakunin
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 41800 / 704514 (5.933%)
GTor <contact _AT_ gtor _DOT_ org>
*/
"178.16.208.57:80 orport=443 id=92CFD9565B24646CAC2D172D3DB503D69E777B8A"
" ipv6=[2a00:1c20:4089:1234:7825:2c5d:1ecd:c66f]:443"
" weight=41800",
/*
kili
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 23800 / 704514 (3.378%)
0x49CBC553 Joost Rijneveld <joost AT joostrijneveld dot nl>
*/
"178.62.173.203:9030 orport=9001 id=DD85503F2D1F52EF9EAD621E942298F46CD2FC10"
" ipv6=[2a03:b0c0:0:1010::a4:b001]:9001"
" weight=23800",
/*
PedicaboMundi
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 23000 / 704514 (3.265%)
0x43DE8191 - 12LiRiasTEL346ZFjgCh5e3nBexQuvDBTg
*/
"144.76.14.145:110 orport=143 id=14419131033443AE6E21DA82B0D307F7CAE42BDB"
" ipv6=[2a01:4f8:190:9490::dead]:443"
" weight=23000",
/*
Doedel26
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 22600 / 704514 (3.208%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.20.134:80 orport=443 id=9F5068310818ED7C70B0BC4087AB55CB12CB4377"
" weight=22600",
/*
Doedel24
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 20800 / 704514 (2.952%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.20.134:9030 orport=9001 id=2CE96A8A1DA032664C90F574AFFBECE18A6E8DFC"
" weight=20800",
/*
Freebird31
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 20500 / 704514 (2.910%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.13.126:80 orport=443 id=F9246DEF2B653807236DA134F2AEAB103D58ABFE"
" weight=20500",
/*
rueckgrat
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 19200 / 704514 (2.725%)
Paul Staroch <paulchen AT rueckgr DOT at> - BTC 1G8pF66fnHc4n4oksY87pCN4TRXAV2Nqhh
*/
"5.9.110.236:9030 orport=9001 id=0756B7CD4DFC8182BE23143FAC0642F515182CEB"
" ipv6=[2a01:4f8:162:51e2::2]:9001"
" weight=19200",
/*
coby
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 16700 / 704514 (2.370%)
c0by <coby AT 127001 dot ovh>
*/
"51.255.33.237:9091 orport=9001 id=A360C21FA87FFA2046D92C17086A6B47E5C68109"
" weight=16700",
/*
Logforme
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 16000 / 704514 (2.271%)
Logforme <m7527 AT abc dot se>
*/
"84.219.173.60:9030 orport=443 id=855BC2DABE24C861CD887DB9B2E950424B49FC34"
" weight=16000",
/*
12xBTME1
Flags: Exit Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 15300 / 704514 (2.172%)
12xBTM@gmail.com - 12xBTMNArLvKXqvbsbyVhpPQfzUDuUaPGP
*/
"81.7.17.171:80 orport=443 id=00C4B4731658D3B4987132A3F77100CFCB190D97"
" ipv6=[2a02:180:1:1::517:11ab]:443"
" weight=15300",
/*
Doedel21
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 14800 / 704514 (2.101%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.44.135:80 orport=443 id=AE6A8C18E7499B586CD36246AC4BCAFFBBF93AB2"
" weight=14800",
/*
Binnacle
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 13700 / 704514 (1.945%)
starlight dot YYYYqQ at binnacle dot cx
*/
"108.53.208.157:80 orport=443 id=4F0DB7E687FC7C0AE55C8F243DA8B0EB27FBF1F2"
" weight=13700",
/*
Freebird32
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 13200 / 704514 (1.874%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.13.126:9030 orport=9001 id=0C475BA4D3AA3C289B716F95954CAD616E50C4E5"
" weight=13200",
/*
eriador
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 12400 / 704514 (1.760%)
hwertiout695@safe-mail.net
*/
"85.25.138.93:9030 orport=4029 id=6DE61A6F72C1E5418A66BFED80DFB63E4C77668F"
" weight=12400",
/*
Nurnberg04
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 11600 / 704514 (1.647%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"88.198.38.226:22 orport=443 id=4B9E2C56FB42B891794FE2CD2FCAD08A320CC3BB"
" ipv6=[2a01:4f8:a0:1351::2]:80"
" weight=11600",
/*
Nurnberg03
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 11000 / 704514 (1.561%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"85.10.201.38:22 orport=443 id=F6279A203C1950ACF592322A235647A05BFBCF91"
" ipv6=[2a01:4f8:a0:43cc::2]:80"
" weight=11000",
/*
Doedel22
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 10600 / 704514 (1.505%)
Felix <zwiebel ta quantentunnel tod de>
*/
"178.254.44.135:9030 orport=9001 id=8FA37B93397015B2BC5A525C908485260BE9F422"
" weight=10600",
/*
Nurnberg01
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 10500 / 704514 (1.490%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"213.239.210.204:22 orport=443 id=5BFDECCE9B4A23AE14EC767C5A2C1E10558B00B9"
" ipv6=[2a01:4f8:a0:9474::2]:80"
" weight=10500",
/*
kitten4
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 10400 / 704514 (1.476%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"212.47.237.95:9130 orport=9101 id=6FB38EB22E57EF7ED5EF00238F6A48E553735D88"
" weight=10400",
/*
Unnamed
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 9780 / 704514 (1.388%)
monitor0penmailbox0rg
*/
"217.12.210.214:80 orport=443 id=943C0C6841C1E914B9FCA796C6846620A5AF9BC7"
" weight=9780",
/*
Nurnberg02
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 9490 / 704514 (1.347%)
Please Donate <tor AT use.startmail dot com> - 1GuD8FxCnTqYGeRbx4MceYPhMLNTKDTsTT
*/
"213.239.220.25:22 orport=443 id=BEE2317AE127EB681C5AE1551C1EA0630580638A"
" ipv6=[2a01:4f8:a0:710c::2]:80"
" weight=9490",
/*
kitten3
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 8640 / 704514 (1.226%)
0xEFB74277ECE4E222 Aeris <aeris+tor AT imirhil DOT fr> - 1aerisnnLWPchhDSXpxWGYWwLiSFUVFnd
*/
"212.47.237.95:9030 orport=9001 id=3F5D8A879C58961BB45A3D26AC41B543B40236D6"
" weight=8640",
/*
horizons
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 7860 / 704514 (1.116%)
kbesig@socal.rr.com
*/
"167.114.35.28:9030 orport=9001 id=E65D300F11E1DB12C534B0146BDAB6972F1A8A48"
" weight=7860",
/*
wagner
Flags: Fast Guard Running Stable V2Dir Valid
Fallback Weight: 7700 / 704514 (1.093%)
Rarely used email <trff914 AT gmail DOT com>
*/
"5.175.233.86:80 orport=443 id=5525D0429BFE5DC4F1B0E9DE47A4CFA169661E33"
" weight=7700",
/*
Unnamed
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 7650 / 704514 (1.086%)
monitor0penmailbox0rg
*/
"217.12.199.208:80 orport=443 id=DF3AED4322B1824BF5539AE54B2D1B38E080FF05"
" weight=7650",
/*
ratchet
Flags: Fast Guard HSDir Running Stable V2Dir Valid
Fallback Weight: 4450 / 704514 (0.632%)
0x1EB4B68F Sam Lanning <sam AT samlanning dot com>
*/
"170.130.1.7:9030 orport=9001 id=FA3415659444AE006E7E9E5375E82F29700CFDFD"
" weight=4450",
