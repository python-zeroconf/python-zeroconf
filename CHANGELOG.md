# CHANGELOG


## v0.140.1 (2025-01-17)

### Bug Fixes

* fix: wheel builds for aarch64 (#1485) ([`9d228e2`](https://github.com/python-zeroconf/python-zeroconf/commit/9d228e28eead1561deda696e8837d59896cbc98d))


## v0.140.0 (2025-01-17)

### Bug Fixes

* fix(docs): remove repetition of words (#1479)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`dde26c6`](https://github.com/python-zeroconf/python-zeroconf/commit/dde26c655a49811c11071b0531e408a188687009))

### Features

* feat: small performance improvement to writing outgoing packets (#1482) ([`d9be715`](https://github.com/python-zeroconf/python-zeroconf/commit/d9be7155a0ef1ac521e5bbedd3884ddeb9f0b99d))

* feat: migrate to native types (#1472)

Co-authored-by: J. Nick Koston <nick@koston.org>
Co-authored-by: pre-commit-ci[bot] <66853113+pre-commit-ci[bot]@users.noreply.github.com> ([`22a0fb4`](https://github.com/python-zeroconf/python-zeroconf/commit/22a0fb487db27bc2c6448a9167742f3040e910ba))


## v0.139.0 (2025-01-09)

### Features

* feat: implement heapq for tracking cache expire times (#1465) ([`09db184`](https://github.com/python-zeroconf/python-zeroconf/commit/09db1848957b34415f364b7338e4adce99b57abc))


## v0.138.1 (2025-01-08)

### Bug Fixes

* fix: ensure cache does not return stale created and ttl values (#1469) ([`e05055c`](https://github.com/python-zeroconf/python-zeroconf/commit/e05055c584ca46080990437b2b385a187bc48458))


## v0.138.0 (2025-01-08)

### Features

* feat: improve performance of processing incoming records (#1467)

Co-authored-by: pre-commit-ci[bot] <66853113+pre-commit-ci[bot]@users.noreply.github.com> ([`ebbb2af`](https://github.com/python-zeroconf/python-zeroconf/commit/ebbb2afccabd3841a3cb0a39824b49773cc6258a))


## v0.137.2 (2025-01-06)

### Bug Fixes

* fix: split wheel builds to avoid timeout (#1461) ([`be05f0d`](https://github.com/python-zeroconf/python-zeroconf/commit/be05f0dc4f6b2431606031a7bb24585728d15f01))


## v0.137.1 (2025-01-06)

### Bug Fixes

* fix: move wheel builds to macos-13 (#1459) ([`4ff48a0`](https://github.com/python-zeroconf/python-zeroconf/commit/4ff48a01bc76c82e5710aafaf6cf6e79c069cd85))


## v0.137.0 (2025-01-06)

### Features

* feat: speed up parsing incoming records (#1458) ([`783c1b3`](https://github.com/python-zeroconf/python-zeroconf/commit/783c1b37d1372c90dfce658c66d03aa753afbf49))


## v0.136.2 (2024-11-21)

### Bug Fixes

* fix: retrigger release from failed github workflow (#1443) ([`2ea705d`](https://github.com/python-zeroconf/python-zeroconf/commit/2ea705d850c1cb096c87372d5ec855f684603d01))


## v0.136.1 (2024-11-21)

### Bug Fixes

* fix(ci): run release workflow only on main repository (#1441) ([`f637c75`](https://github.com/python-zeroconf/python-zeroconf/commit/f637c75f638ba20c193e58ff63c073a4003430b9))

* fix(docs): update python to 3.8 (#1430) ([`483d067`](https://github.com/python-zeroconf/python-zeroconf/commit/483d0673d4ae3eec37840452723fc1839a6cc95c))


## v0.136.0 (2024-10-26)

### Bug Fixes

* fix: update python-semantic-release to fix release process (#1426) ([`2f20155`](https://github.com/python-zeroconf/python-zeroconf/commit/2f201558d0ab089cdfebb18d2d7bb5785b2cce16))

* fix: add ignore for .c file for wheels (#1424) ([`6535963`](https://github.com/python-zeroconf/python-zeroconf/commit/6535963b5b789ce445e77bb728a5b7ee4263e582))

* fix: correct typos (#1422) ([`3991b42`](https://github.com/python-zeroconf/python-zeroconf/commit/3991b4256b8de5b37db7a6144e5112f711b2efef))

### Features

* feat: use SPDX license identifier (#1425) ([`1596145`](https://github.com/python-zeroconf/python-zeroconf/commit/1596145452721e0de4e2a724b055e8e290792d3e))


## v0.135.0 (2024-09-24)

### Features

* feat: improve performance of DNSCache backend (#1415) ([`1df2e69`](https://github.com/python-zeroconf/python-zeroconf/commit/1df2e691ff11c9592e1cdad5599fb6601eb1aa3f))


## v0.134.0 (2024-09-08)

### Bug Fixes

* fix: improve helpfulness of ServiceInfo.request assertions (#1408) ([`9262626`](https://github.com/python-zeroconf/python-zeroconf/commit/9262626895d354ed7376aa567043b793c37a985e))

### Features

* feat: improve performance when IP addresses change frequently (#1407) ([`111c91a`](https://github.com/python-zeroconf/python-zeroconf/commit/111c91ab395a7520e477eb0e75d5924fba3c64c7))


## v0.133.0 (2024-08-27)

### Features

* feat: improve performance of ip address caching (#1392) ([`f7c7708`](https://github.com/python-zeroconf/python-zeroconf/commit/f7c77081b2f8c70b1ed6a9b9751a86cf91f9aae2))

* feat: enable building of arm64 macOS builds (#1384)

Co-authored-by: Alex Ciobanu <alex@rogue-research.com>
Co-authored-by: J. Nick Koston <nick@koston.org> ([`0df2ce0`](https://github.com/python-zeroconf/python-zeroconf/commit/0df2ce0e6f7313831da6a63d477019982d5df55c))

* feat: add classifier for python 3.13 (#1393) ([`7fb2bb2`](https://github.com/python-zeroconf/python-zeroconf/commit/7fb2bb21421c70db0eb288fa7e73d955f58b0f5d))

* feat: python 3.13 support (#1390) ([`98cfa83`](https://github.com/python-zeroconf/python-zeroconf/commit/98cfa83710e43880698353821bae61108b08cb2f))


## v0.132.2 (2024-04-13)

### Bug Fixes

* fix: update references to minimum-supported python version of 3.8 (#1369) ([`599524a`](https://github.com/python-zeroconf/python-zeroconf/commit/599524a5ce1e4c1731519dd89377c2a852e59935))

* fix: bump cibuildwheel to fix wheel builds (#1371) ([`83e4ce3`](https://github.com/python-zeroconf/python-zeroconf/commit/83e4ce3e31ddd4ae9aec2f8c9d84d7a93f8be210))


## v0.132.1 (2024-04-12)

### Bug Fixes

* fix: set change during iteration when dispatching listeners (#1370) ([`e9f8aa5`](https://github.com/python-zeroconf/python-zeroconf/commit/e9f8aa5741ae2d490c33a562b459f0af1014dbb0))


## v0.132.0 (2024-04-01)

### Bug Fixes

* fix: avoid including scope_id in IPv6Address object if its zero (#1367) ([`edc4a55`](https://github.com/python-zeroconf/python-zeroconf/commit/edc4a556819956c238a11332052000dcbcb07e3d))

### Features

* feat: make async_get_service_info available on the Zeroconf object (#1366) ([`c4c2dee`](https://github.com/python-zeroconf/python-zeroconf/commit/c4c2deeb05279ddbb0eba1330c7ae58795fea001))

* feat: drop python 3.7 support (#1359) ([`4877829`](https://github.com/python-zeroconf/python-zeroconf/commit/4877829e6442de5426db152d11827b1ba85dbf59))


## v0.131.0 (2023-12-19)

### Features

* feat: small speed up to constructing outgoing packets (#1354) ([`517d7d0`](https://github.com/python-zeroconf/python-zeroconf/commit/517d7d00ca7738c770077738125aec0e4824c000))

* feat: speed up processing incoming packets (#1352) ([`6c15325`](https://github.com/python-zeroconf/python-zeroconf/commit/6c153258a995cf9459a6f23267b7e379b5e2550f))

* feat: speed up the query handler (#1350) ([`9eac0a1`](https://github.com/python-zeroconf/python-zeroconf/commit/9eac0a122f28a7a4fa76cbfdda21d9a3571d7abb))


## v0.130.0 (2023-12-16)

### Bug Fixes

* fix: scheduling race with the QueryScheduler (#1347) ([`cf40470`](https://github.com/python-zeroconf/python-zeroconf/commit/cf40470b89f918d3c24d7889d3536f3ffa44846c))

* fix: ensure question history suppresses duplicates (#1338) ([`6f23656`](https://github.com/python-zeroconf/python-zeroconf/commit/6f23656576daa04e3de44e100f3ddd60ee4c560d))

* fix: microsecond precision loss in the query handler (#1339) ([`6560fad`](https://github.com/python-zeroconf/python-zeroconf/commit/6560fad584e0d392962c9a9248759f17c416620e))

* fix: ensure IPv6 scoped address construction uses the string cache (#1336) ([`f78a196`](https://github.com/python-zeroconf/python-zeroconf/commit/f78a196db632c4fe017a34f1af8a58903c15a575))

### Features

* feat: make ServiceInfo aware of question history (#1348) ([`b9aae1d`](https://github.com/python-zeroconf/python-zeroconf/commit/b9aae1de07bf1491e873bc314f8a1d7996127ad3))

* feat: small speed up to ServiceInfo construction (#1346) ([`b329d99`](https://github.com/python-zeroconf/python-zeroconf/commit/b329d99917bb731b4c70bf20c7c010eeb85ad9fd))

* feat: significantly improve efficiency of the ServiceBrowser scheduler (#1335) ([`c65d869`](https://github.com/python-zeroconf/python-zeroconf/commit/c65d869aec731b803484871e9d242a984f9f5848))

* feat: small speed up to processing incoming records (#1345) ([`7de655b`](https://github.com/python-zeroconf/python-zeroconf/commit/7de655b6f05012f20a3671e0bcdd44a1913d7b52))

* feat: small performance improvement for converting time (#1342) ([`73d3ab9`](https://github.com/python-zeroconf/python-zeroconf/commit/73d3ab90dd3b59caab771235dd6dbedf05bfe0b3))

* feat: small performance improvement for ServiceInfo asking questions (#1341) ([`810a309`](https://github.com/python-zeroconf/python-zeroconf/commit/810a3093c5a9411ee97740b468bd706bdf4a95de))

* feat: small performance improvement constructing outgoing questions (#1340) ([`157185f`](https://github.com/python-zeroconf/python-zeroconf/commit/157185f28bf1e83e6811e2a5cd1fa9b38966f780))


## v0.129.0 (2023-12-13)

### Features

* feat: add decoded_properties method to ServiceInfo (#1332) ([`9b595a1`](https://github.com/python-zeroconf/python-zeroconf/commit/9b595a1dcacf109c699953219d70fe36296c7318))

* feat: ensure ServiceInfo.properties always returns bytes (#1333) ([`d29553a`](https://github.com/python-zeroconf/python-zeroconf/commit/d29553ab7de6b7af70769ddb804fe2aaf492f320))

* feat: cache is_unspecified for zeroconf ip address objects (#1331) ([`a1c84dc`](https://github.com/python-zeroconf/python-zeroconf/commit/a1c84dc6adeebd155faec1a647c0f70d70de2945))


## v0.128.5 (2023-12-13)

### Bug Fixes

* fix: performance regression with ServiceInfo IPv6Addresses (#1330) ([`e2f9f81`](https://github.com/python-zeroconf/python-zeroconf/commit/e2f9f81dbc54c3dd527eeb3298897d63f99d33f4))


## v0.128.4 (2023-12-10)

### Bug Fixes

* fix: re-expose ServiceInfo._set_properties for backwards compat (#1327) ([`39c4005`](https://github.com/python-zeroconf/python-zeroconf/commit/39c40051d7a63bdc63a3e2dfa20bd944fee4e761))


## v0.128.3 (2023-12-10)

### Bug Fixes

* fix: correct nsec record writing (#1326) ([`cd7a16a`](https://github.com/python-zeroconf/python-zeroconf/commit/cd7a16a32c37b2f7a2e90d3c749525a5393bad57))


## v0.128.2 (2023-12-10)

### Bug Fixes

* fix: timestamps missing double precision (#1324) ([`ecea4e4`](https://github.com/python-zeroconf/python-zeroconf/commit/ecea4e4217892ca8cf763074ac3e5d1b898acd21))

* fix: match cython version for dev deps to build deps (#1325) ([`a0dac46`](https://github.com/python-zeroconf/python-zeroconf/commit/a0dac46c01202b3d5a0823ac1928fc1d75332522))


## v0.128.1 (2023-12-10)

### Bug Fixes

* fix: correct handling of IPv6 addresses with scope_id in ServiceInfo (#1322) ([`1682991`](https://github.com/python-zeroconf/python-zeroconf/commit/1682991b985b1f7b2bf0cff1a7eb7793070e7cb1))


## v0.128.0 (2023-12-02)

### Features

* feat: speed up unpacking TXT record data in ServiceInfo (#1318) ([`a200842`](https://github.com/python-zeroconf/python-zeroconf/commit/a20084281e66bdb9c37183a5eb992435f5b866ac))


## v0.127.0 (2023-11-15)

### Features

* feat: small speed up to writing outgoing packets (#1316) ([`cd28476`](https://github.com/python-zeroconf/python-zeroconf/commit/cd28476f6b0a6c2c733273fb24ddaac6c7bbdf65))

* feat: speed up incoming packet reader (#1314) ([`0d60b61`](https://github.com/python-zeroconf/python-zeroconf/commit/0d60b61538a5d4b6f44b2369333b6e916a0a55b4))

* feat: small speed up to processing incoming dns records (#1315) ([`bfe4c24`](https://github.com/python-zeroconf/python-zeroconf/commit/bfe4c24881a7259713425df5ab00ffe487518841))


## v0.126.0 (2023-11-13)

### Features

* feat: speed up outgoing packet writer (#1313) ([`55cf4cc`](https://github.com/python-zeroconf/python-zeroconf/commit/55cf4ccdff886a136db4e2133d3e6cdd001a8bd6))

* feat: speed up writing name compression for outgoing packets (#1312) ([`9caeabb`](https://github.com/python-zeroconf/python-zeroconf/commit/9caeabb6d4659a25ea1251c1ee7bb824e05f3d8b))


## v0.125.0 (2023-11-12)

### Features

* feat: speed up service browser queries when browsing many types (#1311) ([`d192d33`](https://github.com/python-zeroconf/python-zeroconf/commit/d192d33b1f05aa95a89965e86210aec086673a17))


## v0.124.0 (2023-11-12)

### Features

* feat: avoid decoding known answers if we have no answers to give (#1308) ([`605dc9c`](https://github.com/python-zeroconf/python-zeroconf/commit/605dc9ccd843a535802031f051b3d93310186ad1))

* feat: small speed up to process incoming packets (#1309) ([`56ef908`](https://github.com/python-zeroconf/python-zeroconf/commit/56ef90865189c01d2207abcc5e2efe3a7a022fa1))


## v0.123.0 (2023-11-12)

### Features

* feat: speed up instances only used to lookup answers (#1307) ([`0701b8a`](https://github.com/python-zeroconf/python-zeroconf/commit/0701b8ab6009891cbaddaa1d17116d31fd1b2f78))


## v0.122.3 (2023-11-09)

### Bug Fixes

* fix: do not build musllinux aarch64 wheels to reduce release time (#1306) ([`79aafb0`](https://github.com/python-zeroconf/python-zeroconf/commit/79aafb0acf7ca6b17976be7ede748008deada27b))


## v0.122.2 (2023-11-09)

### Bug Fixes

* fix: do not build aarch64 wheels for PyPy (#1305) ([`7e884db`](https://github.com/python-zeroconf/python-zeroconf/commit/7e884db4d958459e64257aba860dba2450db0687))


## v0.122.1 (2023-11-09)

### Bug Fixes

* fix: skip wheel builds for eol python and older python with aarch64 (#1304) ([`6c8f5a5`](https://github.com/python-zeroconf/python-zeroconf/commit/6c8f5a5dec2072aa6a8f889c5d8a4623ab392234))


## v0.122.0 (2023-11-08)

### Features

* feat: build aarch64 wheels (#1302) ([`4fe58e2`](https://github.com/python-zeroconf/python-zeroconf/commit/4fe58e2edc6da64a8ece0e2b16ec9ebfc5b3cd83))


## v0.121.0 (2023-11-08)

### Features

* feat: speed up record updates (#1301) ([`d2af6a0`](https://github.com/python-zeroconf/python-zeroconf/commit/d2af6a0978f5abe4f8bb70d3e29d9836d0fd77c4))


## v0.120.0 (2023-11-05)

### Features

* feat: speed up incoming packet processing with a memory view (#1290) ([`f1f0a25`](https://github.com/python-zeroconf/python-zeroconf/commit/f1f0a2504afd4d29bc6b7cf715cd3cb81b9049f7))

* feat: speed up decoding labels from incoming data (#1291) ([`c37ead4`](https://github.com/python-zeroconf/python-zeroconf/commit/c37ead4d7000607e81706a97b4cdffd80cf8cf99))

* feat: speed up ServiceBrowsers with a pxd for the signal interface (#1289) ([`8a17f20`](https://github.com/python-zeroconf/python-zeroconf/commit/8a17f2053a89db4beca9e8c1de4640faf27726b4))


## v0.119.0 (2023-10-18)

### Features

* feat: update cibuildwheel to build wheels on latest cython final release (#1285) ([`e8c9083`](https://github.com/python-zeroconf/python-zeroconf/commit/e8c9083bb118764a85b12fac9055152a2f62a212))


## v0.118.1 (2023-10-18)

### Bug Fixes

* fix: reduce size of wheels by excluding generated .c files (#1284) ([`b6afa4b`](https://github.com/python-zeroconf/python-zeroconf/commit/b6afa4b2775a1fdb090145eccdc5711c98e7147a))


## v0.118.0 (2023-10-14)

### Features

* feat: small improvements to ServiceBrowser performance (#1283) ([`0fc031b`](https://github.com/python-zeroconf/python-zeroconf/commit/0fc031b1e7bf1766d5a1d39d70d300b86e36715e))


## v0.117.0 (2023-10-14)

### Features

* feat: small cleanups to incoming data handlers (#1282) ([`4f4bd9f`](https://github.com/python-zeroconf/python-zeroconf/commit/4f4bd9ff7c1e575046e5ea213d9b8c91ac7a24a9))


## v0.116.0 (2023-10-13)

### Features

* feat: reduce type checking overhead at run time (#1281) ([`8f30099`](https://github.com/python-zeroconf/python-zeroconf/commit/8f300996e5bd4316b2237f0502791dd0d6a855fe))


## v0.115.2 (2023-10-05)

### Bug Fixes

* fix: ensure ServiceInfo cache is cleared when adding to the registry (#1279)

* There were production use cases that mutated the service info and re-registered it that need to be accounted for ([`2060eb2`](https://github.com/python-zeroconf/python-zeroconf/commit/2060eb2cc43489c34bea08924c3f40b875d5a498))


## v0.115.1 (2023-10-01)

### Bug Fixes

* fix: add missing python definition for addresses_by_version (#1278) ([`52ee02b`](https://github.com/python-zeroconf/python-zeroconf/commit/52ee02b16860e344c402124f4b2e2869536ec839))


## v0.115.0 (2023-09-26)

### Features

* feat: speed up outgoing multicast queue (#1277) ([`a13fd49`](https://github.com/python-zeroconf/python-zeroconf/commit/a13fd49d77474fd5858de809e48cbab1ccf89173))


## v0.114.0 (2023-09-25)

### Features

* feat: speed up responding to queries (#1275) ([`3c6b18c`](https://github.com/python-zeroconf/python-zeroconf/commit/3c6b18cdf4c94773ad6f4497df98feb337939ee9))


## v0.113.0 (2023-09-24)

### Features

* feat: improve performance of loading records from cache in ServiceInfo (#1274) ([`6257d49`](https://github.com/python-zeroconf/python-zeroconf/commit/6257d49952e02107f800f4ad4894716508edfcda))


## v0.112.0 (2023-09-14)

### Features

* feat: improve AsyncServiceBrowser performance (#1273) ([`0c88ecf`](https://github.com/python-zeroconf/python-zeroconf/commit/0c88ecf5ef6b9b256f991e7a630048de640999a6))


## v0.111.0 (2023-09-14)

### Features

* feat: speed up question and answer internals (#1272) ([`d24722b`](https://github.com/python-zeroconf/python-zeroconf/commit/d24722bfa4201d48ab482d35b0ef004f070ada80))


## v0.110.0 (2023-09-14)

### Features

* feat: small speed ups to ServiceBrowser (#1271) ([`22c433d`](https://github.com/python-zeroconf/python-zeroconf/commit/22c433ddaea3049ac49933325ba938fd87a529c0))


## v0.109.0 (2023-09-14)

### Features

* feat: speed up ServiceBrowsers with a cython pxd (#1270) ([`4837876`](https://github.com/python-zeroconf/python-zeroconf/commit/48378769c3887b5746ca00de30067a4c0851765c))


## v0.108.0 (2023-09-11)

### Features

* feat: improve performance of constructing outgoing queries (#1267) ([`00c439a`](https://github.com/python-zeroconf/python-zeroconf/commit/00c439a6400b7850ef9fdd75bc8d82d4e64b1da0))


## v0.107.0 (2023-09-11)

### Features

* feat: speed up responding to queries (#1266) ([`24a0a00`](https://github.com/python-zeroconf/python-zeroconf/commit/24a0a00b3e457979e279a2eeadc8fad2ab09e125))


## v0.106.0 (2023-09-11)

### Features

* feat: speed up answering questions (#1265) ([`37bfaf2`](https://github.com/python-zeroconf/python-zeroconf/commit/37bfaf2f630358e8c68652f3b3120931a6f94910))


## v0.105.0 (2023-09-10)

### Features

* feat: speed up ServiceInfo with a cython pxd (#1264) ([`7ca690a`](https://github.com/python-zeroconf/python-zeroconf/commit/7ca690ac3fa75e7474d3412944bbd5056cb313dd))


## v0.104.0 (2023-09-10)

### Features

* feat: speed up generating answers (#1262) ([`50a8f06`](https://github.com/python-zeroconf/python-zeroconf/commit/50a8f066b6ab90bc9e3300f81cf9332550b720df))


## v0.103.0 (2023-09-09)

### Features

* feat: avoid calling get_running_loop when resolving ServiceInfo (#1261) ([`33a2714`](https://github.com/python-zeroconf/python-zeroconf/commit/33a2714cadff96edf016b869cc63b0661d16ef2c))


## v0.102.0 (2023-09-07)

### Features

* feat: significantly speed up writing outgoing dns records (#1260) ([`bf2f366`](https://github.com/python-zeroconf/python-zeroconf/commit/bf2f3660a1f341e50ab0ae586dfbacbc5ddcc077))


## v0.101.0 (2023-09-07)

### Features

* feat: speed up writing outgoing dns records (#1259) ([`248655f`](https://github.com/python-zeroconf/python-zeroconf/commit/248655f0276223b089373c70ec13a0385dfaa4d6))


## v0.100.0 (2023-09-07)

### Features

* feat: small speed up to writing outgoing dns records (#1258) ([`1ed6bd2`](https://github.com/python-zeroconf/python-zeroconf/commit/1ed6bd2ec4db0612b71384f923ffff1efd3ce878))


## v0.99.0 (2023-09-06)

### Features

* feat: reduce IP Address parsing overhead in ServiceInfo (#1257) ([`83d0b7f`](https://github.com/python-zeroconf/python-zeroconf/commit/83d0b7fda2eb09c9c6e18b85f329d1ddc701e3fb))


## v0.98.0 (2023-09-06)

### Features

* feat: speed up decoding incoming packets (#1256) ([`ac081cf`](https://github.com/python-zeroconf/python-zeroconf/commit/ac081cf00addde1ceea2c076f73905fdb293de3a))


## v0.97.0 (2023-09-03)

### Features

* feat: speed up answering queries (#1255) ([`2d3aed3`](https://github.com/python-zeroconf/python-zeroconf/commit/2d3aed36e24c73013fcf4acc90803fc1737d0917))


## v0.96.0 (2023-09-03)

### Features

* feat: optimize DNSCache.get_by_details (#1254)

* feat: optimize DNSCache.get_by_details

This is one of the most called functions since ServiceInfo.load_from_cache calls
it

* fix: make get_all_by_details thread-safe

* fix: remove unneeded key checks ([`ce59787`](https://github.com/python-zeroconf/python-zeroconf/commit/ce59787a170781ffdaa22425018d288b395ac081))


## v0.95.0 (2023-09-03)

### Features

* feat: speed up adding and removing RecordUpdateListeners (#1253) ([`22e4a29`](https://github.com/python-zeroconf/python-zeroconf/commit/22e4a296d440b3038c0ff5ed6fc8878304ec4937))


## v0.94.0 (2023-09-03)

### Features

* feat: optimize cache implementation (#1252) ([`8d3ec79`](https://github.com/python-zeroconf/python-zeroconf/commit/8d3ec792277aaf7ef790318b5b35ab00839ca3b3))


## v0.93.1 (2023-09-03)

### Bug Fixes

* fix: no change re-release due to unrecoverable failed CI run (#1251) ([`730921b`](https://github.com/python-zeroconf/python-zeroconf/commit/730921b155dfb9c62251c8c643b1302e807aff3b))


## v0.93.0 (2023-09-02)

### Features

* feat: reduce overhead to answer questions (#1250) ([`7cb8da0`](https://github.com/python-zeroconf/python-zeroconf/commit/7cb8da0c6c5c944588009fe36012c1197c422668))


## v0.92.0 (2023-09-02)

### Features

* feat: cache construction of records used to answer queries from the service registry (#1243) ([`0890f62`](https://github.com/python-zeroconf/python-zeroconf/commit/0890f628dbbd577fb77d3e6f2e267052b2b2b515))


## v0.91.1 (2023-09-02)

### Bug Fixes

* fix: remove useless calls in ServiceInfo (#1248) ([`4e40fae`](https://github.com/python-zeroconf/python-zeroconf/commit/4e40fae20bf50b4608e28fad4a360c4ed48ac86b))


## v0.91.0 (2023-09-02)

### Features

* feat: reduce overhead to process incoming updates by avoiding the handle_response shim (#1247) ([`5e31f0a`](https://github.com/python-zeroconf/python-zeroconf/commit/5e31f0afe4c341fbdbbbe50348a829ea553cbda0))


## v0.90.0 (2023-09-02)

### Features

* feat: avoid python float conversion in listener hot path (#1245) ([`816ad4d`](https://github.com/python-zeroconf/python-zeroconf/commit/816ad4dceb3859bad4bb136bdb1d1ee2daa0bf5a))

### Refactoring

* refactor: reduce duplicate code in engine.py (#1246) ([`36ae505`](https://github.com/python-zeroconf/python-zeroconf/commit/36ae505dc9f95b59fdfb632960845a45ba8575b8))


## v0.89.0 (2023-09-02)

### Features

* feat: reduce overhead to process incoming questions (#1244) ([`18b65d1`](https://github.com/python-zeroconf/python-zeroconf/commit/18b65d1c75622869b0c29258215d3db3ae520d6c))


## v0.88.0 (2023-08-29)

### Features

* feat: speed up RecordManager with additional cython defs (#1242) ([`5a76fc5`](https://github.com/python-zeroconf/python-zeroconf/commit/5a76fc5ff74f2941ffbf7570e45390f35e0b7e01))


## v0.87.0 (2023-08-29)

### Features

* feat: improve performance by adding cython pxd for RecordManager (#1241) ([`a7dad3d`](https://github.com/python-zeroconf/python-zeroconf/commit/a7dad3d9743586f352e21eea1e129c6875f9a713))


## v0.86.0 (2023-08-28)

### Features

* feat: build wheels for cpython 3.12 (#1239) ([`58bc154`](https://github.com/python-zeroconf/python-zeroconf/commit/58bc154f55b06b4ddfc4a141592488abe76f062a))

* feat: use server_key when processing DNSService records (#1238) ([`cc8feb1`](https://github.com/python-zeroconf/python-zeroconf/commit/cc8feb110fefc3fb714fd482a52f16e2b620e8c4))


## v0.85.0 (2023-08-27)

### Features

* feat: simplify code to unpack properties (#1237) ([`68d9998`](https://github.com/python-zeroconf/python-zeroconf/commit/68d99985a0e9d2c72ff670b2e2af92271a6fe934))


## v0.84.0 (2023-08-27)

### Features

* feat: context managers in ServiceBrowser and AsyncServiceBrowser (#1233)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`bd8d846`](https://github.com/python-zeroconf/python-zeroconf/commit/bd8d8467dec2a39a0b525043ea1051259100fded))


## v0.83.1 (2023-08-27)

### Bug Fixes

* fix: rebuild wheels with cython 3.0.2 (#1236) ([`dd637fb`](https://github.com/python-zeroconf/python-zeroconf/commit/dd637fb2e5a87ba283750e69d116e124bef54e7c))


## v0.83.0 (2023-08-26)

### Features

* feat: speed up question and answer history with a cython pxd (#1234) ([`703ecb2`](https://github.com/python-zeroconf/python-zeroconf/commit/703ecb2901b2150fb72fac3deed61d7302561298))


## v0.82.1 (2023-08-22)

### Bug Fixes

* fix: build failures with older cython 0.29 series (#1232) ([`30c3ad9`](https://github.com/python-zeroconf/python-zeroconf/commit/30c3ad9d1bc6b589e1ca6675fea21907ebcd1ced))


## v0.82.0 (2023-08-22)

### Features

* feat: optimize processing of records in RecordUpdateListener subclasses (#1231) ([`3e89294`](https://github.com/python-zeroconf/python-zeroconf/commit/3e89294ea0ecee1122e1c1ffdc78925add8ca40e))


## v0.81.0 (2023-08-22)

### Features

* feat: speed up the service registry with a cython pxd (#1226) ([`47d3c7a`](https://github.com/python-zeroconf/python-zeroconf/commit/47d3c7ad4bc5f2247631c3ad5e6b6156d45a0a4e))

* feat: optimizing sending answers to questions (#1227) ([`cd7b56b`](https://github.com/python-zeroconf/python-zeroconf/commit/cd7b56b2aa0c8ee429da430e9a36abd515512011))


## v0.80.0 (2023-08-15)

### Features

* feat: optimize unpacking properties in ServiceInfo (#1225) ([`1492e41`](https://github.com/python-zeroconf/python-zeroconf/commit/1492e41b3d5cba5598cc9dd6bd2bc7d238f13555))


## v0.79.0 (2023-08-14)

### Features

* feat: refactor notify implementation to reduce overhead of adding and removing listeners (#1224) ([`ceb92cf`](https://github.com/python-zeroconf/python-zeroconf/commit/ceb92cfe42d885dbb38cee7aaeebf685d97627a9))


## v0.78.0 (2023-08-14)

### Features

* feat: add cython pxd file for _listener.py to improve incoming message processing performance (#1221) ([`f459856`](https://github.com/python-zeroconf/python-zeroconf/commit/f459856a0a61b8afa8a541926d7e15d51f8e4aea))


## v0.77.0 (2023-08-14)

### Features

* feat: cythonize _listener.py to improve incoming message processing performance (#1220) ([`9efde8c`](https://github.com/python-zeroconf/python-zeroconf/commit/9efde8c8c1ed14c5d3c162f185b49212fcfcb5c9))


## v0.76.0 (2023-08-14)

### Features

* feat: improve performance responding to queries (#1217) ([`69b33be`](https://github.com/python-zeroconf/python-zeroconf/commit/69b33be3b2f9d4a27ef5154cae94afca048efffa))


## v0.75.0 (2023-08-13)

### Features

* feat: expose flag to disable strict name checking in service registration (#1215) ([`5df8a57`](https://github.com/python-zeroconf/python-zeroconf/commit/5df8a57a14d59687a3c22ea8ee063e265031e278))

* feat: speed up processing incoming records (#1216) ([`aff625d`](https://github.com/python-zeroconf/python-zeroconf/commit/aff625dc6a5e816dad519644c4adac4f96980c04))


## v0.74.0 (2023-08-04)

### Bug Fixes

* fix: remove typing on reset_ttl for cython compat (#1213) ([`0094e26`](https://github.com/python-zeroconf/python-zeroconf/commit/0094e2684344c6b7edd7948924f093f1b4c19901))

### Features

* feat: speed up unpacking text records in ServiceInfo (#1212) ([`99a6f98`](https://github.com/python-zeroconf/python-zeroconf/commit/99a6f98e44a1287ba537eabb852b1b69923402f0))


## v0.73.0 (2023-08-03)

### Features

* feat: add a cache to service_type_name (#1211) ([`53a694f`](https://github.com/python-zeroconf/python-zeroconf/commit/53a694f60e675ae0560e727be6b721b401c2b68f))


## v0.72.3 (2023-08-03)

### Bug Fixes

* fix: revert adding typing to DNSRecord.suppressed_by (#1210) ([`3dba5ae`](https://github.com/python-zeroconf/python-zeroconf/commit/3dba5ae0c0e9473b7b20fd6fc79fa1a3b298dc5a))


## v0.72.2 (2023-08-03)

### Bug Fixes

* fix: revert DNSIncoming cimport in _dns.pxd (#1209) ([`5f14b6d`](https://github.com/python-zeroconf/python-zeroconf/commit/5f14b6dc687b3a0716d0ca7f61ccf1e93dfe5fa1))


## v0.72.1 (2023-08-03)

### Bug Fixes

* fix: race with InvalidStateError when async_request times out (#1208) ([`2233b6b`](https://github.com/python-zeroconf/python-zeroconf/commit/2233b6bc4ceeee5524d2ee88ecae8234173feb5f))


## v0.72.0 (2023-08-02)

### Features

* feat: speed up processing incoming records (#1206) ([`126849c`](https://github.com/python-zeroconf/python-zeroconf/commit/126849c92be8cec9253fba9faa591029d992fcc3))


## v0.71.5 (2023-08-02)

### Bug Fixes

* fix: improve performance of ServiceInfo.async_request (#1205) ([`8019a73`](https://github.com/python-zeroconf/python-zeroconf/commit/8019a73c952f2fc4c88d849aab970fafedb316d8))


## v0.71.4 (2023-07-24)

### Bug Fixes

* fix: cleanup naming from previous refactoring in ServiceInfo (#1202) ([`b272d75`](https://github.com/python-zeroconf/python-zeroconf/commit/b272d75abd982f3be1f4b20f683cac38011cc6f4))


## v0.71.3 (2023-07-23)

### Bug Fixes

* fix: pin python-semantic-release to fix release process (#1200) ([`c145a23`](https://github.com/python-zeroconf/python-zeroconf/commit/c145a238d768aa17c3aebe120c20a46bfbec6b99))


## v0.71.2 (2023-07-23)

### Bug Fixes

* fix: no change re-release to fix wheel builds (#1199) ([`8c3a4c8`](https://github.com/python-zeroconf/python-zeroconf/commit/8c3a4c80c221bea7401c12e1c6a525e75b7ffea2))


## v0.71.1 (2023-07-23)

### Bug Fixes

* fix: add missing if TYPE_CHECKING guard to generate_service_query (#1198) ([`ac53adf`](https://github.com/python-zeroconf/python-zeroconf/commit/ac53adf7e71db14c1a0f9adbfd1d74033df36898))


## v0.71.0 (2023-07-08)

### Features

* feat: improve incoming data processing performance (#1194) ([`a56c776`](https://github.com/python-zeroconf/python-zeroconf/commit/a56c776008ef86f99db78f5997e45a57551be725))


## v0.70.0 (2023-07-02)

### Features

* feat: add support for sending to a specific `addr` and `port` with `ServiceInfo.async_request` and `ServiceInfo.request` (#1192) ([`405f547`](https://github.com/python-zeroconf/python-zeroconf/commit/405f54762d3f61e97de9c1787e837e953de31412))


## v0.69.0 (2023-06-18)

### Features

* feat: cython3 support (#1190) ([`8ae8ba1`](https://github.com/python-zeroconf/python-zeroconf/commit/8ae8ba1af324b0c8c2da3bd12c264a5c0f3dcc3d))

* feat: reorder incoming data handler to reduce overhead (#1189) ([`32756ff`](https://github.com/python-zeroconf/python-zeroconf/commit/32756ff113f675b7a9cf16d3c0ab840ba733e5e4))


## v0.68.1 (2023-06-18)

### Bug Fixes

* fix: reduce debug logging overhead by adding missing checks to datagram_received (#1188) ([`ac5c50a`](https://github.com/python-zeroconf/python-zeroconf/commit/ac5c50afc70aaa33fcd20bf02222ff4f0c596fa3))


## v0.68.0 (2023-06-17)

### Features

* feat: reduce overhead to handle queries and responses (#1184)

- adds slots to handler classes

- avoid any expression overhead and inline instead ([`81126b7`](https://github.com/python-zeroconf/python-zeroconf/commit/81126b7600f94848ef8c58b70bac0c6ab993c6ae))


## v0.67.0 (2023-06-17)

### Features

* feat: speed up answering incoming questions (#1186) ([`8f37665`](https://github.com/python-zeroconf/python-zeroconf/commit/8f376658d2a3bef0353646e6fddfda15626b73a9))


## v0.66.0 (2023-06-13)

### Features

* feat: optimize construction of outgoing dns records (#1182) ([`fc0341f`](https://github.com/python-zeroconf/python-zeroconf/commit/fc0341f281cdb71428c0f1cf90c12d34cbb4acae))


## v0.65.0 (2023-06-13)

### Features

* feat: reduce overhead to enumerate ip addresses in ServiceInfo (#1181) ([`6a85cbf`](https://github.com/python-zeroconf/python-zeroconf/commit/6a85cbf2b872cb0abd184c2dd728d9ae3eb8115c))


## v0.64.1 (2023-06-05)

### Bug Fixes

* fix: small internal typing cleanups (#1180) ([`f03e511`](https://github.com/python-zeroconf/python-zeroconf/commit/f03e511f7aae72c5ccd4f7514d89e168847bd7a2))


## v0.64.0 (2023-06-05)

### Bug Fixes

* fix: always answer QU questions when the exact same packet is received from different sources in sequence (#1178)

If the exact same packet with a QU question is asked from two different sources in a 1s window we end up ignoring the second one as a duplicate. We should still respond in this case because the client wants a unicast response and the question may not be answered by the previous packet since the response may not be multicast.

fix: include NSEC records in initial broadcast when registering a new service

This also revealed that we do not send NSEC records in the initial broadcast. This needed to be fixed in this PR as well for everything to work as expected since all the tests would fail with 2 updates otherwise. ([`74d7ba1`](https://github.com/python-zeroconf/python-zeroconf/commit/74d7ba1aeeae56be087ee8142ee6ca1219744baa))

### Features

* feat: speed up processing incoming records (#1179) ([`d919316`](https://github.com/python-zeroconf/python-zeroconf/commit/d9193160b05beeca3755e19fd377ba13fe37b071))


## v0.63.0 (2023-05-25)

### Features

* feat: small speed up to fetch dns addresses from ServiceInfo (#1176) ([`4deaa6e`](https://github.com/python-zeroconf/python-zeroconf/commit/4deaa6ed7c9161db55bf16ec068ab7260bbd4976))

* feat: speed up the service registry (#1174) ([`360ceb2`](https://github.com/python-zeroconf/python-zeroconf/commit/360ceb2548c4c4974ff798aac43a6fff9803ea0e))

* feat: improve dns cache performance (#1172) ([`bb496a1`](https://github.com/python-zeroconf/python-zeroconf/commit/bb496a1dd5fa3562c0412cb064d14639a542592e))


## v0.62.0 (2023-05-04)

### Features

* feat: improve performance of ServiceBrowser outgoing query scheduler (#1170) ([`963d022`](https://github.com/python-zeroconf/python-zeroconf/commit/963d022ef82b615540fa7521d164a98a6c6f5209))


## v0.61.0 (2023-05-03)

### Features

* feat: speed up parsing NSEC records (#1169) ([`06fa94d`](https://github.com/python-zeroconf/python-zeroconf/commit/06fa94d87b4f0451cb475a921ce1d8e9562e0f26))


## v0.60.0 (2023-05-01)

### Features

* feat: speed up processing incoming data (#1167) ([`fbaaf7b`](https://github.com/python-zeroconf/python-zeroconf/commit/fbaaf7bb6ff985bdabb85feb6cba144f12d4f1d6))


## v0.59.0 (2023-05-01)

### Features

* feat: speed up decoding dns questions when processing incoming data (#1168) ([`f927190`](https://github.com/python-zeroconf/python-zeroconf/commit/f927190cb24f70fd7c825c6e12151fcc0daf3973))


## v0.58.2 (2023-04-26)

### Bug Fixes

* fix: re-release to rebuild failed wheels (#1165) ([`4986271`](https://github.com/python-zeroconf/python-zeroconf/commit/498627166a4976f1d9d8cd1f3654b0d50272d266))


## v0.58.1 (2023-04-26)

### Bug Fixes

* fix: reduce cast calls in service browser (#1164) ([`c0d65ae`](https://github.com/python-zeroconf/python-zeroconf/commit/c0d65aeae7037a18ed1149336f5e7bdb8b2dd8cf))


## v0.58.0 (2023-04-23)

### Features

* feat: speed up incoming parser (#1163) ([`4626399`](https://github.com/python-zeroconf/python-zeroconf/commit/46263999c0c7ea5176885f1eadd2c8498834b70e))


## v0.57.0 (2023-04-23)

### Features

* feat: speed up incoming data parser (#1161) ([`cb4c3b2`](https://github.com/python-zeroconf/python-zeroconf/commit/cb4c3b2b80ca3b88b8de6e87062a45e03e8805a6))


## v0.56.0 (2023-04-07)

### Features

* feat: reduce denial of service protection overhead (#1157) ([`2c2f26a`](https://github.com/python-zeroconf/python-zeroconf/commit/2c2f26a87d0aac81a77205b06bc9ba499caa2321))


## v0.55.0 (2023-04-07)

### Features

* feat: improve performance of processing incoming records (#1155) ([`b65e279`](https://github.com/python-zeroconf/python-zeroconf/commit/b65e2792751c44e0fafe9ad3a55dadc5d8ee9d46))


## v0.54.0 (2023-04-03)

### Features

* feat: avoid waking async_request when record updates are not relevant (#1153) ([`a3f970c`](https://github.com/python-zeroconf/python-zeroconf/commit/a3f970c7f66067cf2c302c49ed6ad8286f19b679))


## v0.53.1 (2023-04-03)

### Bug Fixes

* fix: addresses incorrect after server name change (#1154) ([`41ea06a`](https://github.com/python-zeroconf/python-zeroconf/commit/41ea06a0192c0d186e678009285759eb37d880d5))


## v0.53.0 (2023-04-02)

### Bug Fixes

* fix: make parsed_scoped_addresses return addresses in the same order as all other methods (#1150) ([`9b6adcf`](https://github.com/python-zeroconf/python-zeroconf/commit/9b6adcf5c04a469632ee866c32f5898c5cbf810a))

### Features

* feat: improve ServiceBrowser performance by removing OrderedDict (#1148) ([`9a16be5`](https://github.com/python-zeroconf/python-zeroconf/commit/9a16be56a9f69a5d0f7cde13dc1337b6d93c1433))


## v0.52.0 (2023-04-02)

### Features

* feat: small cleanups to cache cleanup interval (#1146) ([`b434b60`](https://github.com/python-zeroconf/python-zeroconf/commit/b434b60f14ebe8f114b7b19bb4f54081c8ae0173))

* feat: add ip_addresses_by_version to ServiceInfo (#1145) ([`524494e`](https://github.com/python-zeroconf/python-zeroconf/commit/524494edd49bd049726b19ae8ac8f6eea69a3943))

* feat: speed up processing records in the ServiceBrowser (#1143) ([`6a327d0`](https://github.com/python-zeroconf/python-zeroconf/commit/6a327d00ffb81de55b7c5b599893c789996680c1))

* feat: speed up matching types in the ServiceBrowser (#1144) ([`68871c3`](https://github.com/python-zeroconf/python-zeroconf/commit/68871c3b5569e41740a66b7d3d7fa5cc41514ea5))

* feat: include tests and docs in sdist archives (#1142)

feat: Include tests and docs in sdist archives

Include documentation and test files in source distributions, in order
to make them more useful for packagers (Linux distributions, Conda).
Testing is an important part of packaging process, and at least Gentoo
users have requested offline documentation for Python packages.
Furthermore, the COPYING file was missing from sdist, even though it was
referenced in README. ([`da10a3b`](https://github.com/python-zeroconf/python-zeroconf/commit/da10a3b2827cee0719d3bb9152ae897f061c6e2e))


## v0.51.0 (2023-04-01)

### Features

* feat: improve performance of constructing ServiceInfo (#1141) ([`36d5b45`](https://github.com/python-zeroconf/python-zeroconf/commit/36d5b45a4ece1dca902e9c3c79b5a63b8d9ae41f))


## v0.50.0 (2023-04-01)

### Features

* feat: small speed up to handler dispatch (#1140) ([`5bd1b6e`](https://github.com/python-zeroconf/python-zeroconf/commit/5bd1b6e7b4dd796069461c737ded956305096307))


## v0.49.0 (2023-04-01)

### Features

* feat: speed up processing incoming records (#1139) ([`7246a34`](https://github.com/python-zeroconf/python-zeroconf/commit/7246a344b6c0543871b40715c95c9435db4c7f81))


## v0.48.0 (2023-04-01)

### Features

* feat: reduce overhead to send responses (#1135) ([`c4077dd`](https://github.com/python-zeroconf/python-zeroconf/commit/c4077dde6dfde9e2598eb63daa03c36063a3e7b0))


## v0.47.4 (2023-03-20)

### Bug Fixes

* fix: correct duplicate record entries in windows wheels by updating poetry-core (#1134) ([`a43055d`](https://github.com/python-zeroconf/python-zeroconf/commit/a43055d3fa258cd762c3e9394b01f8bdcb24f97e))


## v0.47.3 (2023-02-14)

### Bug Fixes

* fix: hold a strong reference to the query sender start task (#1128) ([`808c3b2`](https://github.com/python-zeroconf/python-zeroconf/commit/808c3b2194a7f499a469a9893102d328ccee83db))


## v0.47.2 (2023-02-14)

### Bug Fixes

* fix: missing c extensions with newer poetry (#1129) ([`44d7fc6`](https://github.com/python-zeroconf/python-zeroconf/commit/44d7fc6483485102f60c91d591d0d697872f8865))


## v0.47.1 (2022-12-24)

### Bug Fixes

* fix: the equality checks for DNSPointer and DNSService should be case insensitive (#1122) ([`48ae77f`](https://github.com/python-zeroconf/python-zeroconf/commit/48ae77f026a96e2ca475b0ff80cb6d22207ce52f))


## v0.47.0 (2022-12-22)

### Features

* feat: optimize equality checks for DNS records (#1120) ([`3a25ff7`](https://github.com/python-zeroconf/python-zeroconf/commit/3a25ff74bea83cd7d50888ce1ebfd7650d704bfa))


## v0.46.0 (2022-12-21)

### Features

* feat: optimize the dns cache (#1119) ([`e80fcef`](https://github.com/python-zeroconf/python-zeroconf/commit/e80fcef967024f8e846e44b464a82a25f5550edf))


## v0.45.0 (2022-12-20)

### Features

* feat: optimize construction of outgoing packets (#1118) ([`81e186d`](https://github.com/python-zeroconf/python-zeroconf/commit/81e186d365c018381f9b486a4dbe4e2e4b8bacbf))


## v0.44.0 (2022-12-18)

### Features

* feat: optimize dns objects by adding pxd files (#1113) ([`919d4d8`](https://github.com/python-zeroconf/python-zeroconf/commit/919d4d875747b4fa68e25bccd5aae7f304d8a36d))


## v0.43.0 (2022-12-18)

### Features

* feat: optimize incoming parser by reducing call stack (#1116) ([`11f3f0e`](https://github.com/python-zeroconf/python-zeroconf/commit/11f3f0e699e00c1ee3d6d8ab5e30f62525510589))


## v0.42.0 (2022-12-18)

### Features

* feat: optimize incoming parser by using unpack_from (#1115) ([`a7d50ba`](https://github.com/python-zeroconf/python-zeroconf/commit/a7d50baab362eadd2d292df08a39de6836b41ea7))


## v0.41.0 (2022-12-18)

### Features

* feat: optimize incoming parser by adding pxd files (#1111) ([`26efeb0`](https://github.com/python-zeroconf/python-zeroconf/commit/26efeb09783050266242542228f34eb4dd83e30c))


## v0.40.1 (2022-12-18)

### Bug Fixes

* fix: fix project name in pyproject.toml (#1112) ([`a330f62`](https://github.com/python-zeroconf/python-zeroconf/commit/a330f62040475257c4a983044e1675aeb95e030a))


## v0.40.0 (2022-12-17)

### Features

* feat: drop async_timeout requirement for python 3.11+ (#1107) ([`1f4224e`](https://github.com/python-zeroconf/python-zeroconf/commit/1f4224ef122299235013cb81b501f8ff9a30dea1))


## v0.39.5 (2022-12-17)

### Unknown

* 0.39.5 ([`2be6fbf`](https://github.com/python-zeroconf/python-zeroconf/commit/2be6fbfe3d10b185096814d2d0de322733d273cf))


## v0.39.4 (2022-10-31)

### Unknown

* Bump version: 0.39.3 → 0.39.4 ([`e620f2a`](https://github.com/python-zeroconf/python-zeroconf/commit/e620f2a1d4f381feb99b639c6ab17845396ba7ea))

* Update changelog for 0.39.4 (#1103) ([`03821b6`](https://github.com/python-zeroconf/python-zeroconf/commit/03821b6f4d9fdc40d94d1070f69553649d18909b))

* Fix IP changes being missed by ServiceInfo (#1102) ([`524ae89`](https://github.com/python-zeroconf/python-zeroconf/commit/524ae89966d9300e78642a91434ad55643277a48))


## v0.39.3 (2022-10-26)

### Unknown

* Bump version: 0.39.2 → 0.39.3 ([`aee3165`](https://github.com/python-zeroconf/python-zeroconf/commit/aee316539b0778eaf2b8878f78d9ead373760cfb))

* Update changelog for 0.39.3 (#1101) ([`39c9842`](https://github.com/python-zeroconf/python-zeroconf/commit/39c9842b80ac7d978e8c7ffef0ad836b3b4700f6))

* Fix port changes not being seen by ServiceInfo (#1100) ([`c96f5f6`](https://github.com/python-zeroconf/python-zeroconf/commit/c96f5f69d8e68672bb6760b1e40a0de51b62efd6))

* Update CI to use released python 3.11 (#1099) ([`6976980`](https://github.com/python-zeroconf/python-zeroconf/commit/6976980b4874dd65ee533d43be57694bb3b7d0fc))


## v0.39.2 (2022-10-20)

### Unknown

* Bump version: 0.39.1 → 0.39.2 ([`785e475`](https://github.com/python-zeroconf/python-zeroconf/commit/785e475467225ddc4930d5302f130781223fd298))

* Update changelog for 0.39.2 (#1098) ([`b197344`](https://github.com/python-zeroconf/python-zeroconf/commit/b19734484b4c5eebb86fe6897a26ad082b07bed5))

* Improve cache of decode labels at offset (#1097) ([`d3c475f`](https://github.com/python-zeroconf/python-zeroconf/commit/d3c475f3e2590ae5a3056d85c29a66dc71ae3bdf))

* Only reprocess address records if the server changes (#1095) ([`0989336`](https://github.com/python-zeroconf/python-zeroconf/commit/0989336d79bc4dd0ef3b26e8d0f9529fca81c1fb))

* Prepare for python 3.11 support by adding rc2 to the CI (#1085) ([`7430ce1`](https://github.com/python-zeroconf/python-zeroconf/commit/7430ce1c462be0dd210712b4f7b3675efd3a6963))


## v0.39.1 (2022-09-05)

### Unknown

* Bump version: 0.39.0 → 0.39.1 ([`6f90896`](https://github.com/python-zeroconf/python-zeroconf/commit/6f90896a590d6d60db75688a1ba753c333c8faab))

* Update changelog for 0.39.1 (#1091) ([`cad3963`](https://github.com/python-zeroconf/python-zeroconf/commit/cad3963e566a7bb2dd188088c11e7a0abb6b3924))

* Replace pack with to_bytes (#1090) ([`5968b76`](https://github.com/python-zeroconf/python-zeroconf/commit/5968b76ac2ffe6e41b8961c59bdcc5a48ba410eb))


## v0.39.0 (2022-08-05)

### Unknown

* Bump version: 0.38.7 → 0.39.0 ([`60167b0`](https://github.com/python-zeroconf/python-zeroconf/commit/60167b05227ec33668aac5b960a8bc5ba5b833de))

* 0.39.0 changelog (#1087) ([`946890a`](https://github.com/python-zeroconf/python-zeroconf/commit/946890aca540bbae95abe8a6ffe66db56fa9e986))

* Remove coveralls from dev requirements (#1086) ([`087914d`](https://github.com/python-zeroconf/python-zeroconf/commit/087914da2e914275dd0fff1e4466b3c51ae0c6d3))

* Fix run_coro_with_timeout test not running in the CI (#1082) ([`b7a24fe`](https://github.com/python-zeroconf/python-zeroconf/commit/b7a24fef05fc6c166b25cfd4235e59c5cbb96a4c))

* Fix flakey service_browser_expire_callbacks test (#1084) ([`d5032b7`](https://github.com/python-zeroconf/python-zeroconf/commit/d5032b70b6ebc5c221a43f778f4d897a1d891f91))

* Fix flakey test_sending_unicast on windows (#1083) ([`389658d`](https://github.com/python-zeroconf/python-zeroconf/commit/389658d998a23deecd96023794d3672e51189a35))

* Replace wait_event_or_timeout internals with async_timeout (#1081)

Its unlikely that https://bugs.python.org/issue39032 and
https://github.com/python/cpython/issues/83213 will be fixed
soon. While we moved away from an asyncio.Condition, we still
has a similar problem with waiting for an asyncio.Event which
wait_event_or_timeout played well with. async_timeout avoids
creating a task so its a bit more efficient. Since we call
these when resolving ServiceInfo, avoiding task creation
will resolve a performance problem when ServiceBrowsers
startup as they tend to create task storms when coupled
with ServiceInfo lookups. ([`7ffea9f`](https://github.com/python-zeroconf/python-zeroconf/commit/7ffea9f93e758f75a0eeb9997ff8d9c9d47ec31a))

* Update stale docstrings in AsyncZeroconf (#1079) ([`88323d0`](https://github.com/python-zeroconf/python-zeroconf/commit/88323d0c7866f78edde063080c63a72c6e875772))


## v0.38.7 (2022-06-14)

### Unknown

* Bump version: 0.38.6 → 0.38.7 ([`f3a9f80`](https://github.com/python-zeroconf/python-zeroconf/commit/f3a9f804914fec37e961f80f347c4e706c4bae33))

* Update changelog for 0.38.7 (#1078) ([`5f7ba0d`](https://github.com/python-zeroconf/python-zeroconf/commit/5f7ba0d7dc9a5a6b2cf3a321b7b2f448d4332de9))

* Speed up unpacking incoming packet data (#1076) ([`533ad10`](https://github.com/python-zeroconf/python-zeroconf/commit/533ad10121739997a4925d90792cbe9e00a5ac4f))


## v0.38.6 (2022-05-06)

### Unknown

* Bump version: 0.38.5 → 0.38.6 ([`1aa7842`](https://github.com/python-zeroconf/python-zeroconf/commit/1aa7842ae0f914c10465ae977551698046406d55))

* Update changelog for 0.38.6 (#1073) ([`dfd3222`](https://github.com/python-zeroconf/python-zeroconf/commit/dfd3222405f0123a849d376d8be466be46bdb557))

* Always return `started` as False once Zeroconf has been marked as done (#1072) ([`ed02e5d`](https://github.com/python-zeroconf/python-zeroconf/commit/ed02e5d92768d1fc41163f59e303a76843bfd9fd))

* Avoid waking up ServiceInfo listeners when there is no new data (#1068) ([`59624a6`](https://github.com/python-zeroconf/python-zeroconf/commit/59624a6cfb1839b2654a6021a7317a1bdad179e9))

* Remove left-in debug print (#1071) ([`5fb0954`](https://github.com/python-zeroconf/python-zeroconf/commit/5fb0954cf2c6040704c3db1d2b0fece389425e5b))

* Use unique name in test_service_browser_expire_callbacks test (#1069) ([`89c9022`](https://github.com/python-zeroconf/python-zeroconf/commit/89c9022f87d3a83cc586b153fb7d5ea3af69ae3b))

* Fix CI failures (#1070) ([`f9b2816`](https://github.com/python-zeroconf/python-zeroconf/commit/f9b2816e15b0459f8051079f77b70e983769cd44))


## v0.38.5 (2022-05-01)

### Unknown

* Bump version: 0.38.4 → 0.38.5 ([`3c55388`](https://github.com/python-zeroconf/python-zeroconf/commit/3c5538899b8974e99c9a279ce3ac46971ab5d91c))

* Update changelog for 0.38.5 (#1066) ([`ae3635b`](https://github.com/python-zeroconf/python-zeroconf/commit/ae3635b9ee73edeaabe2cbc027b8fb8bd7cd97da))

* Fix ServiceBrowsers not getting `ServiceStateChange.Removed` callbacks on PTR record expire (#1064) ([`10ee205`](https://github.com/python-zeroconf/python-zeroconf/commit/10ee2053a80f7c7221b4fa1475d66b01abd21b11))

* Fix ci trying to run mypy on pypy (#1065) ([`31662b7`](https://github.com/python-zeroconf/python-zeroconf/commit/31662b7a0bba65bea1fbfc09c70cd2970160c5c6))

* Force minimum version of 3.7 and update example (#1060)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`6e842f2`](https://github.com/python-zeroconf/python-zeroconf/commit/6e842f238b3e1f3b738ed058e0fa4068115f041b))

* Fix mypy error in zeroconf._service.info (#1062) ([`e9d25f7`](https://github.com/python-zeroconf/python-zeroconf/commit/e9d25f7749778979b7449464153163587583bf8d))

* Refactor to fix mypy error (#1061) ([`6c451f6`](https://github.com/python-zeroconf/python-zeroconf/commit/6c451f64e7cbeaa0bb77f66790936afda2d058ef))


## v0.38.4 (2022-02-28)

### Unknown

* Bump version: 0.38.3 → 0.38.4 ([`5c40e89`](https://github.com/python-zeroconf/python-zeroconf/commit/5c40e89420255b5b978bff4682b21f0820fb4682))

* Update changelog for 0.38.4 (#1058) ([`3736348`](https://github.com/python-zeroconf/python-zeroconf/commit/3736348da30ee4b7c50713936f2ae919e5446ffa))

* Fix IP Address updates when hostname is uppercase (#1057) ([`79d067b`](https://github.com/python-zeroconf/python-zeroconf/commit/79d067b88f9108259a44f33801e26bd3a25ca759))


## v0.38.3 (2022-01-31)

### Unknown

* Bump version: 0.38.2 → 0.38.3 ([`e42549c`](https://github.com/python-zeroconf/python-zeroconf/commit/e42549cb70796d0577c97be96a09bca0056a5755))

* Update changelog for 0.38.2/3 (#1053) ([`d99c7ff`](https://github.com/python-zeroconf/python-zeroconf/commit/d99c7ffea37fd27c315115133dab08445aa417d1))


## v0.38.2 (2022-01-31)

### Unknown

* Bump version: 0.38.1 → 0.38.2 ([`50cd12d`](https://github.com/python-zeroconf/python-zeroconf/commit/50cd12d8c2ced166da8f4852120ba8a28b13cba0))

* Make decode errors more helpful in finding the source of the bad data (#1052) ([`25e6123`](https://github.com/python-zeroconf/python-zeroconf/commit/25e6123a07a9560e978a04d5e285bfa74ee41e64))


## v0.38.1 (2021-12-23)

### Unknown

* Bump version: 0.38.0 → 0.38.1 ([`6a11f24`](https://github.com/python-zeroconf/python-zeroconf/commit/6a11f24e1fc9d73f0dbb62efd834f17a9bd451c4))

* Update changelog for 0.38.1 (#1045) ([`670d4ac`](https://github.com/python-zeroconf/python-zeroconf/commit/670d4ac3be7e32d02afe85b72264a241b5a25ba8))

* Avoid linear type searches in ServiceBrowsers (#1044) ([`ff76634`](https://github.com/python-zeroconf/python-zeroconf/commit/ff766345461a82547abe462b5d690621c755d480))

* Improve performance of query scheduler (#1043) ([`27e50ff`](https://github.com/python-zeroconf/python-zeroconf/commit/27e50ff95625d128f71864138b8e5d871503adf0))


## v0.38.0 (2021-12-23)

### Unknown

* Bump version: 0.37.0 → 0.38.0 ([`95ee5dc`](https://github.com/python-zeroconf/python-zeroconf/commit/95ee5dc031c9c512f99536186d1d89a99e4af37f))

* Update changelog for 0.38.0 (#1042) ([`de14202`](https://github.com/python-zeroconf/python-zeroconf/commit/de1420213cd7e3bd8f57e727ff1031c7b10cf7a0))

* Handle Service types that end with another service type (#1041)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`a4d619a`](https://github.com/python-zeroconf/python-zeroconf/commit/a4d619a9f094682d9dcfc7f8fa293f17bcae88f2))

* Add tests for instance names containing dot(s) (#1039)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`22ed08c`](https://github.com/python-zeroconf/python-zeroconf/commit/22ed08c7e5403a788b1c177a1bb9558419bce2b1))

* Drop python 3.6 support (#1009) ([`631a6f7`](https://github.com/python-zeroconf/python-zeroconf/commit/631a6f7c7863897336a9d6ca4bd1736cc7cc97af))


## v0.37.0 (2021-11-18)

### Unknown

* Bump version: 0.36.13 → 0.37.0 ([`2996e64`](https://github.com/python-zeroconf/python-zeroconf/commit/2996e642f6b1abba1dbb8242ccca4cd4b96696f6))

* Update changelog for 0.37.0 (#1035) ([`61a7e3f`](https://github.com/python-zeroconf/python-zeroconf/commit/61a7e3fb65d99db7d51f1df42b286b55710a2e99))

* Log an error when listeners are added that do not inherit from RecordUpdateListener (#1034) ([`ee071a1`](https://github.com/python-zeroconf/python-zeroconf/commit/ee071a12f31f7010110eef5ccef80c6cdf469d87))

* Throw NotRunningException when Zeroconf is not running (#1033)

- Before this change the consumer would get a timeout or an EventLoopBlocked
  exception when calling `ServiceInfo.*request` when the instance had already been shutdown.
  This was quite a confusing result. ([`28938d2`](https://github.com/python-zeroconf/python-zeroconf/commit/28938d20bb62ae0d9aa2f94929f60434fb346704))

* Throw EventLoopBlocked instead of concurrent.futures.TimeoutError (#1032) ([`21bd107`](https://github.com/python-zeroconf/python-zeroconf/commit/21bd10762a89ca3f4ca89f598c9d93684a02f51b))


## v0.36.13 (2021-11-13)

### Unknown

* Bump version: 0.36.12 → 0.36.13 ([`4241c76`](https://github.com/python-zeroconf/python-zeroconf/commit/4241c76550130469aecbe88cc1a7cdc13505f8ba))

* Update changelog for 0.36.13 (#1030) ([`106cf27`](https://github.com/python-zeroconf/python-zeroconf/commit/106cf27478bb0c1e6e5a7194661ff52947d61c96))

* Downgrade incoming corrupt packet logging to debug (#1029)

- Warning about network traffic we have no control over
  is confusing to users as they think there is
  something wrong with zeroconf ([`73c52d0`](https://github.com/python-zeroconf/python-zeroconf/commit/73c52d04a140bc744669777a0f353eefc6623ff9))

* Skip unavailable interfaces during socket bind (#1028)

- We already skip these when adding multicast members.
  Apply the same logic to the socket bind call ([`aa59998`](https://github.com/python-zeroconf/python-zeroconf/commit/aa59998182ce29c55f8c3dde9a058ce36ac2bb2d))


## v0.36.12 (2021-11-05)

### Unknown

* Bump version: 0.36.11 → 0.36.12 ([`8b0dc48`](https://github.com/python-zeroconf/python-zeroconf/commit/8b0dc48ed42d8edc78750122eb5685a50c3cdc11))

* Update changelog for 0.36.12 (#1027) ([`51bf364`](https://github.com/python-zeroconf/python-zeroconf/commit/51bf364b364ecaad16503df4a4c4c3bb5ead2775))

* Account for intricacies of floating-point arithmetic in service browser tests (#1026) ([`3c70808`](https://github.com/python-zeroconf/python-zeroconf/commit/3c708080b3e42a02930ad17c96a2cf0dcb06f441))

* Prevent service lookups from deadlocking if time abruptly moves backwards (#1006)

- The typical reason time moves backwards is via an ntp update ([`38380a5`](https://github.com/python-zeroconf/python-zeroconf/commit/38380a58a64f563f105cecc610f194c20056b2b6))


## v0.36.11 (2021-10-30)

### Unknown

* Bump version: 0.36.10 → 0.36.11 ([`3d8f50d`](https://github.com/python-zeroconf/python-zeroconf/commit/3d8f50de74f7b3941d9b35b6ae6e42ba02be9361))

* Update changelog for 0.36.11 (#1024) ([`69a9b8e`](https://github.com/python-zeroconf/python-zeroconf/commit/69a9b8e060ae8a596050d393c0a5c8b43beadc8e))

* Add readme check to the CI (#1023) ([`c966976`](https://github.com/python-zeroconf/python-zeroconf/commit/c966976531ac9222460763d647d0a3b75459e275))


## v0.36.10 (2021-10-30)

### Unknown

* Bump version: 0.36.9 → 0.36.10 ([`e0b340a`](https://github.com/python-zeroconf/python-zeroconf/commit/e0b340afbfd25ae9d05a59a577938b062287c8b6))

* Update changelog for 0.36.10 (#1021) ([`69ce817`](https://github.com/python-zeroconf/python-zeroconf/commit/69ce817a68d65f2db0bfe6d4790d3a6a356ac83f))

* Fix test failure when has_working_ipv6 generates an exception (#1022) ([`cd8984d`](https://github.com/python-zeroconf/python-zeroconf/commit/cd8984d3e95bffe6fd32b97eae9844bf5afed4de))

* Strip scope_id from IPv6 address if given. (#1020) ([`686febd`](https://github.com/python-zeroconf/python-zeroconf/commit/686febdd181c837fa6a41afce91edeeded731fbe))

* Optimize decoding labels from incoming packets (#1019)

- decode is a bit faster vs str()

```
>>> ts = Timer("s.decode('utf-8', 'replace')", "s = b'TV Beneden (2)\x10_androidtvremote\x04_tcp\x05local'")
>>> ts.timeit()
0.09910525000003645
>>> ts = Timer("str(s, 'utf-8', 'replace')", "s = b'TV Beneden (2)\x10_androidtvremote\x04_tcp\x05local'")
>>> ts.timeit()
0.1304596250000145
``` ([`4b9a6c3`](https://github.com/python-zeroconf/python-zeroconf/commit/4b9a6c3fd4aec920597e7e63e82e935df68804f4))

* Fix typo in changelog (#1017) ([`0fdcd51`](https://github.com/python-zeroconf/python-zeroconf/commit/0fdcd5146264b37daa7cc35bda883519175e362f))


## v0.36.9 (2021-10-22)

### Unknown

* Bump version: 0.36.8 → 0.36.9 ([`d92d3d0`](https://github.com/python-zeroconf/python-zeroconf/commit/d92d3d030558c1b81b2e35f701b585f4b48fa99a))

* Update changelog for 0.36.9 (#1016) ([`1427ba7`](https://github.com/python-zeroconf/python-zeroconf/commit/1427ba75a8f7e2962aa0b3105d3c856002134790))

* Ensure ServiceInfo orders newest addresess first (#1012) ([`87a4d8f`](https://github.com/python-zeroconf/python-zeroconf/commit/87a4d8f4d5c8365425c2ee969032205f916f80c1))


## v0.36.8 (2021-10-10)

### Unknown

* Bump version: 0.36.7 → 0.36.8 ([`61275ef`](https://github.com/python-zeroconf/python-zeroconf/commit/61275efd05688a61d656b43125b01a5d588f1dba))

* Update changelog for 0.36.8 (#1010) ([`1551618`](https://github.com/python-zeroconf/python-zeroconf/commit/15516188f346c70f64a923bb587804b9bf948873))

* Fix ServiceBrowser infinite looping when zeroconf is closed before its canceled (#1008) ([`b0e8c8a`](https://github.com/python-zeroconf/python-zeroconf/commit/b0e8c8a21fd721e60adbac4dbf7a03959fc3f641))

* Update CI to use python 3.10, pypy 3.7 (#1007) ([`fec9f3d`](https://github.com/python-zeroconf/python-zeroconf/commit/fec9f3dc9626be08eccdf1263dbf4d1686fd27b2))

* Cleanup typing in zeroconf._protocol.outgoing (#1000) ([`543558d`](https://github.com/python-zeroconf/python-zeroconf/commit/543558d0498ed03eb9dc4597c4c40484e16ee4e6))

* Breakout functions with no self-use in zeroconf._handlers (#1003) ([`af4d082`](https://github.com/python-zeroconf/python-zeroconf/commit/af4d082240a545ba3014eb7f1056c3b32ce2cb70))

* Use more f-strings in zeroconf._dns (#1002) ([`d3ed691`](https://github.com/python-zeroconf/python-zeroconf/commit/d3ed69107330f1a29f45d174caafdec1e894f666))

* Remove unused code in zeroconf._core (#1001)

- Breakout functions without self-use ([`8e45ea9`](https://github.com/python-zeroconf/python-zeroconf/commit/8e45ea943be6490b2217f0eb01501e12a5221c16))


## v0.36.7 (2021-09-22)

### Unknown

* Bump version: 0.36.6 → 0.36.7 ([`f44b40e`](https://github.com/python-zeroconf/python-zeroconf/commit/f44b40e26ea8872151ea9ee4762b95ca25790089))

* Update changelog for 0.36.7 (#999) ([`d2853c3`](https://github.com/python-zeroconf/python-zeroconf/commit/d2853c31db9ece28fb258c4146ba61cf0e6a6592))

* Improve log message when receiving an invalid or corrupt packet (#998) ([`b637846`](https://github.com/python-zeroconf/python-zeroconf/commit/b637846e7df3292d6dcdd38a8eb77b6fa3287c51))

* Reduce logging overhead (#994) ([`7df7e4a`](https://github.com/python-zeroconf/python-zeroconf/commit/7df7e4a68e33c3e3a5bddf0168e248a4542a788f))

* Reduce overhead to compare dns records (#997) ([`7fa51de`](https://github.com/python-zeroconf/python-zeroconf/commit/7fa51de5b71d03470643a83004b9f6f8d4017214))

* Refactor service registry to avoid use of getattr (#996) ([`7622365`](https://github.com/python-zeroconf/python-zeroconf/commit/762236547d4838f2b6a94cfa20221dfdd03e9b94))

* Flush CI cache (#995) ([`93ddf7c`](https://github.com/python-zeroconf/python-zeroconf/commit/93ddf7cf9b47d7ff1e341b6c2875254b6f00eef1))


## v0.36.6 (2021-09-19)

### Unknown

* Bump version: 0.36.5 → 0.36.6 ([`0327a06`](https://github.com/python-zeroconf/python-zeroconf/commit/0327a068250c85f3ff84d3f0b809b51f83321c47))

* Fix tense of 0.36.6 changelog (#992) ([`29f995f`](https://github.com/python-zeroconf/python-zeroconf/commit/29f995fd3c09604f37980e74f2785b1a451da089))

* Update changelog for 0.36.6 (#991) ([`92f5f4a`](https://github.com/python-zeroconf/python-zeroconf/commit/92f5f4a80b8a8e50df5ca06e3cc45480dc39b504))

* Simplify the can_send_to check (#990) ([`1887c55`](https://github.com/python-zeroconf/python-zeroconf/commit/1887c554b3f9d0b90a1c01798d7f06a7e4de6900))


## v0.36.5 (2021-09-18)

### Unknown

* Bump version: 0.36.4 → 0.36.5 ([`34f4a26`](https://github.com/python-zeroconf/python-zeroconf/commit/34f4a26c9254d6002bdccb1a003d9822a8798c04))

* Update changelog for 0.36.5 (#989) ([`aebabe9`](https://github.com/python-zeroconf/python-zeroconf/commit/aebabe95c59e34f703307340e087b3eab5339a06))

* Seperate zeroconf._protocol into an incoming and outgoing modules (#988) ([`87b6a32`](https://github.com/python-zeroconf/python-zeroconf/commit/87b6a32fb77d9bdcea9d2d7ffba189abc5371b50))

* Reduce dns protocol attributes and add slots (#987) ([`f4665fc`](https://github.com/python-zeroconf/python-zeroconf/commit/f4665fc67cd762c4ab66271a550d75640d3bffca))

* Fix typo in changelog (#986) ([`4398538`](https://github.com/python-zeroconf/python-zeroconf/commit/43985380b9e995d9790d71486aed258326ad86e4))


## v0.36.4 (2021-09-16)

### Unknown

* Bump version: 0.36.3 → 0.36.4 ([`a23f6d2`](https://github.com/python-zeroconf/python-zeroconf/commit/a23f6d2cc40ea696410c3c31b73760065c36f0bf))

* Update changelog for 0.36.4 (#985) ([`f4d4164`](https://github.com/python-zeroconf/python-zeroconf/commit/f4d4164989931adbac0e5907b7bf276da1d0d7d7))

* Defer decoding known answers until needed (#983) ([`88b9875`](https://github.com/python-zeroconf/python-zeroconf/commit/88b987551cb98757c2df2540ba390f320d46fa7b))

* Collapse _GLOBAL_DONE into done (#984) ([`05c4329`](https://github.com/python-zeroconf/python-zeroconf/commit/05c4329d7647c381783ead086c2ed4f3b6b44262))

* Remove flake8 requirement restriction as its no longer needed (#981) ([`bc64d63`](https://github.com/python-zeroconf/python-zeroconf/commit/bc64d63ef73e643e71634957fd79e6f6597373d4))

* Reduce duplicate code to write records (#979) ([`acf6457`](https://github.com/python-zeroconf/python-zeroconf/commit/acf6457b3c6742c92e9112b0a39a387b33cea4db))

* Force CI cache clear (#982) ([`d9ea918`](https://github.com/python-zeroconf/python-zeroconf/commit/d9ea9189def07531d126e01c7397b2596d9a8695))

* Reduce name compression overhead and complexity (#978) ([`f1d6fc3`](https://github.com/python-zeroconf/python-zeroconf/commit/f1d6fc3f60e685ff63b1a1cb820cfc3ca5268fcb))


## v0.36.3 (2021-09-14)

### Unknown

* Bump version: 0.36.2 → 0.36.3 ([`769b397`](https://github.com/python-zeroconf/python-zeroconf/commit/769b3973835ebc6f5a34e236a01cb2cd935e81de))

* Update changelog for 0.36.3 (#977) ([`84f16bf`](https://github.com/python-zeroconf/python-zeroconf/commit/84f16bff6df41f1907e060e7bd4ce24d173d51c4))

* Reduce DNSIncoming parsing overhead (#975)

- Parsing incoming packets is the most expensive operation
  zeroconf performs on networks with high mDNS volume ([`78f9cd5`](https://github.com/python-zeroconf/python-zeroconf/commit/78f9cd5123d0e3c582aba05bd61388419d4dc01e))


## v0.36.2 (2021-08-30)

### Unknown

* Bump version: 0.36.1 → 0.36.2 ([`5f52438`](https://github.com/python-zeroconf/python-zeroconf/commit/5f52438f4c0851bb1a3b78575c0c28e0b6ce561d))

* Update changelog for 0.36.2 (#973) ([`b4efa33`](https://github.com/python-zeroconf/python-zeroconf/commit/b4efa33b4ef6d5292d8d477da4258d99d22c4e84))

* Include NSEC records for non-existant types when responding with addresses (#972)

Implements datatracker.ietf.org/doc/html/rfc6762#section-6.2 ([`7a20fd3`](https://github.com/python-zeroconf/python-zeroconf/commit/7a20fd3bc8dc0a703619ca9413faf674b3d7a111))

* Add support for writing NSEC records (#971) ([`768a23c`](https://github.com/python-zeroconf/python-zeroconf/commit/768a23c656e3f091ecbecbb6b380b5becbbf9674))


## v0.36.1 (2021-08-29)

### Unknown

* Bump version: 0.36.0 → 0.36.1 ([`e8d8401`](https://github.com/python-zeroconf/python-zeroconf/commit/e8d84017b750ab5f159abc7225f9922d84a8f9fd))

* Update changelog for 0.36.1 (#970) ([`d504333`](https://github.com/python-zeroconf/python-zeroconf/commit/d5043337de39a11b2b241e9247a34c41c0c7c2bc))

* Skip goodbye packets for addresses when there is another service registered with the same name (#968) ([`d9d3208`](https://github.com/python-zeroconf/python-zeroconf/commit/d9d3208eed84b71b61c458f2992b08b5db259da1))

* Fix equality and hash for dns records with the unique bit (#969) ([`574e241`](https://github.com/python-zeroconf/python-zeroconf/commit/574e24125a536dc4fb9a1784797efd495ceb1fdf))


## v0.36.0 (2021-08-16)

### Unknown

* Bump version: 0.35.1 → 0.36.0 ([`e4985c7`](https://github.com/python-zeroconf/python-zeroconf/commit/e4985c7dd2088d4da9fc2be25f67beb65f548e95))

* Update changelog for 0.36.0 (#966) ([`bc50bce`](https://github.com/python-zeroconf/python-zeroconf/commit/bc50bce04b650756fef3f8b1cce6defbc5dccee5))

* Create full IPv6 address tuple to enable service discovery on Windows (#965) ([`733eb3a`](https://github.com/python-zeroconf/python-zeroconf/commit/733eb3a31ed40c976f5fa4b7b3baf055589ef36b))


## v0.35.1 (2021-08-15)

### Unknown

* Bump version: 0.35.0 → 0.35.1 ([`4281221`](https://github.com/python-zeroconf/python-zeroconf/commit/4281221b668123b770c6d6b0835dd876d1d2f22d))

* Fix formatting in 0.35.1 changelog entry (#964) ([`c7c7d47`](https://github.com/python-zeroconf/python-zeroconf/commit/c7c7d4778e9962af5180616af73977d8503e4762))

* Update changelog for 0.35.1 (#963) ([`f7bebfe`](https://github.com/python-zeroconf/python-zeroconf/commit/f7bebfe09aeb9bb973dbe6ba147b682472b64246))

* Cache DNS record and question hashes (#960) ([`d4c109c`](https://github.com/python-zeroconf/python-zeroconf/commit/d4c109c3abffcba2331a7f9e7bf45c6477a8d4e8))

* Fix flakey test: test_future_answers_are_removed_on_send (#962) ([`3b482e2`](https://github.com/python-zeroconf/python-zeroconf/commit/3b482e229d37b85e59765e023ddbca77aa513731))

* Add coverage for sending answers removes future queued answers (#961)

- If we send an answer that is queued to be sent out in the future
  we should remove it from the queue as the question has already
  been answered and we do not want to generate additional traffic. ([`2d1b832`](https://github.com/python-zeroconf/python-zeroconf/commit/2d1b8329ad39b94f9f4aa5f53caf3bb2813879ca))

* Only reschedule types if the send next time changes (#958)

- When the PTR response was seen again, the timer was being canceled and
  rescheduled even if the timer was for the same time. While this did
  not cause any breakage, it is quite inefficient. ([`7b125a1`](https://github.com/python-zeroconf/python-zeroconf/commit/7b125a1a0a109ef29d0a4e736a27645a7e9b4207))


## v0.35.0 (2021-08-13)

### Unknown

* Bump version: 0.34.3 → 0.35.0 ([`1e60e13`](https://github.com/python-zeroconf/python-zeroconf/commit/1e60e13ae15a5b533a48cc955b98951eedd04dbb))

* Update changelog for 0.35.0 (#957) ([`dd40437`](https://github.com/python-zeroconf/python-zeroconf/commit/dd40437f4328f4ee36c43239ecf5f484b6ac261e))

* Reduce chance of accidental synchronization of ServiceInfo requests (#955) ([`c772936`](https://github.com/python-zeroconf/python-zeroconf/commit/c77293692062ea701037e06c1cf5497f019ae2f2))

* Send unicast replies on the same socket the query was received (#952)

When replying to a QU question, we do not know if the sending host is reachable
from all of the sending sockets. We now avoid this problem by replying via
the receiving socket. This was the existing behavior when `InterfaceChoice.Default`
is set.

This change extends the unicast relay behavior to used with `InterfaceChoice.Default`
to apply when `InterfaceChoice.All` or interfaces are explicitly passed when
instantiating a `Zeroconf` instance.

Fixes #951 ([`5fb3e20`](https://github.com/python-zeroconf/python-zeroconf/commit/5fb3e202c06e3a0d30e3c7824397d8e8a9f52555))

* Sort responses to increase chance of name compression (#954)

- When building an outgoing response, sort the names together
  to increase the likelihood of name compression. In testing
  this reduced the number of packets for large responses
  (from 7 packets to 6) ([`ebc23ee`](https://github.com/python-zeroconf/python-zeroconf/commit/ebc23ee5e9592dd7f0235cd57f9b3ad727ec8bff))


## v0.34.3 (2021-08-09)

### Unknown

* Bump version: 0.34.2 → 0.34.3 ([`9d69d18`](https://github.com/python-zeroconf/python-zeroconf/commit/9d69d18713bdfab53762a6b8c3aff7fd72ebd025))

* Update changelog for 0.34.3 (#950) ([`23b00e9`](https://github.com/python-zeroconf/python-zeroconf/commit/23b00e983b2e8335431dcc074935f379fd399d46))

* Fix sending immediate multicast responses (#949)

- Fixes a typo in handle_assembled_query that prevented immediate
  responses from being sent. ([`02af7f7`](https://github.com/python-zeroconf/python-zeroconf/commit/02af7f78d2e5eabcc5cce8238546ee5170951b28))


## v0.34.2 (2021-08-09)

### Unknown

* Bump version: 0.34.1 → 0.34.2 ([`6c21f68`](https://github.com/python-zeroconf/python-zeroconf/commit/6c21f6802b58d949038e9c8501ea204eeda57a16))

* Update changelog for 0.34.2 (#947) ([`b87f493`](https://github.com/python-zeroconf/python-zeroconf/commit/b87f4934b39af02f26bbbfd6f372c7154fe95906))

* Ensure ServiceInfo requests can be answered with the default timeout with network protection (#946)

- Adjust the time windows to ensure responses that have triggered the
protection against against excessive packet flooding due to
software bugs or malicious attack described in RFC6762 section 6
can respond in under 1350ms to ensure ServiceInfo can ask two
questions within the default timeout of 3000ms ([`6d7266d`](https://github.com/python-zeroconf/python-zeroconf/commit/6d7266d0e1e6dcb950456da0354b4c43fd5c0ecb))

* Coalesce aggregated multicast answers when the random delay is shorter than the last scheduled response (#945)

- Reduces traffic when we already know we will be sending a group of answers
  inside the random delay window described in
  https://datatracker.ietf.org/doc/html/rfc6762#section-6.3

closes #944 ([`9a5164a`](https://github.com/python-zeroconf/python-zeroconf/commit/9a5164a7a3231903537231bfb56479e617355f92))


## v0.34.1 (2021-08-08)

### Unknown

* Bump version: 0.34.0 → 0.34.1 ([`7878a9e`](https://github.com/python-zeroconf/python-zeroconf/commit/7878a9eed93a8ec2396d8450389a08bf54bd5693))

* Update changelog for 0.34.1 (#943) ([`9942484`](https://github.com/python-zeroconf/python-zeroconf/commit/9942484172d7a79fe84c47924538c2c02fde7264))

* Ensure multicast aggregation sends responses within 620ms (#942) ([`de96e2b`](https://github.com/python-zeroconf/python-zeroconf/commit/de96e2bf01af68d754bb7c71da949e30de88a77b))


## v0.34.0 (2021-08-08)

### Unknown

* Bump version: 0.33.4 → 0.34.0 ([`549ac3d`](https://github.com/python-zeroconf/python-zeroconf/commit/549ac3de27eb3924cc7967088c3d316184722b9d))

* Update changelog for 0.34.0 (#941) ([`342532e`](https://github.com/python-zeroconf/python-zeroconf/commit/342532e1d13ac24673735dc467a79edebdfb9362))

* Implement Multicast Response Aggregation (#940)

- Responses are now aggregated when possible per rules in RFC6762 section 6.4
- Responses that trigger the protection against against excessive packet flooding due to
   software bugs or malicious attack described in RFC6762 section 6 are delayed instead of discarding as it was causing responders that implement Passive Observation Of Failures (POOF) to evict the records. 
- Probe responses are now always sent immediately as there were cases where they would fail to be answered in time to defend a name.

closes #939 ([`55efb41`](https://github.com/python-zeroconf/python-zeroconf/commit/55efb4169b588cef093f3065f3a894878ae8bd95))


## v0.33.4 (2021-08-06)

### Unknown

* Bump version: 0.33.3 → 0.33.4 ([`7bbacd5`](https://github.com/python-zeroconf/python-zeroconf/commit/7bbacd57a134c12ee1fb61d8318b312dfdae18f8))

* Update changelog for 0.33.4 (#937) ([`858605d`](https://github.com/python-zeroconf/python-zeroconf/commit/858605db52f909d41198df76130597ff93f64cdd))

* Ensure zeroconf can be loaded when the system disables IPv6 (#933)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`496ac44`](https://github.com/python-zeroconf/python-zeroconf/commit/496ac44e99b56485cc9197490e71bb2dd7bec6f9))


## v0.33.3 (2021-08-05)

### Unknown

* Bump version: 0.33.2 → 0.33.3 ([`206671a`](https://github.com/python-zeroconf/python-zeroconf/commit/206671a1237ee8237d302b04c5a84158fed1d50b))

* Update changelog for 0.33.3 (#936) ([`6a140cc`](https://github.com/python-zeroconf/python-zeroconf/commit/6a140cc6b9c7e50e572456662d2f76f6fbc2ed25))

* Add support for forward dns compression pointers (#934)

- nslookup supports these and some implementations (likely avahi)
  will generate them

- Careful attention was given to make sure we detect loops
  and do not create anti-patterns described in
  https://github.com/Forescout/namewreck/blob/main/rfc/draft-dashevskyi-dnsrr-antipatterns-00.txt

Fixes https://github.com/home-assistant/core/issues/53937
Fixes https://github.com/home-assistant/core/issues/46985
Fixes https://github.com/home-assistant/core/issues/53668
Fixes #308 ([`5682a4c`](https://github.com/python-zeroconf/python-zeroconf/commit/5682a4c3c89043bf8a10e79232933ada5ab71972))

* Provide sockname when logging a protocol error (#935) ([`319992b`](https://github.com/python-zeroconf/python-zeroconf/commit/319992bb093d9b965976bad724512d9bcd05aca7))


## v0.33.2 (2021-07-28)

### Unknown

* Bump version: 0.33.1 → 0.33.2 ([`4d30c25`](https://github.com/python-zeroconf/python-zeroconf/commit/4d30c25fe57425bcae36a539006e44941ef46e2c))

* Update changelog for 0.33.2 (#931) ([`c80b5f7`](https://github.com/python-zeroconf/python-zeroconf/commit/c80b5f7253e521928d6f7e54681675be59371c6c))

* Handle duplicate goodbye answers in the same packet (#928)

- Solves an exception being thrown when we tried to remove the known answer
  from the cache when the second goodbye answer in the same packet was processed

- We previously swallowed all exceptions on cache removal so this was not
  visible until 0.32.x which removed the broad exception catch

Fixes #926 ([`97e0b66`](https://github.com/python-zeroconf/python-zeroconf/commit/97e0b669be60f716e45e963f1bcfcd35b7213626))

* Skip ipv6 interfaces that return ENODEV (#930) ([`73e3d18`](https://github.com/python-zeroconf/python-zeroconf/commit/73e3d1865f4167e7c9f7c23ec4cc7ebfac40f512))

* Remove some pylint workarounds (#925) ([`1247acd`](https://github.com/python-zeroconf/python-zeroconf/commit/1247acd2e6f6154a4e5f2e27a820c55329391d8e))


## v0.33.1 (2021-07-18)

### Unknown

* Bump version: 0.33.0 → 0.33.1 ([`6774de3`](https://github.com/python-zeroconf/python-zeroconf/commit/6774de3e7f8b461ccb83675bbb05d47949df487b))

* Update changelog for 0.33.1 (#924)

- Fixes overly restrictive directory permissions reported in #923 ([`ed80333`](https://github.com/python-zeroconf/python-zeroconf/commit/ed80333896c0710857cc46b5af4d7ba3a81e07c8))


## v0.33.0 (2021-07-18)

### Unknown

* Bump version: 0.32.1 → 0.33.0 ([`cfb28aa`](https://github.com/python-zeroconf/python-zeroconf/commit/cfb28aaf134e566d8a89b397967d1ad1ec66de35))

* Update changelog for 0.33.0 release (#922) ([`e4a9655`](https://github.com/python-zeroconf/python-zeroconf/commit/e4a96550398c408c3e1e6944662cc3093db912a7))

* Fix examples/async_registration.py attaching to the correct loop (#921) ([`b0b23f9`](https://github.com/python-zeroconf/python-zeroconf/commit/b0b23f96d3b33a627a0d071557a36af97a65dae4))

* Add support for bump2version (#920) ([`2e00002`](https://github.com/python-zeroconf/python-zeroconf/commit/2e0000252f0aecad8b62a649128326a6528b6824))

* Update changelog for 0.33.0 release (#919) ([`96be961`](https://github.com/python-zeroconf/python-zeroconf/commit/96be9618ede3c941e23cb23398b9aed11bed1ffa))

* Let connection_lost close the underlying socket (#918)

- The socket was closed during shutdown before asyncio's connection_lost
  handler had a chance to close it which resulted in a traceback on
  win32.

- Fixes #917 ([`919b096`](https://github.com/python-zeroconf/python-zeroconf/commit/919b096d6260a4f9f4306b9b4dddb5b026b49462))

* Reduce complexity of DNSRecord (#915)

- Use constants for calculations in is_expired/is_stale/is_recent ([`b6eaf72`](https://github.com/python-zeroconf/python-zeroconf/commit/b6eaf7249f386f573b0876204ccfdfa02ee9ac5b))

* Remove Zeroconf.wait as its now unused in the codebase (#914) ([`aa71084`](https://github.com/python-zeroconf/python-zeroconf/commit/aa7108481235cc018600d096b093c785447d8769))

* Switch periodic cleanup task to call_later (#913)

- Simplifies AsyncEngine to avoid the long running
  task ([`38eb271`](https://github.com/python-zeroconf/python-zeroconf/commit/38eb271c952e89260ecac6fac3e723f4206c4648))

* Update changelog for 0.33.0 (#912) ([`b2a7a00`](https://github.com/python-zeroconf/python-zeroconf/commit/b2a7a00f82d401066166776cecf0857ebbdb56ad))

* Remove locking from ServiceRegistry (#911)

- All calls to the ServiceRegistry are now done in async context
  which makes them thread safe. Locking is no longer needed. ([`2d3da7a`](https://github.com/python-zeroconf/python-zeroconf/commit/2d3da7a77699f88bd90ebc09d36b333690385f85))

* Remove duplicate unregister_all_services code (#910) ([`e63ca51`](https://github.com/python-zeroconf/python-zeroconf/commit/e63ca518c91cda7b9f460436aee4fdac1a7b9567))

* Rename DNSNsec.next to DNSNsec.next_name (#908) ([`69942d5`](https://github.com/python-zeroconf/python-zeroconf/commit/69942d5bfb4d92c6a312aea7c17f63fce0401e23))

* Upgrade syntax to python 3.6 (#907) ([`0578731`](https://github.com/python-zeroconf/python-zeroconf/commit/057873128ff05a0b2d6eae07510e23d705d10bae))

* Implement NSEC record parsing (#903)

- This is needed for negative responses
  https://datatracker.ietf.org/doc/html/rfc6762#section-6.1 ([`bc9e9cf`](https://github.com/python-zeroconf/python-zeroconf/commit/bc9e9cf8a5b997ca924730ed091a829f4f961ca3))

* Centralize running coroutines from threads (#906)

- Cleanup to ensure all coros we run from a thread
  use _LOADED_SYSTEM_TIMEOUT ([`9399c57`](https://github.com/python-zeroconf/python-zeroconf/commit/9399c57bb2b280c7b433e7fbea7cca2c2f4417ee))

* Reduce duplicate code between zeroconf.asyncio and zeroconf._core (#904) ([`e417fc0`](https://github.com/python-zeroconf/python-zeroconf/commit/e417fc0f5ed7eaa47a0dcaffdbc6fe335bfcc058))

* Disable N818 in flake8 (#905)

- We cannot rename these exceptions now without a breaking change
  as they have existed for many years ([`f8af0fb`](https://github.com/python-zeroconf/python-zeroconf/commit/f8af0fb251938dcb410127b2af2b8b407989aa08))


## v0.32.1 (2021-07-05)

### Unknown

* Release version 0.32.1 ([`675fd6f`](https://github.com/python-zeroconf/python-zeroconf/commit/675fd6fc959e76e4e3690e5c7a02db269ca9ef60))

* Fix the changelog's one sentence's tense ([`fc089be`](https://github.com/python-zeroconf/python-zeroconf/commit/fc089be1f412d991f44daeecd0944198d3a638a5))

* Update changelog (#899) ([`a93301d`](https://github.com/python-zeroconf/python-zeroconf/commit/a93301d0fd493bf18147187bf8efed1a4ea02214))

* Increase timeout in ServiceInfo.request to handle loaded systems (#895)

It can take a few seconds for a loaded system to run the `async_request` coroutine when the event loop is busy or the system is CPU bound (example being Home Assistant startup).  We now add
an additional `_LOADED_SYSTEM_TIMEOUT` (10s) to the `run_coroutine_threadsafe` calls to ensure the coroutine has the total amount of time to run up to its internal timeout (default of 3000ms). 

Ten seconds is a bit large of a timeout; however, its only unused in cases where we wrap other timeouts. We now expect the only instance the `run_coroutine_threadsafe` result timeout will happen in a production circumstance is when someone is running a `ServiceInfo.request()` in a thread and another thread calls `Zeroconf.close()` at just the right moment that the future is never completed unless the system is so loaded that it is nearly unresponsive.

The timeout for `run_coroutine_threadsafe` is the maximum time a thread can cleanly shut down when zeroconf is closed out in another thread, which should always be longer than the underlying thread operation. ([`56c7d69`](https://github.com/python-zeroconf/python-zeroconf/commit/56c7d692d67b7f56c386a7f1f4e45ebfc4e8366a))

* Add test for running sync code within executor (#894) ([`90bc8ca`](https://github.com/python-zeroconf/python-zeroconf/commit/90bc8ca8dce1af26ea81c5d6ecb17cf6ea664a71))


## v0.32.0 (2021-06-30)

### Unknown

* Fix readme formatting

It wasn't proper reStructuredText before:

    % twine check dist/*
    Checking dist/zeroconf-0.32.0-py3-none-any.whl: FAILED
      `long_description` has syntax errors in markup and would not be rendered on PyPI.
        line 381: Error: Unknown target name: "async".
      warning: `long_description_content_type` missing. defaulting to `text/x-rst`.
    Checking dist/zeroconf-0.32.0.tar.gz: FAILED
      `long_description` has syntax errors in markup and would not be rendered on PyPI.
        line 381: Error: Unknown target name: "async".
      warning: `long_description_content_type` missing. defaulting to `text/x-rst`. ([`82ff150`](https://github.com/python-zeroconf/python-zeroconf/commit/82ff150e0a72a7e20823a0c805f48f117bf1e274))

* Release version 0.32.0 ([`ea7bc85`](https://github.com/python-zeroconf/python-zeroconf/commit/ea7bc8592e418332e5b9973007698d3cd79754d9))

* Reformat changelog to match prior versions (#892) ([`34f6e49`](https://github.com/python-zeroconf/python-zeroconf/commit/34f6e498dec18b84dab1c27c75348916bceef8e6))

* Fix spelling and grammar errors in 0.32.0 changelog (#891) ([`ba235dd`](https://github.com/python-zeroconf/python-zeroconf/commit/ba235dd8bc65de4f461f76fd2bf4647844437e1a))

* Rewrite 0.32.0 changelog in past tense (#890) ([`0d91156`](https://github.com/python-zeroconf/python-zeroconf/commit/0d911568d367f1520acb19bdf830fe188b6ffb70))

* Reformat backwards incompatible changes to match previous versions (#889) ([`9abb40c`](https://github.com/python-zeroconf/python-zeroconf/commit/9abb40cf331bc0acc5fdbb03fce5c958cec8b41e))

* Remove extra newlines between changelog entries (#888) ([`d31fd10`](https://github.com/python-zeroconf/python-zeroconf/commit/d31fd103cc942574f7fbc75e5346cc3d3eaf7ee1))

* Collapse changelog for 0.32.0 (#887) ([`14cf936`](https://github.com/python-zeroconf/python-zeroconf/commit/14cf9362c9ae947bcee5911b9c593ca76f50d529))

* Disable pylint in the CI (#886) ([`b9dc12d`](https://github.com/python-zeroconf/python-zeroconf/commit/b9dc12dee8b4a7f6d8e1f599948bf16e5e7fab47))

* Revert name change of zeroconf.asyncio to zeroconf.aio (#885)

- Now that `__init__.py` no longer needs to import `asyncio`,
  the name conflict is not a concern.

Fixes #883 ([`b9eae5a`](https://github.com/python-zeroconf/python-zeroconf/commit/b9eae5a6f8f86bfe60446f133cad5fc33d072959))

* Update changelog (#879) ([`be1d3bb`](https://github.com/python-zeroconf/python-zeroconf/commit/be1d3bbe0ee12254d11e3d8b75c2faba950fabce))

* Add coverage to ensure loading zeroconf._logger does not override logging level (#878) ([`86e2ab9`](https://github.com/python-zeroconf/python-zeroconf/commit/86e2ab9db3c7bd47b6e81837d594280ced3b30f9))

* Add coverge for disconnected adapters in add_multicast_member (#877) ([`ab83819`](https://github.com/python-zeroconf/python-zeroconf/commit/ab83819ad6b6ff727a894271dde3e4be6c28cb2c))

* Break apart net_socket for easier testing (#875) ([`f0770fe`](https://github.com/python-zeroconf/python-zeroconf/commit/f0770fea80b00f2340815fa983968f68a15c702e))

* Fix flapping test test_integration_with_listener_class (#876) ([`decd8a2`](https://github.com/python-zeroconf/python-zeroconf/commit/decd8a26aa8a89ceefcd9452fe562f2eeaa3fecb))

* Add coverage to ensure unrelated A records do not generate ServiceBrowser callbacks (#874)

closes #871 ([`471bacd`](https://github.com/python-zeroconf/python-zeroconf/commit/471bacd3200aa1216054c0e52b2e5842e9760aa0))

* Update changelog (#870) ([`972da99`](https://github.com/python-zeroconf/python-zeroconf/commit/972da99e4dd9d0fe1c1e0786da45d66fd43a717a))

* Fix deadlock when event loop is shutdown during service registration (#869) ([`4ed9036`](https://github.com/python-zeroconf/python-zeroconf/commit/4ed903698b10f434cfbbe601998f27c10d2fb9db))

* Break apart new_socket to be testable (#867) ([`22ff6b5`](https://github.com/python-zeroconf/python-zeroconf/commit/22ff6b56d7b6531d2af5c50dca66fd2be2b276f4))

* Add test coverage to ensure ServiceBrowser ignores unrelated updates (#866) ([`dcf18c8`](https://github.com/python-zeroconf/python-zeroconf/commit/dcf18c8a32652c6aa70af180b6a5261f4277faa9))

* Add test coverage for duplicate properties in a TXT record (#865) ([`6ef65fc`](https://github.com/python-zeroconf/python-zeroconf/commit/6ef65fc7cafc3d4089a2b943da224c6cb027b4b0))

* Update changelog (#864) ([`c64064a`](https://github.com/python-zeroconf/python-zeroconf/commit/c64064ad3b38a40775637c0fd8877d9d00d2d537))

* Ensure protocol and sending errors are logged once (#862) ([`c516919`](https://github.com/python-zeroconf/python-zeroconf/commit/c516919064687551299f23e23bf0797888020041))

* Remove unreachable code in AsyncListener.datagram_received (#863) ([`f536869`](https://github.com/python-zeroconf/python-zeroconf/commit/f5368692d7907e440ca81f0acee9744f79dbae80))

* Add unit coverage for shutdown_loop (#860) ([`af83c76`](https://github.com/python-zeroconf/python-zeroconf/commit/af83c766c2ae72bd23184c6f6300e4d620c7b3e8))

* Make a dispatch dict for ServiceStateChange listeners (#859) ([`57cccc4`](https://github.com/python-zeroconf/python-zeroconf/commit/57cccc4dcbdc9df52672297968ccb55054122049))

* Cleanup coverage data (#858) ([`3eb7be9`](https://github.com/python-zeroconf/python-zeroconf/commit/3eb7be95fd6cd4960f96f29aa72fc45347c57b6e))

* Fix changelog formatting (#857) ([`59247f1`](https://github.com/python-zeroconf/python-zeroconf/commit/59247f1c44b485bf51d4a8d3e3966b9faf40cf82))

* Update changelog (#856) ([`cb2e237`](https://github.com/python-zeroconf/python-zeroconf/commit/cb2e237b6f1af0a83bc7352464562cdb7bbcac14))

* Only run linters on Linux in CI (#855)

- The github MacOS and Windows runners are slower and
  will have the same results as the Linux runners so there
  is no need to wait for them.

closes #854 ([`03411f3`](https://github.com/python-zeroconf/python-zeroconf/commit/03411f35d82752d5d2633a67db132a011098d9e6))

* Speed up test_verify_name_change_with_lots_of_names under PyPy (#853)

fixes #840 ([`0cd876f`](https://github.com/python-zeroconf/python-zeroconf/commit/0cd876f5a42699aeb0176380ba4cca4d8a536df3))

* Make ServiceInfo first question QU (#852)

- We want an immediate response when making a request with ServiceInfo
  by asking a QU question, most responders will not delay the response
  and respond right away to our question. This also improves compatibility
  with split networks as we may not have been able to see the response
  otherwise.  If the responder has not multicast the record recently
  it may still choose to do so in addition to responding via unicast

- Reduces traffic when there are multiple zeroconf instances running
  on the network running ServiceBrowsers

- If we don't get an answer on the first try, we ask a QM question
  in the event we can't receive a unicast response for some reason

- This change puts ServiceInfo inline with ServiceBrowser which
  also asks the first question as QU since ServiceInfo is commonly
  called from ServiceBrowser callbacks

closes #851 ([`76e0b05`](https://github.com/python-zeroconf/python-zeroconf/commit/76e0b05ca9c601bd638817bf68ca8d981f1d65f8))

* Update changelog (#850) ([`8c9d1d8`](https://github.com/python-zeroconf/python-zeroconf/commit/8c9d1d8964d9226d5d3ac38bec908e930954b369))

* Switch ServiceBrowser query scheduling to use call_later instead of a loop (#849)

- Simplifies scheduling as there is no more need to sleep in a loop as
  we now schedule future callbacks with call_later

- Simplifies cancelation as there is no more coroutine to cancel, only a timer handle
  We no longer have to handle the canceled error and cleaning up the awaitable

- Solves the infrequent test failures in test_backoff and test_integration ([`a8c1623`](https://github.com/python-zeroconf/python-zeroconf/commit/a8c16231881de43adedbedbc3f1ea707c0b457f2))

* Fix spurious failures in ZeroconfServiceTypes tests (#848)

- These tests ran the same test twice in 0.5s and would
  trigger the duplicate packet suppression.  Rather then
  making them run longer, we can disable the suppression
  for the test. ([`9f71e5b`](https://github.com/python-zeroconf/python-zeroconf/commit/9f71e5b7364d4a23492cafe4f49a5c2acda4178d))

* Fix thread safety in handlers test (#847) ([`182c68f`](https://github.com/python-zeroconf/python-zeroconf/commit/182c68ff11ba381444a708e17560e920ae1849ef))

* Update changelog (#845) ([`72502c3`](https://github.com/python-zeroconf/python-zeroconf/commit/72502c303a1a889cf84906b8764fd941a840e6d3))

* Increase timeout in test_integration (#844)

- The github macOS runners tend to be a bit loaded and these
  sometimes fail because of it ([`dd86f2f`](https://github.com/python-zeroconf/python-zeroconf/commit/dd86f2f9fee4bbaebce956b330c1837a6e9c6c99))

* Use AAAA records instead of A records in test_integration_with_listener_ipv6 (#843) ([`688c518`](https://github.com/python-zeroconf/python-zeroconf/commit/688c5184dce67e5af857c138639ced4bdcec1e57))

* Fix ineffective patching on PyPy (#842)

- Use patch in all places so its easier to find where we need
  to clean up ([`ecd9c94`](https://github.com/python-zeroconf/python-zeroconf/commit/ecd9c941810e4b413b20dc55929b3ae1a7e57b27))

* Limit duplicate packet suppression to 1s intervals (#841)

- Only suppress duplicate packets that happen within the same
  second. Legitimate queriers will retry the question if they
  are suppressed. The limit was reduced to one second to be
  in line with rfc6762:

   To protect the network against excessive packet flooding due to
   software bugs or malicious attack, a Multicast DNS responder MUST NOT
   (except in the one special case of answering probe queries) multicast
   a record on a given interface until at least one second has elapsed
   since the last time that record was multicast on that particular ([`7fb11bf`](https://github.com/python-zeroconf/python-zeroconf/commit/7fb11bfc03c06cbe9ed5a4303b3e632d69665bb1))

* Skip dependencies install in CI on cache hit (#839)

There is no need to reinstall dependencies in the CI when we have a cache hit. ([`937be52`](https://github.com/python-zeroconf/python-zeroconf/commit/937be522a42830b27326b5253d49003b57998bc9))

* Adjust restore key for CI cache (#838) ([`3fdd834`](https://github.com/python-zeroconf/python-zeroconf/commit/3fdd8349553c160586fb6831c9466410f19a3308))

* Make multipacket known answer suppression per interface (#836)

- The suppression was happening per instance of Zeroconf instead
  of per interface. Since the same network can be seen on multiple
  interfaces (usually and wifi and ethernet), this would confuse the
  multi-packet known answer supression since it was not expecting
  to get the same data more than once

Fixes #835 ([`7297f3e`](https://github.com/python-zeroconf/python-zeroconf/commit/7297f3ef71c9984296c3e28539ce7a4b42f04a05))

* Ensure coverage.xml is written for codecov (#837) ([`0b1abbc`](https://github.com/python-zeroconf/python-zeroconf/commit/0b1abbc8f2b09235cfd44e5586024c7b82dc5289))

* Wait for startup in test_integration (#834) ([`540c652`](https://github.com/python-zeroconf/python-zeroconf/commit/540c65218eb9d1aedc88a3d3724af97f39ccb88e))

* Cache dependency installs in CI (#833) ([`0bf4f75`](https://github.com/python-zeroconf/python-zeroconf/commit/0bf4f7537a042a00d9d3f815afcdf7ebe29d9f53))

* Annotate test failures on github (#831) ([`4039b0b`](https://github.com/python-zeroconf/python-zeroconf/commit/4039b0b755a3d0fe15e4cb1a7cb1592c35e048e1))

* Show 20 slowest tests on each run (#832) ([`8230e3f`](https://github.com/python-zeroconf/python-zeroconf/commit/8230e3f40da5d2d152942725d67d5f8c0b8c647b))

* Disable duplicate question suppression for test_integration (#830)

- This test waits until we get 50 known answers. It would
  sometimes fail because it could not ask enough
  unsuppressed questions in the allowed time. ([`10f4a7f`](https://github.com/python-zeroconf/python-zeroconf/commit/10f4a7f8d607d09673be56e5709912403503d86b))

* Convert test_integration to asyncio to avoid testing threading races (#828)

Fixes #768 ([`4c4b388`](https://github.com/python-zeroconf/python-zeroconf/commit/4c4b388ba125ad23a03722b30c71da86853fe05a))

* Update changelog (#827) ([`82f80c3`](https://github.com/python-zeroconf/python-zeroconf/commit/82f80c301a6324d2f1711ca751e81069e90030ec))

* Drop oversize packets before processing them (#826)

- Oversized packets can quickly overwhelm the system and deny
  service to legitimate queriers. In practice this is usually
  due to broken mDNS implementations rather than malicious
  actors. ([`6298ef9`](https://github.com/python-zeroconf/python-zeroconf/commit/6298ef9078cf2408bc1e57660ee141e882d13469))

* Guard against excessive ServiceBrowser queries from PTR records significantly lower than recommended (#824)

* We now enforce a minimum TTL for PTR records to avoid
ServiceBrowsers generating excessive queries refresh queries.
Apple uses a 15s minimum TTL, however we do not have the same
level of rate limit and safe guards so we use 1/4 of the recommended value. ([`7f6d003`](https://github.com/python-zeroconf/python-zeroconf/commit/7f6d003210244b6f7df133bd474d7ddf64098422))

* Update changelog (#822) ([`4a82769`](https://github.com/python-zeroconf/python-zeroconf/commit/4a8276941a07188180ee31dc4ca578306c2df92b))

* Only wake up the query loop when there is a change in the next query time (#818)

The ServiceBrowser query loop (async_browser_task) was being awoken on
every packet because it was using `zeroconf.async_wait` which wakes
up on every new packet.  We only need to awaken the loop when the next time
we are going to send a query has changed.

fixes #814 fixes #768 ([`4062fe2`](https://github.com/python-zeroconf/python-zeroconf/commit/4062fe21d8baaad36960f8cae0f59ac7083a6b55))

* Fix reliablity of tests that patch sending (#820) ([`a7b4f8e`](https://github.com/python-zeroconf/python-zeroconf/commit/a7b4f8e070de69db1ed872e2ff7a953ec624394c))

* Fix default v6_flow_scope argument with tests that mock send (#819) ([`f9d3529`](https://github.com/python-zeroconf/python-zeroconf/commit/f9d35299a39fee0b1632a3b2ac00170f761d53b1))

* Turn on logging in the types test (#816)

- Will be needed to track down #813 ([`ffd2532`](https://github.com/python-zeroconf/python-zeroconf/commit/ffd2532f72a59ede86732b310512774b8fa344e7))

* New ServiceBrowsers now request QU in the first outgoing when unspecified (#812) ([`e32bb5d`](https://github.com/python-zeroconf/python-zeroconf/commit/e32bb5d98be0dc7ed130224206a4de699bcd68e3))

* Update changelog (#811) ([`13c558c`](https://github.com/python-zeroconf/python-zeroconf/commit/13c558cf3f40e52a13347a39b050e49a9241c269))

* Simplify wait_event_or_timeout (#810)

- This function always did the same thing on timeout and
  wait complete so we can use the same callback.  This
  solves the CI failing due to the test coverage flapping
  back and forth as the timeout would rarely happen. ([`d4c8f0d`](https://github.com/python-zeroconf/python-zeroconf/commit/d4c8f0d3ffdcdc609810aca383492a57f9e1a723))

* Make DNSHinfo and DNSAddress use the same match order as DNSPointer and DNSText (#808)

We want to check the data that is most likely to be unique first
so we can reject the __eq__ as soon as possible. ([`f9bbbce`](https://github.com/python-zeroconf/python-zeroconf/commit/f9bbbce388f2c6c24109c15ef843c10eeccf008f))

* Format tests/services/test_info.py with newer black (#809) ([`0129ac0`](https://github.com/python-zeroconf/python-zeroconf/commit/0129ac061db4a950f7bddf1084309e44aaabdbdf))

* Qualify IPv6 link-local addresses with scope_id (#343)

Co-authored-by: Lokesh Prajapati <lokesh.prajapati@ncipher.com>
Co-authored-by: de Angelis, Antonio <Antonio.deAngelis@ncipher.com>

When a service is advertised on an IPv6 address where
the scope is link local, i.e. fe80::/64 (see RFC 4007)
the resolved IPv6 address must be extended with the
scope_id that identifies through the "%" symbol the
local interface to be used when routing to that address.
A new API `parsed_scoped_addresses()` is provided to
return qualified addresses to avoid breaking compatibility
on the existing parsed_addresses(). ([`05bb21b`](https://github.com/python-zeroconf/python-zeroconf/commit/05bb21b9b43f171e30b48fad6a756df49162b557))

* Tag 0.32.0b3 (#805) ([`5dccf34`](https://github.com/python-zeroconf/python-zeroconf/commit/5dccf3496a9bd4c268da4c39aab545ddcd50ac57))

* Update changelog (#804) ([`59e4bd2`](https://github.com/python-zeroconf/python-zeroconf/commit/59e4bd25347aac254700dc3a1518676042982b3a))

* Skip network adapters that are disconnected (#327)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`df66da2`](https://github.com/python-zeroconf/python-zeroconf/commit/df66da2a943b9ff978602680b746f1edeba048dc))

* Add slots to DNS classes (#803)

- On a busy network that receives many mDNS packets per second, we
  will not know the answer to most of the questions being asked.
  In this case the creating the DNS* objects are usually garbage
  collected within 1s as they are not needed. We now set __slots__
  to speed up the creation and destruction of these objects ([`18fe341`](https://github.com/python-zeroconf/python-zeroconf/commit/18fe341300e28ed93d7b5d7ca8e07edb119bd597))

* Update changelog (#802) ([`58ae3cf`](https://github.com/python-zeroconf/python-zeroconf/commit/58ae3cf553cd925ac90f3db551f4085ea5bc8b79))

* Update changelog (#801) ([`662ed61`](https://github.com/python-zeroconf/python-zeroconf/commit/662ed6166282b9b5b6e83a596c0576a57f8962d2))

* Ensure we handle threadsafe shutdown under PyPy with multiple event loops (#800) ([`bbc9124`](https://github.com/python-zeroconf/python-zeroconf/commit/bbc91241a86f3339aa27cae7b4ea2ab9d7c1f37d))

* Update changelog (#798) ([`9961dce`](https://github.com/python-zeroconf/python-zeroconf/commit/9961dce598d3c6eeda68a2f874a7a50ec33f819c))

* Ensure fresh ServiceBrowsers see old_record as None when replaying the cache (#793) ([`38e66ec`](https://github.com/python-zeroconf/python-zeroconf/commit/38e66ec5ba5fcb96cef17b8949385075807a2fb7))

* Update changelog (#797) ([`c36099a`](https://github.com/python-zeroconf/python-zeroconf/commit/c36099a41a71298d58e7afa42ecdc7a54d3b010a))

* Pass both the new and old records to async_update_records (#792)

* Pass the old_record (cached) as the value and the new_record (wire)
to async_update_records instead of forcing each consumer to
check the cache since we will always have the old_record
when generating the async_update_records call. This avoids
the overhead of multiple cache lookups for each listener. ([`d637d67`](https://github.com/python-zeroconf/python-zeroconf/commit/d637d67378698e0a505be90afbce4e2264b49444))

* Remove unused constant from zeroconf._handlers (#796) ([`cb91484`](https://github.com/python-zeroconf/python-zeroconf/commit/cb91484670ba76c8c453dc49502e89195561b31e))

* Make add_listener and remove_listener threadsafe (#794) ([`2bfbcbe`](https://github.com/python-zeroconf/python-zeroconf/commit/2bfbcbe9e05b9df98bba66a73deb0041c0e7c13b))

* Fix test_tc_bit_defers_last_response_missing failures due to thread safety (#795) ([`6aac0eb`](https://github.com/python-zeroconf/python-zeroconf/commit/6aac0eb0c1e394ec7ee21ddd6e98e446417d0e07))

* Ensure outgoing ServiceBrowser questions are seen by the question history (#790) ([`ecad4e8`](https://github.com/python-zeroconf/python-zeroconf/commit/ecad4e84c44ffd21dbf15e969c08f7b3376b131c))

* Update changelog (#788) ([`5d23628`](https://github.com/python-zeroconf/python-zeroconf/commit/5d2362825110e9f7a9c9259218a664e2e927e821))

* Add async_apple_scanner example (#719) ([`62dc9c9`](https://github.com/python-zeroconf/python-zeroconf/commit/62dc9c91c277bc4755f81597adca030a43d0ce5f))

* Add support for requesting QU questions to ServiceBrowser and ServiceInfo (#787) ([`135983c`](https://github.com/python-zeroconf/python-zeroconf/commit/135983cb96a27e3ad3750234286d1d9bfa6ff44f))

* Update changelog (#786) ([`3b3ecf0`](https://github.com/python-zeroconf/python-zeroconf/commit/3b3ecf09d2f30ee39c6c29b4d85e000577b2c4b9))

* Ensure the queue is created before adding listeners to ServiceBrowser (#785)

* Ensure the queue is created before adding listeners to ServiceBrowser

- The callback from the listener could generate an event that would
  fire in async context that should have gone to the queue which
  could result in the consumer running a sync call in the event loop
  and blocking it.

* add comments

* add comments

* add comments

* add comments

* black ([`97f5b50`](https://github.com/python-zeroconf/python-zeroconf/commit/97f5b502815075f2ff29bee3ace7cde6ad725dfb))

* Add a guard to prevent running ServiceInfo.request in async context (#784)

* Add a guard to prevent running ServiceInfo.request in async context

* test ([`dd85ae7`](https://github.com/python-zeroconf/python-zeroconf/commit/dd85ae7defd3f195ed0511a2fdb6512326ca0562))

* Inline utf8 decoding when processing incoming packets (#782) ([`3be1bc8`](https://github.com/python-zeroconf/python-zeroconf/commit/3be1bc84bff5ee2840040ddff41185b257a1055c))

* Drop utf cache from _dns (#781)

- The cache did not make enough difference to justify the additional
  complexity after additional testing was done ([`1b87343`](https://github.com/python-zeroconf/python-zeroconf/commit/1b873436e2d9ff36876a71c48fa697d277fd3ffa))

* Switch to using a simple cache instead of lru_cache (#779) ([`7aeafbf`](https://github.com/python-zeroconf/python-zeroconf/commit/7aeafbf3b990ab671ff691b6c20cd410f69808bf))

* Reformat test_handlers (#780) ([`767ae8f`](https://github.com/python-zeroconf/python-zeroconf/commit/767ae8f6cd92493f8f43d66edc70c8fd856ed11e))

* Fix Responding to Address Queries (RFC6762 section 6.2) (#777) ([`ac9f72a`](https://github.com/python-zeroconf/python-zeroconf/commit/ac9f72a986ae314af0043cae6fb6219baabea7e6))

* Implement duplicate question supression (#770)

https://datatracker.ietf.org/doc/html/rfc6762#section-7.3 ([`c0f4f48`](https://github.com/python-zeroconf/python-zeroconf/commit/c0f4f48e2bb996ce18cb569aa5369356cbc919ff))

* Fix deadlock on ServiceBrowser shutdown with PyPy (#774) ([`b5d54e4`](https://github.com/python-zeroconf/python-zeroconf/commit/b5d54e485d9dbcde1b7b472760a0b307198b8ec8))

* Add a guard against the task list changing when shutting down (#776) ([`e8836b1`](https://github.com/python-zeroconf/python-zeroconf/commit/e8836b134c47080edaf47532d7cb844b307dfb08))

* Verify async callers can still use Zeroconf without migrating to AsyncZeroconf (#775) ([`f23df4f`](https://github.com/python-zeroconf/python-zeroconf/commit/f23df4f5f05e3911cbf96234b198ea88691aadad))

* Implement accidental synchronization protection (RFC2762 section 5.2) (#773) ([`b600547`](https://github.com/python-zeroconf/python-zeroconf/commit/b600547a47878775e1c6fb8df46682a670beccba))

* Improve performance of parsing DNSIncoming by caching read_utf (#769) ([`5d44a36`](https://github.com/python-zeroconf/python-zeroconf/commit/5d44a36a59c21ef7869ba9e6dde9f658d3502793))

* Add test coverage to ensure RecordManager.add_listener callsback known question answers (#767) ([`e70431e`](https://github.com/python-zeroconf/python-zeroconf/commit/e70431e1fdc92c155309a1d40c89fed48737970c))

* Switch to using an asyncio.Event for async_wait (#759)

- We no longer need to check for thread safety under a asyncio.Condition
  as the ServiceBrowser and ServiceInfo internals schedule coroutines
  in the eventloop. ([`6c82fa9`](https://github.com/python-zeroconf/python-zeroconf/commit/6c82fa9efd0f434f0f7c83e3bd98bd7851ede4cf))

* Break test_lots_of_names into two tests (#764) ([`85532e1`](https://github.com/python-zeroconf/python-zeroconf/commit/85532e13e42447fcd6d4d4b0060f04d33c3ab780))

* Fix test_lots_of_names overflowing the incoming buffer (#763) ([`38b59a6`](https://github.com/python-zeroconf/python-zeroconf/commit/38b59a64592f41b2bb547b35c72a010a925a2941))

* Fix race condition in ServiceBrowser test_integration (#762)

- The event was being cleared in the wrong thread which
  meant if the test was fast enough it would not be seen
  the second time and give a spurious failure ([`fc0e599`](https://github.com/python-zeroconf/python-zeroconf/commit/fc0e599eec77477dd8f21ecd68b238e6a27f1bcf))

* Add 60s timeout for each test (#761) ([`936500a`](https://github.com/python-zeroconf/python-zeroconf/commit/936500a47cc33d9daa86f9012b1791986361ff63))

* Add missing coverage for SignalRegistrationInterface (#758) ([`9f68fc8`](https://github.com/python-zeroconf/python-zeroconf/commit/9f68fc8b1b834d0194e8ba1069d052aa853a8d38))

* Update changelog (#757) ([`1c93baa`](https://github.com/python-zeroconf/python-zeroconf/commit/1c93baa486b1b0f44487891766e0a0c1de3eb252))

* Simplify ServiceBrowser callsbacks (#756) ([`f24ebba`](https://github.com/python-zeroconf/python-zeroconf/commit/f24ebba9ecc4d1626d570956a7cc735206d7ff6e))

* Revert: Fix thread safety in _ServiceBrowser.update_records_complete (#708) (#755)

- This guarding is no longer needed as the ServiceBrowser loop
  now runs in the event loop and the thread safety guard is no
  longer needed ([`f53c88b`](https://github.com/python-zeroconf/python-zeroconf/commit/f53c88b52ed080c80e2e98d3da91a830f0c7ebca))

* Drop AsyncServiceListener (#754) ([`04cd268`](https://github.com/python-zeroconf/python-zeroconf/commit/04cd2688022ebd07c1f875fefc73f8d15c4ed56c))

* Run ServiceBrowser queries in the event loop (#752) ([`4d0a8f3`](https://github.com/python-zeroconf/python-zeroconf/commit/4d0a8f3c643a0fc5c3a40420bab96ef18dddaecb))

* Remove unused argument from AsyncZeroconf (#751) ([`e7adce2`](https://github.com/python-zeroconf/python-zeroconf/commit/e7adce2bf6ea0b4af1709369a36421acd9757b4a))

* Fix warning about Zeroconf._async_notify_all not being awaited in sync shutdown (#750) ([`3b9baf0`](https://github.com/python-zeroconf/python-zeroconf/commit/3b9baf07278290b2b4eb8ac5850bccfbd8b107d8))

* Update async_service_info_request example to ensure it runs in the right event loop (#749) ([`0f702c6`](https://github.com/python-zeroconf/python-zeroconf/commit/0f702c6a41bb33ed63872249b82d1111bdac4fa6))

* Run ServiceInfo requests in the event loop (#748) ([`0dbcabf`](https://github.com/python-zeroconf/python-zeroconf/commit/0dbcabfade41057a055ebefffd410d1afc3eb0ea))

* Remove support for notify listeners (#733) ([`7b3b4b5`](https://github.com/python-zeroconf/python-zeroconf/commit/7b3b4b5b8303a684165fcd53c0d9c36a1b8dda3d))

* Update changelog (#747) ([`0909c80`](https://github.com/python-zeroconf/python-zeroconf/commit/0909c80c67287ba92ed334ab6896136aec0f3f24))

* Relocate service info tests to tests/services/test_info.py (#746) ([`541292e`](https://github.com/python-zeroconf/python-zeroconf/commit/541292e55fee8bbafe687afcb8d152f6fe0efb5f))

* Relocate service browser tests to tests/services/test_browser.py (#745) ([`869c95a`](https://github.com/python-zeroconf/python-zeroconf/commit/869c95a51e228131eb7debe1acc47c105b9bf7b5))

* Relocate ServiceBrowser to zeroconf._services.browser (#744) ([`368163d`](https://github.com/python-zeroconf/python-zeroconf/commit/368163d3c30325d60021203430711e10fd6d97e9))

* Relocate ServiceInfo to zeroconf._services.info (#741) ([`f0d727b`](https://github.com/python-zeroconf/python-zeroconf/commit/f0d727bd9addd6dab373b75008f04a6f8547928b))

* Run question answer callbacks from add_listener in the event loop (#740) ([`c8e15dd`](https://github.com/python-zeroconf/python-zeroconf/commit/c8e15dd2bb5f6d2eb3a8ef5f26ad044517b70c47))

* Fix flakey cache bit flush test (#739) ([`e227d6e`](https://github.com/python-zeroconf/python-zeroconf/commit/e227d6e4c337ef9d5aa626c41587a8046313e416))

* Remove second level caching from ServiceBrowsers (#737) ([`5feda7e`](https://github.com/python-zeroconf/python-zeroconf/commit/5feda7e318f7d164d2b04b2d243a804372517da6))

* Breakout ServiceBrowser handler from listener creation (#736) ([`35ac7a3`](https://github.com/python-zeroconf/python-zeroconf/commit/35ac7a39d1fab00898ed6075e7e930424716b627))

* Add fast cache lookup functions (#732) ([`9d31245`](https://github.com/python-zeroconf/python-zeroconf/commit/9d31245f9ed4f6b1f7d9d7c51daf0ca394fd208f))

* Switch to using DNSRRSet in RecordManager (#735) ([`c035925`](https://github.com/python-zeroconf/python-zeroconf/commit/c035925f47732a889c76a2ff0989b92c6687c950))

* Add test coverage to ensure the cache flush bit is properly handled (#734) ([`50af944`](https://github.com/python-zeroconf/python-zeroconf/commit/50af94493ff6bf5d21445eaa80d3a96f348b0d11))

* Fix server cache to be case-insensitive (#731) ([`3ee9b65`](https://github.com/python-zeroconf/python-zeroconf/commit/3ee9b650bedbe61d59838897f653ad43a6d51910))

* Update changelog (#730) ([`733f79d`](https://github.com/python-zeroconf/python-zeroconf/commit/733f79d28c7dd4500a1598b279ee638ead8bdd55))

* Prefix cache functions that are non threadsafe with async_ (#724) ([`3503e76`](https://github.com/python-zeroconf/python-zeroconf/commit/3503e7614fc31bbfe2c919f13689468cc73179fd))

* Fix cache handling of records with different TTLs (#729)

- There should only be one unique record in the cache at
  a time as having multiple unique records will different
  TTLs in the cache can result in unexpected behavior since
  some functions returned all matching records and some
  fetched from the right side of the list to return the
  newest record. Intead we now store the records in a dict
  to ensure that the newest record always replaces the same
  unique record and we never have a source of truth problem
  determining the TTL of a record from the cache. ([`88aa610`](https://github.com/python-zeroconf/python-zeroconf/commit/88aa610274bf79aef6c74998f2bfca8c8de0dccb))

* Add tests for the DNSCache class (#728)

- There is currently a bug in the implementation where an entry
  can exist in two places in the cache with different TTLs. Since
  a known answer cannot be both expired and expired at the same
  time, this is a bug that needs to be fixed. ([`ceb79bd`](https://github.com/python-zeroconf/python-zeroconf/commit/ceb79bd7f7bdad434cbe5b4846492cd434ea883b))

* Update changelog (#727) ([`9cc834d`](https://github.com/python-zeroconf/python-zeroconf/commit/9cc834d501fa5e582adeb4468b02775288e1fa11))

* Rename handlers and internals to make it clear what is threadsafe (#726)

- It was too easy to get confused about what was threadsafe and
  what was not threadsafe which lead to unexpected failures.
  Rename functions to make it clear what will be run in the event
  loop and what is expected to be threadsafe ([`f91af79`](https://github.com/python-zeroconf/python-zeroconf/commit/f91af79c8779ac235598f5584f439c78b3bdcca2))

* Fix ServiceInfo with multiple A records (#725) ([`3338594`](https://github.com/python-zeroconf/python-zeroconf/commit/33385948da9123bc9348374edce7502abd898e82))

* Relocate cache tests to tests/test_cache.py (#722) ([`e2d4d98`](https://github.com/python-zeroconf/python-zeroconf/commit/e2d4d98db70b376c53883367b3a24c1d2510c2b5))

* Synchronize time for fate sharing (#718) ([`18ddb8d`](https://github.com/python-zeroconf/python-zeroconf/commit/18ddb8dbeef3edad3bb97131803dfecde4355467))

* Update changelog (#717) ([`1ab6859`](https://github.com/python-zeroconf/python-zeroconf/commit/1ab685960bc0e412d36baf6794fde06350998474))

* Cleanup typing in zero._core and document ignores (#714) ([`8183640`](https://github.com/python-zeroconf/python-zeroconf/commit/818364008e911757fca24e41a4eb36e0eef49bfa))

* Update README (#716) ([`0f2f4e2`](https://github.com/python-zeroconf/python-zeroconf/commit/0f2f4e207cb5007112ba09e87a332b1a46cd1577))

* Cleanup typing in zeroconf._logger (#715) ([`3fcdcfd`](https://github.com/python-zeroconf/python-zeroconf/commit/3fcdcfd9a3efc56a34f0334ffb8706613e07d19d))

* Cleanup typing in zeroconf._utils.net (#713) ([`a50b3ee`](https://github.com/python-zeroconf/python-zeroconf/commit/a50b3eeda5f275c31b36cdc1c8312f61599e72bf))

* Cleanup typing in zeroconf._services (#711) ([`a42512c`](https://github.com/python-zeroconf/python-zeroconf/commit/a42512ca6a6a4c15f37ab623a96deb2aa06dd053))

* Cleanup typing in zeroconf._services.registry (#712) ([`6b923de`](https://github.com/python-zeroconf/python-zeroconf/commit/6b923deb3682088d0fe9182377b5603d0ade1e1a))

* Add setter for DNSQuestion to easily make a QU question (#710)

Closes #703 ([`aeb1b23`](https://github.com/python-zeroconf/python-zeroconf/commit/aeb1b23defa2d5956a6f19acca4ce410d6a04cc9))

* Synchronize created time for incoming and outgoing queries (#709) ([`c366c8c`](https://github.com/python-zeroconf/python-zeroconf/commit/c366c8cc45f565c4066fc72b481c6a960bac1cb9))

* Set stale unique records to expire 1s in the future instead of instant removal (#706)

- Fixes #475

- https://tools.ietf.org/html/rfc6762#section-10.2
  Queriers receiving a Multicast DNS response with a TTL of zero SHOULD
  NOT immediately delete the record from the cache, but instead record
  a TTL of 1 and then delete the record one second later.  In the case
  of multiple Multicast DNS responders on the network described in
  Section 6.6 above, if one of the responders shuts down and
  incorrectly sends goodbye packets for its records, it gives the other
  cooperating responders one second to send out their own response to
  "rescue" the records before they expire and are deleted. ([`f3eeecd`](https://github.com/python-zeroconf/python-zeroconf/commit/f3eeecd84413b510b9b8e05e2d1f6ad99d0dc37d))

* Fix thread safety in _ServiceBrowser.update_records_complete (#708) ([`dc0c613`](https://github.com/python-zeroconf/python-zeroconf/commit/dc0c6137742edf97626c972e5c9191dfbffaecdc))

* Split DNSOutgoing/DNSIncoming/DNSMessage into zeroconf._protocol (#705) ([`f39bde0`](https://github.com/python-zeroconf/python-zeroconf/commit/f39bde0f6cba7a3c1b8fe8bc1a4ab4388801e486))

* Update changelog (#699) ([`c368e1c`](https://github.com/python-zeroconf/python-zeroconf/commit/c368e1c67c82598e920ca52b1f7a47ed6e1cf738))

* Efficiently bucket queries with known answers (#698) ([`7e30848`](https://github.com/python-zeroconf/python-zeroconf/commit/7e308480238fdf2cfe08474d679121e77f746fa6))

* Abstract DNSOutgoing ttl write into _write_ttl (#695) ([`26fa2fb`](https://github.com/python-zeroconf/python-zeroconf/commit/26fa2fb479fff87ca5af17c2c09a557c4b6176b5))

* Use unique names in service types tests (#697) ([`767546b`](https://github.com/python-zeroconf/python-zeroconf/commit/767546b656d7db6df0cbf2b257953498f1bc3996))

* Rollback data in one call instead of poping one byte at a time in DNSOutgoing (#696) ([`5cbaa3f`](https://github.com/python-zeroconf/python-zeroconf/commit/5cbaa3fc02f635e6c735e1ee5f1ca19b84c0a069))

* Fix off by 1 in test_tc_bit_defers_last_response_missing (#694) ([`32b7dc4`](https://github.com/python-zeroconf/python-zeroconf/commit/32b7dc40e2c3621fcacb2f389d51408ab35ac832))

* Suppress additionals when answer is suppressed (#690) ([`0cdba98`](https://github.com/python-zeroconf/python-zeroconf/commit/0cdba98e65dd3dce2db8aa607e97e3b67b97721a))

* Move setting DNS created and ttl into its own function (#692) ([`993a82e`](https://github.com/python-zeroconf/python-zeroconf/commit/993a82e414db8aadaee0e0475e178e75df417a71))

* Remove AA flags from handlers test (#693)

- The flag was added by mistake when copying from other tests ([`b60f307`](https://github.com/python-zeroconf/python-zeroconf/commit/b60f307d59e342983d1baa6040c3d997f84538ab))

* Implement multi-packet known answer supression (#687)

- Implements https://datatracker.ietf.org/doc/html/rfc6762#section-7.2

- Fixes https://github.com/jstasiak/python-zeroconf/issues/499 ([`8a25a44`](https://github.com/python-zeroconf/python-zeroconf/commit/8a25a44ec5e4f21c6bdb282fefb8f6c2d296a70b))

* Remove sleeps from services types test (#688)

- Instead of registering the services and doing the broadcast
  we now put them in the registry directly. ([`4865d2b`](https://github.com/python-zeroconf/python-zeroconf/commit/4865d2ba782d0313c0f7d878f5887453086febaa))

* Add truncated property to DNSMessage to lookup the TC bit (#686) ([`e816053`](https://github.com/python-zeroconf/python-zeroconf/commit/e816053af4d900f57100c07c48f384165ba28b9a))

* Update changelog (#684) ([`6fd1bf2`](https://github.com/python-zeroconf/python-zeroconf/commit/6fd1bf2364da4fc2949a905d2e4acb7da003e84d))

* Add coverage to verify ServiceInfo tolerates bytes or string in the txt record (#683) ([`95ddb36`](https://github.com/python-zeroconf/python-zeroconf/commit/95ddb36de64ddf3be9e93f07a1daa8389410f73d))

* Fix logic reversal in apple_p2p test (#681) ([`00b972c`](https://github.com/python-zeroconf/python-zeroconf/commit/00b972c062fd0ed3f2fcc4ceaec84c43b9a613be))

* Check if SO_REUSEPORT exists instead of using an exception catch (#682) ([`d2b5e51`](https://github.com/python-zeroconf/python-zeroconf/commit/d2b5e51d0dcde801e171a4c1e43ef1f86abde825))

* Use DNSRRSet for known answer suppression (#680)

- DNSRRSet uses hash table lookups under the hood which
  is much faster than the linear searches used by
  DNSRecord.suppressed_by ([`e5ea9bb`](https://github.com/python-zeroconf/python-zeroconf/commit/e5ea9bb6c0a3bce7d05241f275a205ddd9e6b615))

* Add DNSRRSet class for quick hashtable lookups of records (#678)

- This class will be used to do fast checks to see
  if records should be suppressed by a set of answers. ([`691c29e`](https://github.com/python-zeroconf/python-zeroconf/commit/691c29eeb049e17a12d6f0a6e3bce2c3f8c2aa02))

* Allow unregistering a service multiple times (#679) ([`d3d439a`](https://github.com/python-zeroconf/python-zeroconf/commit/d3d439ad5d475cff094a4ea83f19d17939527021))

* Remove unreachable BadTypeInNameException check in _ServiceBrowser (#677) ([`57c94bb`](https://github.com/python-zeroconf/python-zeroconf/commit/57c94bb25e056e1827f15c234d7e0bcb5702a0e3))

* Make calculation of times in DNSRecord lazy (#676)

- Most of the time we only check one of the time attrs
  or none at all. Wait to calculate them until they are
  requested. ([`ba2a4f9`](https://github.com/python-zeroconf/python-zeroconf/commit/ba2a4f960d0f9478198968a1466a8b48c963b772))

* Add oversized packet to the invalid packet test (#671) ([`8535110`](https://github.com/python-zeroconf/python-zeroconf/commit/8535110dd661ce406904930994a9f86faf897597))

* Add test for sending unicast responses (#670) ([`d274cd3`](https://github.com/python-zeroconf/python-zeroconf/commit/d274cd3a3409997b764c49d3eae7e8ee2fba33b6))

* Add missing coverage for ServiceInfo address changes (#669) ([`d59fb8b`](https://github.com/python-zeroconf/python-zeroconf/commit/d59fb8be29d8602ad66d89f595b26671a528fd77))

* Add missing coverage for ServiceListener (#668) ([`75347b4`](https://github.com/python-zeroconf/python-zeroconf/commit/75347b4e30429e130716b666da52953700f0f8e9))

* Update async_browser.py example to use AsyncZeroconfServiceTypes (#665) ([`481cc42`](https://github.com/python-zeroconf/python-zeroconf/commit/481cc42d000f5b0258f1be3b6df7cb7b24428b7f))

* Permit the ServiceBrowser to browse overlong types (#666)

- At least one type "tivo-videostream" exists in the wild
  so we are permissive about what we will look for, and
  strict about what we will announce.

Fixes #661 ([`e76c7a5`](https://github.com/python-zeroconf/python-zeroconf/commit/e76c7a5b76485efce0929ee8417aa2e0f262c04c))

* Add an AsyncZeroconfServiceTypes to mirror ZeroconfServiceTypes to zeroconf.aio (#658) ([`aaf8a36`](https://github.com/python-zeroconf/python-zeroconf/commit/aaf8a368063f080be4a9c01fe671243e63bdf576))

* Fix flakey ZeroconfServiceTypes types test (#662) ([`72db0c1`](https://github.com/python-zeroconf/python-zeroconf/commit/72db0c10246e948c15d9a53f60a54b835ccc67bc))

* Add test for launching with apple_p2p=True (#660)

- Switch to using `sys.platform` to detect Mac instead of
  `platform.system()` since `platform.system()` is not intended
  to be machine parsable and is only for humans.

Closes #650 ([`0e52be0`](https://github.com/python-zeroconf/python-zeroconf/commit/0e52be059065e23ebe9e11c465adc20655b6080e))

* Add test for Zeroconf.get_service_info failure case (#657) ([`5752ace`](https://github.com/python-zeroconf/python-zeroconf/commit/5752ace7727bffa34cdac0455125a941014ab123))

* Add coverage for registering a service with a custom ttl (#656) ([`87fe529`](https://github.com/python-zeroconf/python-zeroconf/commit/87fe529a33b920532b2af688bb66182ae832a3ad))

* Improve aio utils tests to validate high lock contention (#655) ([`efd6bfb`](https://github.com/python-zeroconf/python-zeroconf/commit/efd6bfbe81f448da2ee68b91d49cbe1982271da3))

* Add test coverage for normalize_interface_choice exception paths (#654) ([`3c61d03`](https://github.com/python-zeroconf/python-zeroconf/commit/3c61d03f5954c3e45229d6c1399a63c0f7331d55))

* Remove all calls to the executor in AsyncZeroconf (#653) ([`7d8994b`](https://github.com/python-zeroconf/python-zeroconf/commit/7d8994bc3cb4d5978bb1ff189bb5a4b7c81b5c4c))

* Set __all__ in zeroconf.aio to ensure private functions do now show in the docs (#652) ([`b940f87`](https://github.com/python-zeroconf/python-zeroconf/commit/b940f878fe1f8e6b8dfe2554b781cd6034dee722))

* Ensure interface_index_to_ip6_address skips ipv4 adapters (#651) ([`df9f8d9`](https://github.com/python-zeroconf/python-zeroconf/commit/df9f8d9a0110cc9135b7c2f0b4cd47e985da9a7e))

* Add async_unregister_all_services to AsyncZeroconf (#649) ([`72e709b`](https://github.com/python-zeroconf/python-zeroconf/commit/72e709b40caed016ba981be3752c439bbbf40ec7))

* Use cache clear helper in aio tests (#648) ([`79e39c0`](https://github.com/python-zeroconf/python-zeroconf/commit/79e39c0e923a1f6d87353761809f34f0fe1f0800))

* Ensure services are removed from the registry when calling unregister_all_services (#644)

- There was a race condition where a query could be answered for a service
  in the registry while goodbye packets which could result a fresh record
  being broadcast after the goodbye if a query came in at just the right
  time. To avoid this, we now remove the services from the registry right
  after we generate the goodbye packet ([`cf0b5b9`](https://github.com/python-zeroconf/python-zeroconf/commit/cf0b5b9e2cfa4779425401b3d205f5d913621864))

* Use ServiceInfo.key/ServiceInfo.server_key instead of lowering in ServiceRegistry (#647) ([`a83d390`](https://github.com/python-zeroconf/python-zeroconf/commit/a83d390bef042da51d93014c222c65af81723a20))

* Add missing coverage to ServiceRegistry (#646) ([`9354ab3`](https://github.com/python-zeroconf/python-zeroconf/commit/9354ab39f350e4e6451dc4965225591761ada40d))

* Ensure the ServiceInfo.key gets updated when the name is changed externally (#645) ([`330e36c`](https://github.com/python-zeroconf/python-zeroconf/commit/330e36ceb4202c579fe979958c63c37033ababbb))

* Ensure cache is cleared before starting known answer enumeration query test (#639) ([`5ebd954`](https://github.com/python-zeroconf/python-zeroconf/commit/5ebd95452b16e76c37649486b232856a80390ac3))

* Ensure AsyncZeroconf.async_close can be called multiple times like Zeroconf.close (#638) ([`ce6912a`](https://github.com/python-zeroconf/python-zeroconf/commit/ce6912a75392cde41d8950b224ba3d14460993ff))

* Update changelog (#637) ([`09c18a4`](https://github.com/python-zeroconf/python-zeroconf/commit/09c18a4173a013e67da5a1cdc7089452ba6f67ee))

* Ensure eventloop shutdown is threadsafe (#636)

- Prevent ConnectionResetError from being thrown on
  Windows with ProactorEventLoop on cpython 3.8+ ([`bbbbddf`](https://github.com/python-zeroconf/python-zeroconf/commit/bbbbddf40d78dbd62a84f2439763d0a59211c5b9))

* Update changelog (#635) ([`c854d03`](https://github.com/python-zeroconf/python-zeroconf/commit/c854d03efd31e1d002518a43221b347fa6ca5de5))

* Clear cache in ZeroconfServiceTypes tests to ensure responses can be mcast before the timeout (#634)

- We prevent the same record from being multicast within 1s
  because of RFC6762 sec 14. Since these test timeout after
  0.5s, the answers they are looking for many be suppressed.
  Since a legitimate querier will retry again later, we need
  to clear the cache to simulate that the record has not
  been multicast recently ([`a0977a1`](https://github.com/python-zeroconf/python-zeroconf/commit/a0977a1ddfd7a7a1abcf74c1d90c18021aebc910))

* Mark DNSOutgoing write functions as protected (#633) ([`5f66caa`](https://github.com/python-zeroconf/python-zeroconf/commit/5f66caaccf44c1504988cb82c1cba78d28dde7e7))

* Return early in the shutdown/close process (#632) ([`4ce33e4`](https://github.com/python-zeroconf/python-zeroconf/commit/4ce33e48e2094f17d8358cf221c7e2f9a8cb3568))

* Update changelog (#631) ([`64f6dd7`](https://github.com/python-zeroconf/python-zeroconf/commit/64f6dd7e244c86d58b962f48a50d07625f2a2a33))

* Remove unreachable cache check for DNSAddresses (#629)

- The ServiceBrowser would check to see if a DNSAddress was
  already in the cache and return early to avoid sending
  updates when the address already was held in the cache.
  This check was not needed since there is already a check
  a few lines before as `self.zc.cache.get(record)` which
  effectively does the same thing. This lead to the check
  never being covered in the tests and 2 cache lookups when
  only one was needed. ([`2b31612`](https://github.com/python-zeroconf/python-zeroconf/commit/2b31612e3f128b1193da9e0d2640f4e93fab2e3a))

* Add test for wait_condition_or_timeout_times_out util (#630) ([`2065b1d`](https://github.com/python-zeroconf/python-zeroconf/commit/2065b1d7ec7cb5d41c34826c2d8887bdd8a018b6))

* Return early on invalid data received (#628)

- Improve coverage for handling invalid incoming data ([`28a614e`](https://github.com/python-zeroconf/python-zeroconf/commit/28a614e0586a0ca1c5c1651b59c9a4d9c1af9a1b))

* Update changelog (#627) ([`215d6ba`](https://github.com/python-zeroconf/python-zeroconf/commit/215d6badb3db796b13a000b26953cb57c557e5e5))

* Add test to ensure ServiceBrowser sees port change as an update (#625) ([`113874a`](https://github.com/python-zeroconf/python-zeroconf/commit/113874a7b59ac9cc887b1b626ac1486781c7d56f))

* Fix random test failures due to monkey patching not being undone between tests (#626)

- Switch patching to use unitest.mock.patch to ensure the patch
  is reverted when the test is completed

Fixes #505 ([`5750f7c`](https://github.com/python-zeroconf/python-zeroconf/commit/5750f7ceef0441fe1cedc0d96e7ef5ccc232d875))

* Ensure zeroconf can be loaded when the system disables IPv6 (#624) ([`42d53c7`](https://github.com/python-zeroconf/python-zeroconf/commit/42d53c7c04a7bbf4e60e691e2e58fe7acfec8ad9))

* Update changelog (#623) ([`4d05961`](https://github.com/python-zeroconf/python-zeroconf/commit/4d05961088efa8b503cad5658afade874eaeec76))

* Eliminate aio sender thread (#622) ([`f15e84f`](https://github.com/python-zeroconf/python-zeroconf/commit/f15e84f3ee7a644792fe98edde84dd216b3497cb))

* Replace select loop with asyncio loop (#504) ([`8f00cfc`](https://github.com/python-zeroconf/python-zeroconf/commit/8f00cfca0e67dde6afda399da6984ed7d8f929df))

* Add support for handling QU questions (#621)

- Implements RFC 6762 sec 5.4:
  Questions Requesting Unicast Responses
  https://datatracker.ietf.org/doc/html/rfc6762#section-5.4 ([`9a32db8`](https://github.com/python-zeroconf/python-zeroconf/commit/9a32db8582588e4bf812fd5670a7e61c50631a2e))

* Add is_recent property to DNSRecord (#620)

- RFC 6762 defines recent as not multicast within one quarter of its TTL
  https://datatracker.ietf.org/doc/html/rfc6762#section-5.4 ([`1f36754`](https://github.com/python-zeroconf/python-zeroconf/commit/1f36754f3964738e496a1da9c24380e204aaff01))

* Protect the network against excessive packet flooding (#619) ([`0e644ad`](https://github.com/python-zeroconf/python-zeroconf/commit/0e644ad650627024c7a3f926a86f7d9ecc66e591))

* Ensure matching PTR queries are returned with the ANY query (#618)

Fixes #464 ([`b6365aa`](https://github.com/python-zeroconf/python-zeroconf/commit/b6365aa1f889a3045aa185f67354de622bd7ebd3))

* Suppress additionals when they are already in the answers section (#617) ([`427b728`](https://github.com/python-zeroconf/python-zeroconf/commit/427b7285269984cbb6f28c87a8bf8f864a5e15d7))

* Fix queries for AAAA records (#616) ([`0100c08`](https://github.com/python-zeroconf/python-zeroconf/commit/0100c08c5a3fb90d0795cf57f0bd3e11c7a94a0b))

* Breakout the query response handler into its own class (#615) ([`c828c75`](https://github.com/python-zeroconf/python-zeroconf/commit/c828c7555ed1fb82ff95ed578262d1553f19d903))

* Avoid including additionals when the answer is suppressed by known-answer supression (#614) ([`219aa3e`](https://github.com/python-zeroconf/python-zeroconf/commit/219aa3e54c944b2935c9a40cc15de19284aded3c))

* Add the ability for ServiceInfo.dns_addresses to filter by address type (#612) ([`aea2c8a`](https://github.com/python-zeroconf/python-zeroconf/commit/aea2c8ab24d4be19b34f407c854241e0d73d0525))

* Make DNSRecords hashable (#611)

- Allows storing them in a set for de-duplication

- Needed to be able to check for duplicates to solve https://github.com/jstasiak/python-zeroconf/issues/604 ([`b7d8678`](https://github.com/python-zeroconf/python-zeroconf/commit/b7d867878153fa600053869265260992e5462b2d))

* Ensure the QU bit is set for probe queries (#609)

- The bit should be set per
  https://datatracker.ietf.org/doc/html/rfc6762#section-8.1 ([`22bd147`](https://github.com/python-zeroconf/python-zeroconf/commit/22bd1475fb58c7c421c0009cd0c5c791cedb225d))

* Log destination when sending packets (#606) ([`850e211`](https://github.com/python-zeroconf/python-zeroconf/commit/850e2115aa79c10765dfc45a290a68193397de6c))

* Fix docs version to match readme (cpython 3.6+) (#602) ([`809b6df`](https://github.com/python-zeroconf/python-zeroconf/commit/809b6df376205e6ab5ce8fb5fe3a92e77662fe2d))

* Add ZeroconfServiceTypes to zeroconf.__all__ (#601)

- This class is in the readme, but is not exported by
  default ([`f6cd8f6`](https://github.com/python-zeroconf/python-zeroconf/commit/f6cd8f6d23459f9ed48ad06ff6702e606d620eaf))

* Ensure unicast responses can be sent to any source port (#598)

- Unicast responses were only being sent if the source port
  was 53, this prevented responses when testing with dig:

    dig -p 5353 @224.0.0.251 media-12.local

  The above query will now see a response ([`3556c22`](https://github.com/python-zeroconf/python-zeroconf/commit/3556c22aacc72e62c318955c084533b70311bcc9))

* Add id_ param to allow setting the id in the DNSOutgoing constructor (#599) ([`cb64e0d`](https://github.com/python-zeroconf/python-zeroconf/commit/cb64e0dd5d1c621f61d0d0f92ea282d287a9c242))

* Fix lookup of uppercase names in registry (#597)

- If the ServiceInfo was registered with an uppercase name and the query was
  for a lowercase name, it would not be found and vice-versa. ([`fe72524`](https://github.com/python-zeroconf/python-zeroconf/commit/fe72524dbaf934ca63ebce053e34f3e838743460))

* Add unicast property to DNSQuestion to determine if the QU bit is set (#593) ([`d2d8262`](https://github.com/python-zeroconf/python-zeroconf/commit/d2d826220bd4f287835ebb4304450cc2311d1db6))

* Reduce branching in DNSOutgoing.add_answer_at_time (#592) ([`35e25fd`](https://github.com/python-zeroconf/python-zeroconf/commit/35e25fd46f8d3689b723dd845eba9862a5dc8a22))

* Move notify listener tests to test_core (#591) ([`72032d6`](https://github.com/python-zeroconf/python-zeroconf/commit/72032d6dde2ee7388b8cb4545554519d3ffa8508))

* Set mypy follow_imports to skip as ignore is not a valid option (#590) ([`fd70ac1`](https://github.com/python-zeroconf/python-zeroconf/commit/fd70ac1b6bdded992f8fbbb723ca92f5395abf23))

* Relocate handlers tests to tests/test_handlers (#588) ([`8aa14d3`](https://github.com/python-zeroconf/python-zeroconf/commit/8aa14d33849c057c91a00e1093606081ade488e7))

* Relocate ServiceRegistry tests to tests/services/test_registry (#587) ([`ae6530a`](https://github.com/python-zeroconf/python-zeroconf/commit/ae6530a59e2d8ddb9a7367243c29c5e00665a82f))

* Disable flakey ServiceTypesQuery ipv6 win32 test (#586) ([`5cb5702`](https://github.com/python-zeroconf/python-zeroconf/commit/5cb5702fca2845e99b457e4427428497c3cd9b31))

* Relocate network utils tests to tests/utils/test_net (#585) ([`12f5676`](https://github.com/python-zeroconf/python-zeroconf/commit/12f567695b5364c9c5c5af0a7017d877de84274d))

* Relocate ServiceTypesQuery tests to tests/services/test_types (#584) ([`1fe282b`](https://github.com/python-zeroconf/python-zeroconf/commit/1fe282ba246505d172356cc8672307c7d125820d))

* Mark zeroconf.services as protected by renaming to zeroconf._services (#583)

- The public API should only access zeroconf and zeroconf.aio
  as internals may be relocated between releases ([`4a88066`](https://github.com/python-zeroconf/python-zeroconf/commit/4a88066d66b2f2a00ebc388c5cda478c52cb9e6c))

* Mark zeroconf.utils as protected by renaming to zeroconf._utils (#582)

- The public API should only access zeroconf and zeroconf.aio
  as internals may be relocated between releases ([`cc5bc36`](https://github.com/python-zeroconf/python-zeroconf/commit/cc5bc36f6f7597a0adb0d637147c2f93ca243ff4))

* Mark zeroconf.cache as protected by renaming to zeroconf._cache (#581)

- The public API should only access zeroconf and zeroconf.aio
  as internals may be relocated between releases ([`a16e85b`](https://github.com/python-zeroconf/python-zeroconf/commit/a16e85b20c2069aa9cee0510c618cb61d46dc19c))

* Mark zeroconf.exceptions as protected by renaming to zeroconf._exceptions (#580)

- The public API should only access zeroconf and zeroconf.aio
  as internals may be relocated between releases ([`241700a`](https://github.com/python-zeroconf/python-zeroconf/commit/241700a07a76a8c45afbe1bdd8325cd9f0eb0168))

* Fix flakey backoff test race on startup (#579) ([`dd9ada7`](https://github.com/python-zeroconf/python-zeroconf/commit/dd9ada781fdb1d5efc7c6ad194426e92550245b1))

* Mark zeroconf.logger as protected by renaming to zeroconf._logger (#578) ([`500066f`](https://github.com/python-zeroconf/python-zeroconf/commit/500066f940aa89737f343976ee0387eae97eac37))

* Mark zeroconf.handlers as protected by renaming to zeroconf._handlers (#577)

- The public API should only access zeroconf and zeroconf.aio
  as internals may be relocated between releases ([`1a2ee68`](https://github.com/python-zeroconf/python-zeroconf/commit/1a2ee6892e996c1e84ba97082e5cda609d1d55d7))

* Log zeroconf.asyncio deprecation warning with the logger module (#576) ([`c29a235`](https://github.com/python-zeroconf/python-zeroconf/commit/c29a235eb59ed3b4883305cf11f8bf9fa06284d3))

* Mark zeroconf.core as protected by renaming to zeroconf._core (#575) ([`601e8f7`](https://github.com/python-zeroconf/python-zeroconf/commit/601e8f70499638a6f24291bc0a28054fd78243c0))

* Mark zeroconf.dns as protected by renaming to zeroconf._dns (#574)

- The public API should only access zeroconf and zeroconf.aio
  as internals may be relocated between releases ([`0e61b15`](https://github.com/python-zeroconf/python-zeroconf/commit/0e61b1502c7fd3412f979bc4d651ee016e712de9))

* Update changelog (#573) ([`f10a562`](https://github.com/python-zeroconf/python-zeroconf/commit/f10a562471ad89527e6eef6ba935a27177bb1417))

* Relocate services tests to test_services (#570) ([`ae552e9`](https://github.com/python-zeroconf/python-zeroconf/commit/ae552e94732568fd798e1f2d0e811849edff7790))

* Remove DNSOutgoing.packet backwards compatibility (#569)

- DNSOutgoing.packet only returned a partial message when the
  DNSOutgoing contents exceeded _MAX_MSG_ABSOLUTE or _MAX_MSG_TYPICAL
  This was a legacy function that was replaced with .packets()
  which always returns a complete payload in #248  As packet()
  should not be used since it will end up missing data, it has
  been removed ([`1e7c074`](https://github.com/python-zeroconf/python-zeroconf/commit/1e7c07481bb0cd08fe492dab02be888c6a1dadf2))

* Breakout DNSCache into zeroconf.cache (#568) ([`0e0bc2a`](https://github.com/python-zeroconf/python-zeroconf/commit/0e0bc2a901ed1d64e357c63e9fb8655f3a6e9298))

* Removed protected imports from zeroconf namespace (#567)

- These protected items are not intended to be part of the
  public API ([`a8420cd`](https://github.com/python-zeroconf/python-zeroconf/commit/a8420cde192647486eba4da4e54df9d0fe65adba))

* Update setup.py for utils and services (#562) ([`7807fa0`](https://github.com/python-zeroconf/python-zeroconf/commit/7807fa0dfdab20d950c446f17b7233a8c65cbab1))

* Move additional dns tests to test_dns (#561) ([`ae1ce09`](https://github.com/python-zeroconf/python-zeroconf/commit/ae1ce092de7eb4797da0f56e9eb8e538c95a8cc1))

* Move exceptions tests to test_exceptions (#560) ([`b5d848d`](https://github.com/python-zeroconf/python-zeroconf/commit/b5d848de1ed95c55f8c262bcf0811248818da901))

* Move additional tests to test_core (#559) ([`eb37f08`](https://github.com/python-zeroconf/python-zeroconf/commit/eb37f089579fdc5a405dbc2f0ce5620cf9d1b011))

* Relocate additional dns tests to test_dns (#558) ([`18b9d0a`](https://github.com/python-zeroconf/python-zeroconf/commit/18b9d0a8bd07c0a0d2923763a5f131905c31e0df))

* Relocate dns tests to test_dns (#557) ([`f0d99e2`](https://github.com/python-zeroconf/python-zeroconf/commit/f0d99e2e68791376a8517254338c708a3244f178))

* Relocate some of the services tests to test_services (#556) ([`715cd9a`](https://github.com/python-zeroconf/python-zeroconf/commit/715cd9a1d208139862e6d9d718114e1e472efd28))

* Fix invalid typing in ServiceInfo._set_text (#554) ([`3d69656`](https://github.com/python-zeroconf/python-zeroconf/commit/3d69656c4e5fbd8f90d54826877a04120d5ec951))

* Add missing coverage for ipv6 network utils (#555) ([`3dfda64`](https://github.com/python-zeroconf/python-zeroconf/commit/3dfda644efef83640e80876e4fe7da10e87b5990))

* Move ZeroconfServiceTypes to zeroconf.services.types (#553) ([`e50b62b`](https://github.com/python-zeroconf/python-zeroconf/commit/e50b62bb633916d5b84df7bcf7a804c9e3ef7fc2))

* Add recipe for TYPE_CHECKING to .coveragerc (#552) ([`e7fb4e5`](https://github.com/python-zeroconf/python-zeroconf/commit/e7fb4e5fb2a6b2163b143a63e2a9e8c5d1eca482))

* Move QueryHandler and RecordManager handlers into zeroconf.handlers (#551) ([`5b489e5`](https://github.com/python-zeroconf/python-zeroconf/commit/5b489e5b15ff89a0ffc000ccfeab2a8af346a65e))

* Move ServiceListener to zeroconf.services (#550) ([`ffdc988`](https://github.com/python-zeroconf/python-zeroconf/commit/ffdc9887ede1f867c155743b344efc53e0ceee42))

* Move the ServiceRegistry into its own module (#549) ([`4086fb4`](https://github.com/python-zeroconf/python-zeroconf/commit/4086fb4304b0653153865306e46c865c90137922))

* Move ServiceStateChange to zeroconf.services (#548) ([`c8a0a71`](https://github.com/python-zeroconf/python-zeroconf/commit/c8a0a71c31252bbc4a242701bc786eb419e1a8e8))

* Relocate core functions into zeroconf.core (#547) ([`bf0e867`](https://github.com/python-zeroconf/python-zeroconf/commit/bf0e867ead1e48e05a27fe8db69900d9dc387ea2))

* Breakout service classes into zeroconf.services (#544) ([`bdea21c`](https://github.com/python-zeroconf/python-zeroconf/commit/bdea21c0a61b6d9d0af3810f18dbc2fc2364c484))

* Move service_type_name to zeroconf.utils.name (#543) ([`b4814f5`](https://github.com/python-zeroconf/python-zeroconf/commit/b4814f5f216cd4072bafdd7dd1e68ee522f329c2))

* Relocate DNS classes to zeroconf.dns (#541) ([`1e3e7df`](https://github.com/python-zeroconf/python-zeroconf/commit/1e3e7df8b7fdacd90cf5d864411e5db5a915be94))

* Update zeroconf.aio import locations (#539) ([`8733cad`](https://github.com/python-zeroconf/python-zeroconf/commit/8733cad2eae71ebdf94ecadc6fd5439882477235))

* Move int2byte to zeroconf.utils.struct (#540) ([`6af42b5`](https://github.com/python-zeroconf/python-zeroconf/commit/6af42b54640ebba541302bfcf7688b3926453b15))

* Breakout network utils into zeroconf.utils.net (#537) ([`5af3eb5`](https://github.com/python-zeroconf/python-zeroconf/commit/5af3eb58bfdc1736e6db175c4c6f7c6f2c05b694))

* Move time utility functions into zeroconf.utils.time (#536) ([`7ff810a`](https://github.com/python-zeroconf/python-zeroconf/commit/7ff810a02e608fae39634be09d6c3ce0a93485b8))

* Avoid making DNSOutgoing aware of the Zeroconf object (#535)

- This is not a breaking change since this code has not
  yet shipped ([`2976cc2`](https://github.com/python-zeroconf/python-zeroconf/commit/2976cc2001cbba2c0afc57b9a3d301f382ddac8a))

* Add missing coverage for QuietLogger (#534) ([`328c1b9`](https://github.com/python-zeroconf/python-zeroconf/commit/328c1b9acdcd5cafa2df3e5b4b833b908d299500))

* Move logger into zeroconf.logger (#533) ([`e2e4eed`](https://github.com/python-zeroconf/python-zeroconf/commit/e2e4eede9117827f47c66a4852dd2d236b46ecda))

* Move exceptions into zeroconf.exceptions (#532) ([`5100506`](https://github.com/python-zeroconf/python-zeroconf/commit/5100506f896b649e6a6a8e2efb592362cd2644d3))

* Move constants into const.py (#531) ([`89d4755`](https://github.com/python-zeroconf/python-zeroconf/commit/89d4755106a6c3bced395b0a26eb3082c1268fa1))

* Move asyncio utils into zeroconf.utils.aio (#530) ([`2d8a27a`](https://github.com/python-zeroconf/python-zeroconf/commit/2d8a27a54aee298af74121986b4ea76f1f50b421))

* Relocate tests to tests directory (#527) ([`3f1a5a7`](https://github.com/python-zeroconf/python-zeroconf/commit/3f1a5a7b7a929d5f699812a809347b0c2f799fbf))

* Fix flakey test_update_record test (round 2) (#528) ([`14542bd`](https://github.com/python-zeroconf/python-zeroconf/commit/14542bd2bd327fd9b3d93cfb48a3bf09d6c89e15))

* Move ipversion auto detection code into its own function (#524) ([`16d40b5`](https://github.com/python-zeroconf/python-zeroconf/commit/16d40b50ccab6a8d53fe4aeb7b0006f7fd67ef53))

* Fix flakey test_update_record (#525)

- Ensure enough time has past that the first record update
  was processed before sending the second one ([`f49342c`](https://github.com/python-zeroconf/python-zeroconf/commit/f49342cdaff2d012ad23635b49ae746ad71333df))

* Update python compatibility as PyPy3 7.2 is required (#523)

- When the version requirement changed to cpython 3.6, PyPy
  was not bumped as well ([`b37d115`](https://github.com/python-zeroconf/python-zeroconf/commit/b37d115a233b61e2989d1439f65cdd911b86f407))

* Make the cache cleanup interval a constant (#522) ([`7ce29a2`](https://github.com/python-zeroconf/python-zeroconf/commit/7ce29a2f736af13886aa66dc1c49e15768e6fdcc))

* Add test helper to inject DNSIncoming (#518) ([`ef7aa25`](https://github.com/python-zeroconf/python-zeroconf/commit/ef7aa250e140d70b8c62abf4d13dcaa36f128c63))

* Remove broad exception catch from RecordManager.remove_listener (#517) ([`e125239`](https://github.com/python-zeroconf/python-zeroconf/commit/e12523933819087d2a087b8388e79b24af058a58))

* Small cleanups to RecordManager.add_listener (#516) ([`f80a051`](https://github.com/python-zeroconf/python-zeroconf/commit/f80a0515cf73b1e304d0615f8cee91ae38ac1ae8))

* Move RecordUpdateListener management into RecordManager (#514) ([`6cc3adb`](https://github.com/python-zeroconf/python-zeroconf/commit/6cc3adb020115ef9626caf61bb5f7550a2da8b4c))

* Update changelog (#513) ([`3d6c682`](https://github.com/python-zeroconf/python-zeroconf/commit/3d6c68278713a2ca66e27938feedcc451a078369))

* Break out record updating into RecordManager (#512) ([`9a766a2`](https://github.com/python-zeroconf/python-zeroconf/commit/9a766a2a96abd0f105056839b5c30f2ede31ea2e))

* Remove uneeded wait in the Engine thread (#511)

- It is not longer necessary to wait since the socketpair
    was added in #243 which will cause the select to unblock
    when a new socket is added or removed. ([`70b455b`](https://github.com/python-zeroconf/python-zeroconf/commit/70b455ba53ce43e9280c02612e8a89665abd57f6))

* Stop monkey patching send in the TTL test (#510) ([`954ca3f`](https://github.com/python-zeroconf/python-zeroconf/commit/954ca3fb498bdc7cd5a6a168c40ad5b6b2476e71))

* Stop monkey patching send in the PTR optimization test (#509) ([`db866f7`](https://github.com/python-zeroconf/python-zeroconf/commit/db866f7d032ed031e6aa5e14fba24b3dafeafa8d))

* Extract code for handling queries into QueryHandler (#507) ([`1cfcc56`](https://github.com/python-zeroconf/python-zeroconf/commit/1cfcc5636a845924eb683ad4acf4d9a36ef85fb7))

* Update changelog for zeroconf.asyncio -> zeroconf.aio (#506) ([`26b7005`](https://github.com/python-zeroconf/python-zeroconf/commit/26b70050ffe7dee4fb34428f285be377d1d8f210))

* Rename zeroconf.asyncio to zeroconf.aio (#503)

- The asyncio name could shadow system asyncio in some cases. If
  zeroconf is in sys.path, this would result in loading zeroconf.asyncio
  when system asyncio was intended.

- An `zeroconf.asyncio` shim module has been added that imports `zeroconf.aio`
  that was available in 0.31 to provide backwards compatibility in 0.32.
  This module will be removed in 0.33 to fix the underlying problem
  detailed in #502 ([`bfca3b4`](https://github.com/python-zeroconf/python-zeroconf/commit/bfca3b46fd9a395f387bd90b68c523a3ca84bde4))

* Update changelog, move breaking changes to the top of the list (#501) ([`9b480bc`](https://github.com/python-zeroconf/python-zeroconf/commit/9b480bc1abb2c2702f60796f2edae76ce03ca5d4))

* Set the TC bit for query packets where the known answers span multiple packets (#494) ([`f04a2eb`](https://github.com/python-zeroconf/python-zeroconf/commit/f04a2eb43745eba7c43c9c56179ed1fceb992bd8))

* Ensure packets are properly seperated when exceeding maximum size (#498)

- Ensure that questions that exceed the max packet size are
  moved to the next packet. This fixes DNSQuestions being
  sent in multiple packets in violation of:
  https://datatracker.ietf.org/doc/html/rfc6762#section-7.2

- Ensure only one resource record is sent when a record
  exceeds _MAX_MSG_TYPICAL
  https://datatracker.ietf.org/doc/html/rfc6762#section-17 ([`e2908c6`](https://github.com/python-zeroconf/python-zeroconf/commit/e2908c6c89802ba7a0ea51ac351da40bce3f1cb6))

* Make a base class for DNSIncoming and DNSOutgoing (#497) ([`38e4b42`](https://github.com/python-zeroconf/python-zeroconf/commit/38e4b42b847e700db52bc51973210efc485d8c23))

* Update internal version check to match docs (3.6+) (#491) ([`20f8b3d`](https://github.com/python-zeroconf/python-zeroconf/commit/20f8b3d6fb8d117b0c3c794c4075a00e117e3f31))

* Remove unused __ne__ code from Python 2 era (#492) ([`f0c02a0`](https://github.com/python-zeroconf/python-zeroconf/commit/f0c02a02c1a2d7c914c62479bad4957b06471661))

* Lint before testing in the CI (#488) ([`69880ae`](https://github.com/python-zeroconf/python-zeroconf/commit/69880ae6ca4d4f0a7d476b0271b89adea92b9389))

* Add AsyncServiceBrowser example (#487) ([`ef9334f`](https://github.com/python-zeroconf/python-zeroconf/commit/ef9334f1279d029752186bc6f4a1ebff6229bf5b))

* Move threading daemon property into ServiceBrowser class (#486) ([`275765a`](https://github.com/python-zeroconf/python-zeroconf/commit/275765a4fd3b477b79163c04f6411709e14506b9))

* Enable test_integration_with_listener_class test on PyPy (#485) ([`49db96d`](https://github.com/python-zeroconf/python-zeroconf/commit/49db96dae466a602662f4fde1537f62a8c8d3110))

* RecordUpdateListener now uses update_records instead of update_record (#419) ([`0a69aa0`](https://github.com/python-zeroconf/python-zeroconf/commit/0a69aa0d37e13cb2c65ceb5cc3ab0fd7e9d34b22))

* AsyncServiceBrowser must recheck for handlers to call when holding condition (#483)

- There was a short race condition window where the AsyncServiceBrowser
  could add to _handlers_to_call in the Engine thread, have the
  condition notify_all called, but since the AsyncServiceBrowser was
  not yet holding the condition it would not know to stop waiting
  and process the handlers to call. ([`9606936`](https://github.com/python-zeroconf/python-zeroconf/commit/960693628006e23fd13fcaefef915ca0c84401b9))

* Relocate ServiceBrowser wait time calculation to seperate function (#484)

- Eliminate the need to duplicate code between the ServiceBrowser
  and AsyncServiceBrowser to calculate the wait time. ([`9c06ce1`](https://github.com/python-zeroconf/python-zeroconf/commit/9c06ce15db31ebffe3a556896393d48cb786b5d9))

* Switch from using an asyncio.Event to asyncio.Condition for waiting (#482) ([`393910b`](https://github.com/python-zeroconf/python-zeroconf/commit/393910b67ac667a660ee9351cc8f94310937f654))

* ServiceBrowser must recheck for handlers to call when holding condition (#477) ([`8da00ca`](https://github.com/python-zeroconf/python-zeroconf/commit/8da00caf31e007153e10a8038a0a484edea03c2f))

* Provide a helper function to convert milliseconds to seconds (#481) ([`849e9bc`](https://github.com/python-zeroconf/python-zeroconf/commit/849e9bc792c6cc77b879b4761195192bea1720ce))

* Fix AsyncServiceInfo.async_request not waiting long enough (#480)

- The call to async_wait should have been in milliseconds, but
  the time was being passed in seconds which resulted in waiting
  1000x shorter ([`b0c0cdc`](https://github.com/python-zeroconf/python-zeroconf/commit/b0c0cdc6779dc095cf03ebd92652af69800b7bca))

* Add support for updating multiple records at once to ServiceInfo (#474)

- Adds `update_records` method to `ServiceInfo` ([`ed53f62`](https://github.com/python-zeroconf/python-zeroconf/commit/ed53f6283265eb8fb506d4af8fb31bd4eaa7292b))

* Narrow exception catch in DNSAddress.__repr__ to only expected exceptions (#473) ([`b853413`](https://github.com/python-zeroconf/python-zeroconf/commit/b8534130ec31a6be191fcc60615ab2fd02fd8d7a))

* Add test coverage to ensure ServiceInfo rejects expired records (#468) ([`d0f5a60`](https://github.com/python-zeroconf/python-zeroconf/commit/d0f5a60275ccf810407055c63ca9080fa6654443))

* Reduce branching in service_type_name (#472) ([`00af5ad`](https://github.com/python-zeroconf/python-zeroconf/commit/00af5adc4be76afd23135d37653119f45c57a531))

* Fix flakey test_update_record (#470) ([`1eaeef2`](https://github.com/python-zeroconf/python-zeroconf/commit/1eaeef2d6f07efba67e91699529f8361226233ce))

* Reduce branching in Zeroconf.handle_response (#467)

- Adds `add_records` and `remove_records` to `DNSCache` to
  permit multiple records to be added or removed in one call

- This change is not enough to remove the too-many-branches
  pylint disable, however when combined with #419 it should
  no longer be needed ([`8a9ae29`](https://github.com/python-zeroconf/python-zeroconf/commit/8a9ae29b6f6643f3625938ac44df66dcc556de46))

* Ensure PTR questions asked in uppercase are answered (#465) ([`7a50402`](https://github.com/python-zeroconf/python-zeroconf/commit/7a5040247cbaad6bed3fc1204820dfc31ed9b0ae))

* Clear cache between ServiceTypesQuery tests (#466)

- Ensures the test relies on the ZeroconfServiceTypes.find making
  the correct calls instead of the cache from the previous call ([`c3365e1`](https://github.com/python-zeroconf/python-zeroconf/commit/c3365e1fd060cebc63cc42443260bd785077c246))

* Break apart Zeroconf.handle_query to reduce branching (#462) ([`c1ed987`](https://github.com/python-zeroconf/python-zeroconf/commit/c1ed987ede34b0049e6466e673b1629d7cd0cd6a))

* Support for context managers in Zeroconf and AsyncZeroconf (#284)

Co-authored-by: J. Nick Koston <nick@koston.org> ([`4c4b529`](https://github.com/python-zeroconf/python-zeroconf/commit/4c4b529c841f015108a7489bd8f3b92a5e57e827))

* Use constant for service type enumeration (#461) ([`558cec3`](https://github.com/python-zeroconf/python-zeroconf/commit/558cec3687ac7e7f494ab7aa4ce574c1e784b81f))

* Reduce branching in Zeroconf.handle_response (#459) ([`ceb0def`](https://github.com/python-zeroconf/python-zeroconf/commit/ceb0def1b43f2e55bb17e33d13d4efdaa055221c))

* Reduce branching in Zeroconf.handle_query (#460) ([`5e24da0`](https://github.com/python-zeroconf/python-zeroconf/commit/5e24da08bc463bf79b27eb3768ec01755804f403))

* Enable pylint (#438) ([`6fafdee`](https://github.com/python-zeroconf/python-zeroconf/commit/6fafdee241571d68937e29ee0a2b1bd5ef0038d9))

* Trap OSError directly in Zeroconf.send instead of checking isinstance (#453)

- Fixes: Instance of 'Exception' has no 'errno' member (no-member) ([`9510808`](https://github.com/python-zeroconf/python-zeroconf/commit/9510808cfd334b0b2f6381da8214225c4cfbf6a0))

* Disable protected-access on the ServiceBrowser usage of _handlers_lock (#452)

- This will be fixed in https://github.com/jstasiak/python-zeroconf/pull/419 ([`69c4cf6`](https://github.com/python-zeroconf/python-zeroconf/commit/69c4cf69bbc34474e70eac3ad0fe905be7ab4eb4))

* Mark functions with too many branches in need of refactoring (#455) ([`5fce89d`](https://github.com/python-zeroconf/python-zeroconf/commit/5fce89db2707b163231aec216e4c4fc310527e4c))

* Disable pylint no-self-use check on abstract methods (#451) ([`7544cdf`](https://github.com/python-zeroconf/python-zeroconf/commit/7544cdf956c4eeb4b688729432ba87278f606b7c))

* Use unique name in test_async_service_browser test (#450) ([`f26a92b`](https://github.com/python-zeroconf/python-zeroconf/commit/f26a92bc2abe61f5a2b5acd76991f81d07452201))

* Disable no-member check for WSAEINVAL false positive (#454) ([`ef0cf8e`](https://github.com/python-zeroconf/python-zeroconf/commit/ef0cf8e393a8ffdccb3cd2094a8764f707f518c1))

* Mark methods used by asyncio without self use (#447) ([`7e03f83`](https://github.com/python-zeroconf/python-zeroconf/commit/7e03f836dd7a4ee938bfff21cd150e863f608b5e))

* Extract _get_queue from _AsyncSender (#444) ([`18851ed`](https://github.com/python-zeroconf/python-zeroconf/commit/18851ed4c0f605996798472e1a68dded16d41ff6))

* Add missing update_service method to ZeroconfServiceTypes (#449) ([`ffc6cbb`](https://github.com/python-zeroconf/python-zeroconf/commit/ffc6cbb94d7401a70ebd6f747ed6c5e56e528bb0))

* Fix redefining argument with the local name 'record' in ServiceInfo.update_record (#448) ([`929ba12`](https://github.com/python-zeroconf/python-zeroconf/commit/929ba12d046496782491d96160e6cb8d0d04cfe5))

* Remove unneeded-not in new_socket (#445) ([`424c002`](https://github.com/python-zeroconf/python-zeroconf/commit/424c00257083f1d091a52ff0c966b306eea70efb))

* Disable broad except checks in places we still catch broad exceptions (#443) ([`6002c9c`](https://github.com/python-zeroconf/python-zeroconf/commit/6002c9c88a9a49814f86070c07925f798a61461a))

* Merge _TYPE_CNAME and _TYPE_PTR comparison in DNSIncoming.read_others (#442) ([`41be4f4`](https://github.com/python-zeroconf/python-zeroconf/commit/41be4f4db0501adb9fbaa6b353fbcb36a45e6e21))

* Convert unnecessary use of a comprehension to a list (#441) ([`a70370a`](https://github.com/python-zeroconf/python-zeroconf/commit/a70370a0f653df911cc6f641522cec0fcc8471a3))

* Remove unused now argument from ServiceInfo._process_record (#440) ([`594da70`](https://github.com/python-zeroconf/python-zeroconf/commit/594da709273c2e0a53fee2f9ad7fcec607ad0868))

* Disable pylint too-many-branches for functions that need refactoring (#439) ([`4bcb698`](https://github.com/python-zeroconf/python-zeroconf/commit/4bcb698bda0ec7266d5e454b5e81a07eb64be32a))

* Cleanup unused variables (#437) ([`8412eb7`](https://github.com/python-zeroconf/python-zeroconf/commit/8412eb791dd5ad1c287c1d7cc24c5db75a5291b7))

* Cleanup unnecessary else after returns (#436) ([`1d3f986`](https://github.com/python-zeroconf/python-zeroconf/commit/1d3f986e00e18682c209cecbdea2481f4ca987b5))

* Update changelog for latest changes (#435) ([`6737e13`](https://github.com/python-zeroconf/python-zeroconf/commit/6737e13d8e6227b96d5cc0e776c62889b7dc4fd3))

* Add zeroconf.asyncio to the docs (#434) ([`5460cae`](https://github.com/python-zeroconf/python-zeroconf/commit/5460caef83b5cdb9c5d637741ed95dea6b328f08))

* Fix warning when generating sphinx docs (#432)

- `docstring of zeroconf.ServiceInfo:5: WARNING: Unknown target name: "type".` ([`e5a0c9a`](https://github.com/python-zeroconf/python-zeroconf/commit/e5a0c9a45df93a668f3611ddf5c41a1800cb4556))

* Implement an AsyncServiceBrowser to compliment the sync ServiceBrowser (#429) ([`415a7b7`](https://github.com/python-zeroconf/python-zeroconf/commit/415a7b762030e9d236bef71f39156686a0b277f9))

* Seperate non-thread specific code from ServiceBrowser into _ServiceBrowserBase (#428) ([`e7b2bb5`](https://github.com/python-zeroconf/python-zeroconf/commit/e7b2bb5e351f04f4f1e14ef5a20ed2111f8097c4))

* Remove is_type_unique as it is unused (#426) ([`e68e337`](https://github.com/python-zeroconf/python-zeroconf/commit/e68e337cd482e06a422b2d2e2e6ae12ce1673ce5))

* Avoid checking the registry when answering requests for _services._dns-sd._udp.local. (#425)

- _services._dns-sd._udp.local. is a special case and should never
  be in the registry ([`47e266e`](https://github.com/python-zeroconf/python-zeroconf/commit/47e266eb66be36b355f1738cd4d2f7369712b7b3))

* Remove unused argument from ServiceInfo.dns_addresses (#423)

- This should always return all addresses since its _CLASS_UNIQUE ([`fc97e5c`](https://github.com/python-zeroconf/python-zeroconf/commit/fc97e5c3ad35da789373a1898c00efe0f13a3b5f))

* A methods to generate DNSRecords from ServiceInfo (#422) ([`41de419`](https://github.com/python-zeroconf/python-zeroconf/commit/41de419453c0679c5a04ec248339783afbeb0e4f))

* Seperate logic for consuming records in ServiceInfo (#421) ([`8bca030`](https://github.com/python-zeroconf/python-zeroconf/commit/8bca0305deae0db8ced7e213be3aaee975985c56))

* Seperate query generation for ServiceBrowser (#420) ([`58cfcf0`](https://github.com/python-zeroconf/python-zeroconf/commit/58cfcf0c902b5e27937f118bf4f7a855db635301))

* Add async_request example with browse (#415) ([`7f08826`](https://github.com/python-zeroconf/python-zeroconf/commit/7f08826c03b7997758ff0236834bf6f1a091c558))

* Add async_register_service/async_unregister_service example (#414) ([`71cfbcb`](https://github.com/python-zeroconf/python-zeroconf/commit/71cfbcb85bdd5948f1b96a871b10e9e35ab76c3b))

* Update changelog for 0.32.0 (#411) ([`bb83edf`](https://github.com/python-zeroconf/python-zeroconf/commit/bb83edfbca339fb6ec20b821d79b171220f5e675))

* Add async_get_service_info to AsyncZeroconf and async_request to AsyncServiceInfo (#408) ([`0fa049c`](https://github.com/python-zeroconf/python-zeroconf/commit/0fa049c2e0f5e9f18830583a8df2736630c891e2))

* Add async_wait function to AsyncZeroconf (#410) ([`53306e1`](https://github.com/python-zeroconf/python-zeroconf/commit/53306e1b99d9133590d47081994ee77cef468828))

* Add support for registering notify listeners (#409)

- Notify listeners will be used by AsyncZeroconf to set
  asyncio.Event objects when new data is received

- Registering a notify listener:
   notify_listener = YourNotifyListener()
   Use zeroconf.add_notify_listener(notify_listener)

- Unregistering a notify listener:
   Use zeroconf.remove_notify_listener(notify_listener)

- Notify listeners must inherit from the NotifyListener
  class ([`745087b`](https://github.com/python-zeroconf/python-zeroconf/commit/745087b234dd5ff65b4b041a7221d58030a69cdd))

* Remove unreachable code in ServiceInfo.get_name (#407) ([`ff31f38`](https://github.com/python-zeroconf/python-zeroconf/commit/ff31f386273fbe9fd0b466bbe5f724c815745215))

* Allow passing in a sync Zeroconf instance to AsyncZeroconf (#406)

- Uses the same pattern as ZeroconfServiceTypes.find ([`2da6198`](https://github.com/python-zeroconf/python-zeroconf/commit/2da6198b2e60a598580637e80b3bd579c1f845a5))

* Use a dedicated thread for sending outgoing packets with asyncio (#404)

- Sends now go into a queue and are processed by the thread FIFO

- Avoids overwhelming the executor when registering multiple
  services in parallel ([`1e7b46c`](https://github.com/python-zeroconf/python-zeroconf/commit/1e7b46c36f6e0735b44d3edd9740891a2dc0c761))

* Seperate query generation for Zeroconf (#403)

- Will be used to send the query in asyncio ([`e753078`](https://github.com/python-zeroconf/python-zeroconf/commit/e753078f0345fa28ffceb8de69542c8549d2994c))

* Seperate query generation in ServiceInfo (#401) ([`bddf69c`](https://github.com/python-zeroconf/python-zeroconf/commit/bddf69c0839eda966376987a8c4a1fbe3d865529))

* Remove unreachable code in ServiceInfo (part 2) (#402)

- self.server is never None ([`4ae27be`](https://github.com/python-zeroconf/python-zeroconf/commit/4ae27beba29c6e9ac1782f40eadda584b4722af7))

* Remove unreachable code in ServiceInfo (#400)

- self.server is never None ([`dd63835`](https://github.com/python-zeroconf/python-zeroconf/commit/dd6383589b161e828def0ed029519a645e434512))

* Update changelog with latest changes (#394) ([`a6010a9`](https://github.com/python-zeroconf/python-zeroconf/commit/a6010a94b626a9a1585cc47417c08516020729d7))

* Add test coverage for multiple AAAA records (#391) ([`acf174d`](https://github.com/python-zeroconf/python-zeroconf/commit/acf174db93ee60f1a80d501eb691d9cb434a90b7))

* Enable IPv6 in the CI (#393) ([`ec2fafd`](https://github.com/python-zeroconf/python-zeroconf/commit/ec2fafd904cd2d341a3815fcf6d34508dcddda5a))

* Fix IPv6 setup under MacOS when binding to "" (#392)

- Setting IP_MULTICAST_TTL and IP_MULTICAST_LOOP does not work under
  MacOS when the bind address is "" ([`d67d5f4`](https://github.com/python-zeroconf/python-zeroconf/commit/d67d5f41effff4c01735de0ae64ed25a5dbe7567))

* Update changelog for 0.32.0 (Unreleased) (#390) ([`33a3a6a`](https://github.com/python-zeroconf/python-zeroconf/commit/33a3a6ae42ef8c4ea0f606ad2a02df3f6bc13752))

* Ensure ZeroconfServiceTypes.find always cancels the ServiceBrowser (#389) ([`8f4d2e8`](https://github.com/python-zeroconf/python-zeroconf/commit/8f4d2e858a5efadeb33120322c1169f3ce7d6e0c))

* Fix flapping test: test_update_record (#388) ([`ba8d8e3`](https://github.com/python-zeroconf/python-zeroconf/commit/ba8d8e3e658c71e0d603db3f4c5bdfe8e508710a))

* Simplify DNSPointer processing in ServiceBrowser (#386) ([`709bd9a`](https://github.com/python-zeroconf/python-zeroconf/commit/709bd9abae63cf566220693501cd37cf74391ccf))

* Ensure listeners do not miss initial packets if Engine starts too quickly (#387) ([`62a02d7`](https://github.com/python-zeroconf/python-zeroconf/commit/62a02d774fd874340fa3043bd3bf260a77ffe3d8))

* Update changelog with latest commits (#384) ([`69d9357`](https://github.com/python-zeroconf/python-zeroconf/commit/69d9357b3dae7a99d302bf4ad71d4ed45cbe3e42))

* Ensure the cache is checked for name conflict after final service query with asyncio (#382)

- The check was not happening after the last query ([`5057f97`](https://github.com/python-zeroconf/python-zeroconf/commit/5057f97b9b724c041d2bee65972fe3637bf04f0b))

* Fix multiple unclosed instances in tests (#383) ([`69a79b9`](https://github.com/python-zeroconf/python-zeroconf/commit/69a79b9fd48a24d311520e228c78b2aae52d1dd5))

* Update changelog with latest merges (#381) ([`2b502bc`](https://github.com/python-zeroconf/python-zeroconf/commit/2b502bc2e21efa2f840c42ed79f850b276a8c103))

* Complete ServiceInfo request as soon as all questions are answered (#380)

- Closes a small race condition where there were no questions
  to ask because the cache was populated in between checks ([`3afa5c1`](https://github.com/python-zeroconf/python-zeroconf/commit/3afa5c13f2be956505428c5b01f6ce507845131a))

* Coalesce browser questions scheduled at the same time (#379)

- With multiple types, the ServiceBrowser questions can be
  chatty because it would generate a question packet for
  each type. If multiple types are due to be requested,
  try to combine the questions into a single outgoing
  packet(s) ([`60c1895`](https://github.com/python-zeroconf/python-zeroconf/commit/60c1895e67a6147ab8c6ba7d21d4fe5adec3e590))

* Bump version to 0.31.0 to match released version (#378) ([`23442d2`](https://github.com/python-zeroconf/python-zeroconf/commit/23442d2e5a0336a64646cb70f2ce389746744ce0))

* Update changelog with latest merges (#377) ([`5535ea8`](https://github.com/python-zeroconf/python-zeroconf/commit/5535ea8c365557681721fdafdcabfc342c75daf5))

* Ensure duplicate packets do not trigger duplicate updates (#376)

- If TXT or SRV records update was already processed and then
  recieved again, it was possible for a second update to be
  called back in the ServiceBrowser ([`b158b1c`](https://github.com/python-zeroconf/python-zeroconf/commit/b158b1cff31620d5cf27969e475d788332f4b38c))

* Only trigger a ServiceStateChange.Updated event when an ip address is added (#375) ([`5133742`](https://github.com/python-zeroconf/python-zeroconf/commit/51337425c9be08d59d496c6783d07d5e4e2382d4))

* Fix RFC6762 Section 10.2 paragraph 2 compliance (#374) ([`03f2eb6`](https://github.com/python-zeroconf/python-zeroconf/commit/03f2eb688859a78807305771d04b216e20e72064))

* Reduce length of ServiceBrowser thread name with many types (#373)

- Before

"zeroconf-ServiceBrowser__ssh._tcp.local.-_enphase-envoy._tcp.local.-_hap._udp.local."
"-_nut._tcp.local.-_Volumio._tcp.local.-_kizbox._tcp.local.-_home-assistant._tcp.local."
"-_viziocast._tcp.local.-_dvl-deviceapi._tcp.local.-_ipp._tcp.local.-_touch-able._tcp.local."
"-_hap._tcp.local.-_system-bridge._udp.local.-_dkapi._tcp.local.-_airplay._tcp.local."
"-_elg._tcp.local.-_miio._udp.local.-_wled._tcp.local.-_esphomelib._tcp.local."
"-_ipps._tcp.local.-_fbx-api._tcp.local.-_xbmc-jsonrpc-h._tcp.local.-_powerview._tcp.local."
"-_spotify-connect._tcp.local.-_leap._tcp.local.-_api._udp.local.-_plugwise._tcp.local."
"-_googlecast._tcp.local.-_printer._tcp.local.-_axis-video._tcp.local.-_http._tcp.local."
"-_mediaremotetv._tcp.local.-_homekit._tcp.local.-_bond._tcp.local.-_daap._tcp.local._243"

- After

"zeroconf-ServiceBrowser-_miio._udp-_mediaremotetv._tcp-_dvl-deviceapi._tcp-_ipp._tcp"
"-_dkapi._tcp-_hap._udp-_xbmc-jsonrpc-h._tcp-_hap._tcp-_googlecast._tcp-_airplay._tcp"
"-_viziocast._tcp-_api._udp-_kizbox._tcp-_spotify-connect._tcp-_home-assistant._tcp"
"-_bond._tcp-_powerview._tcp-_daap._tcp-_http._tcp-_leap._tcp-_elg._tcp-_homekit._tcp"
"-_ipps._tcp-_plugwise._tcp-_ssh._tcp-_esphomelib._tcp-_Volumio._tcp-_fbx-api._tcp"
"-_wled._tcp-_touch-able._tcp-_enphase-envoy._tcp-_axis-video._tcp-_printer._tcp"
"-_system-bridge._udp-_nut._tcp-244" ([`5d4aa28`](https://github.com/python-zeroconf/python-zeroconf/commit/5d4aa2800d1196274cfdd0bf3e631f49ab5b78bd))

* Update changelog for 0.32.0 (unreleased) (#372) ([`82fb26f`](https://github.com/python-zeroconf/python-zeroconf/commit/82fb26f14518a8e59f886b8d7b0708a68725bf48))

* Remove Callable quoting (#371)

- The current minimum supported cpython is 3.6+ which does not need
  the quoting ([`7f45bef`](https://github.com/python-zeroconf/python-zeroconf/commit/7f45bef8db444b0436c5f80b4f4b31b2f1d7ec2f))

* Abstract check to see if a record matches a type the ServiceBrowser wants (#369) ([`4819ef8`](https://github.com/python-zeroconf/python-zeroconf/commit/4819ef8c97ddbbadcd6e7cf1b5fee36f573bde45))

* Reduce complexity of ServiceBrowser enqueue_callback (#368)

- The handler key was by name, however ServiceBrowser can have multiple
  types which meant the check to see if a state change was an add
  remove, or update was overly complex. Reduce the complexity by
  making the key (name, type_) ([`4657a77`](https://github.com/python-zeroconf/python-zeroconf/commit/4657a773690a34c897c80894a10ac33b6edadf8b))

* Fix empty answers being added in ServiceInfo.request (#367) ([`5a4c1e4`](https://github.com/python-zeroconf/python-zeroconf/commit/5a4c1e46510956276de117d86bee9d2ccb602802))

* Ensure ServiceInfo populates all AAAA records (#366)

- Use get_all_by_details to ensure all records are loaded
  into addresses.

- Only load A/AAAA records from cache once in load_from_cache
  if there is a SRV record present

- Move duplicate code that checked if the ServiceInfo was complete
  into its own function ([`bae3a9b`](https://github.com/python-zeroconf/python-zeroconf/commit/bae3a9b97672581e77255c4937b815173c8547b4))

* Remove black python 3.5 exception block (#365) ([`6d29e6c`](https://github.com/python-zeroconf/python-zeroconf/commit/6d29e6c93bdcf6cf31fcfa133258257704945dfc))

* Small cleanup of ServiceInfo.update_record (#364)

- Return as record is not viable (None or expired)

- Switch checks to isinstance since its needed by mypy anyways

- Prepares for supporting multiple AAAA records (via https://github.com/jstasiak/python-zeroconf/pull/361) ([`1b8b291`](https://github.com/python-zeroconf/python-zeroconf/commit/1b8b2917e7e70e3996e9a96204dd5df3dfb39072))

* Add new cache function get_all_by_details (#363)

- When working with IPv6, multiple AAAA records can exist
  for a given host. get_by_details would only return the
  latest record in the cache.

- Fix a case where the cache list can change during
  iteration ([`d8c3240`](https://github.com/python-zeroconf/python-zeroconf/commit/d8c32401ada4f430cd75617324b6d8ecd1dbe1f2))

* Small cleanups to asyncio tests (#362) ([`7e960b7`](https://github.com/python-zeroconf/python-zeroconf/commit/7e960b78cac8008beca9c5451c6d465e2674a050))

* Improve test coverage for name conflicts (#357) ([`c0674e9`](https://github.com/python-zeroconf/python-zeroconf/commit/c0674e97aee4f61212389337340fc8ff4472eb25))

* Return task objects created by AsyncZeroconf (#360) ([`8c1c394`](https://github.com/python-zeroconf/python-zeroconf/commit/8c1c394e9b4aa01e08a2c3e240396b533792be55))

* Separate cache loading from I/O in ServiceInfo (#356)

Provides a load_from_cache method on ServiceInfo that does no I/O

- When a ServiceBrowser is running for a type there is no need
  to make queries on the network since the entries will already
  be in the cache. When discovering many devices making queries
  that will almost certainly fail for offline devices delays the
  startup of online devices.

- The DNSEntry and ServiceInfo classes were matching on the name
  instead of the key (lowercase name). These classes now treat dns
  names the same reguardless of case.

  https://datatracker.ietf.org/doc/html/rfc6762#section-16
  > The simple rules for case-insensitivity in Unicast DNS [RFC1034]
  > [RFC1035] also apply in Multicast DNS; that is to say, in name
  > comparisons, the lowercase letters "a" to "z" (0x61 to 0x7A) match
  > their uppercase equivalents "A" to "Z" (0x41 to 0x5A).  Hence, if a
  > querier issues a query for an address record with the name
  > "myprinter.local.", then a responder having an address record with
  > the name "MyPrinter.local." should issue a response. ([`87ba2a3`](https://github.com/python-zeroconf/python-zeroconf/commit/87ba2a3960576cfcf4207ea74a711b2c0cc584a7))

* Provide an asyncio class for service registration (#347)

* Provide an AIO wrapper for service registration

- When using zeroconf with async code, service registration can cause the
  executor to overload when registering multiple services since each one
  will have to wait a bit between sending the broadcast. An aio subclass
  is now available as aio.AsyncZeroconf that implements the following

    - async_register_service
    - async_unregister_service
    - async_update_service
    - async_close

  I/O is currently run in the executor to provide backwards compat with
  existing use cases.

  These functions avoid overloading the executor by waiting in the event
  loop instead of the executor threads. ([`a41d7b8`](https://github.com/python-zeroconf/python-zeroconf/commit/a41d7b8aa5572f3faf29eb087cc18a1343bbcdfa))

* Eliminate the reaper thread (#349)

- Cache is now purged between reads when the interval is reached

- Reduce locking since we are already making a copy of the readers
  and not reading under the lock

- Simplify shutdown process ([`7816278`](https://github.com/python-zeroconf/python-zeroconf/commit/781627864efbb3c8285e1b75144d688083414cf3))

* Return early when already closed (#350)

- Reduce indentation with a return early guard in close ([`523aefb`](https://github.com/python-zeroconf/python-zeroconf/commit/523aefb0b0c477489e4e1e4ab763ce56c57295b7))

* Skip socket creation if add_multicast_member fails (windows) (#341)

Co-authored-by: Timothee 'TTimo' Besset <ttimo@ttimo.net> ([`beccad1`](https://github.com/python-zeroconf/python-zeroconf/commit/beccad1f0b41730f541b2e90ea2eaa2496de5044))

* Simplify cache iteration (#340)

- Remove the need to trap runtime error
- Only copy the names of the keys when iterating the cache
- Fixes RuntimeError: list changed size during iterating entries_from_name
- Cache services
- The Repear thread is no longer aware of the cache internals ([`fe94810`](https://github.com/python-zeroconf/python-zeroconf/commit/fe948105cc0923336ffa6d93cbe7d45470612a36))


## v0.29.0 (2021-03-25)

### Unknown

* Release version 0.29.0 ([`203ec2e`](https://github.com/python-zeroconf/python-zeroconf/commit/203ec2e26e6f0f676e7d88b4a1b0c80ad74659f1))

* Fill a missing changelog entry ([`53cb804`](https://github.com/python-zeroconf/python-zeroconf/commit/53cb8044bfb4256f570d438817fd37acc8b78511))

* Make mypy configuration more lenient

We want to be able to call untyped modules. ([`f871b90`](https://github.com/python-zeroconf/python-zeroconf/commit/f871b90d25c0f788590ceb14237b08a6b5e6eeeb))

* Silence a flaky test on PyPy ([`bc6ef8c`](https://github.com/python-zeroconf/python-zeroconf/commit/bc6ef8c65b22d982798104d5bdf11b78746a8ddd))

* Silence a mypy false-positive ([`6482da0`](https://github.com/python-zeroconf/python-zeroconf/commit/6482da05344e6ae8c4da440da4a704a20c344bb6))

* Switch from Travis CI/Coveralls to GH Actions/Codecov

Travis CI free tier is going away and Codecov is my go-to code coverage
service now.

Closes GH-332. ([`bd80d20`](https://github.com/python-zeroconf/python-zeroconf/commit/bd80d20682c0af5e15a4b7102dcfe814cdba3a01))

* Drop Python 3.5 compatibilty, it reached its end of life ([`ab67a7a`](https://github.com/python-zeroconf/python-zeroconf/commit/ab67a7aecd63042178061f0d1a76f9a7f6e1559a))

* Use a single socket for InterfaceChoice.Default

When using multiple sockets with multi-cast, the outgoing
socket's responses could be read back on the incoming socket,
which leads to duplicate processing and could fill up the
incoming buffer before it could be processed.

This behavior manifested with error similar to
`OSError: [Errno 105] No buffer space available`

By using a single socket with InterfaceChoice.Default
we avoid this case. ([`6beefbb`](https://github.com/python-zeroconf/python-zeroconf/commit/6beefbbe76a0e261394b308c8cc68545be653019))

* Simplify read_name

(venv) root@ha-dev:~/python-zeroconf# python3 -m timeit -s 'result=""' -u usec 'result = "".join((result, "thisisaname" + "."))'
20000 loops, best of 5: 16.4 usec per loop
(venv) root@ha-dev:~/python-zeroconf# python3 -m timeit -s 'result=""' -u usec 'result += "thisisaname" + "."'
2000000 loops, best of 5: 0.105 usec per loop ([`5e268fa`](https://github.com/python-zeroconf/python-zeroconf/commit/5e268faeaa99f0a513c7bbeda8f447f4eb36a747))

* Fix link to readme md --> rst (#324) ([`c5a675d`](https://github.com/python-zeroconf/python-zeroconf/commit/c5a675d22788aa905a4e47feb1d4c30f30416356))


## v0.28.8 (2021-01-04)

### Unknown

* Release version 0.28.8 ([`1d726b5`](https://github.com/python-zeroconf/python-zeroconf/commit/1d726b551a49e945b134df6e29b352697030c5a9))

* Ensure the name cache is rolled back when the packet reaches maximum size

If the packet was too large, it would be rolled back at the end of write_record.
We need to remove the names that were added to the name cache (self.names)
as well to avoid a case were we would create a pointer to a name that was
rolled back.

The size of the packet was incorrect at the end after the inserts because
insert_short would increase self.size even though it was already accounted
before. To resolve this insert_short_at_start was added which does not
increase self.size. This did not cause an actual bug, however it sure
made debugging this problem far more difficult.

Additionally the size now inserted and then replaced when the actual
size is known because it made debugging quite difficult since the size
did not previously agree with the data. ([`86b4e11`](https://github.com/python-zeroconf/python-zeroconf/commit/86b4e11434d44e2f9a42354109a10f601c44d66a))


## v0.28.7 (2020-12-13)

### Unknown

* Release version 0.28.7 ([`8f7effd`](https://github.com/python-zeroconf/python-zeroconf/commit/8f7effd2f89c542162d0e5ac257c561501690d16))

* Refactor to move service registration into a registry

This permits removing the broad exception catch that
was expanded to avoid a crash in when adding or
removing a service ([`2708fef`](https://github.com/python-zeroconf/python-zeroconf/commit/2708fef6052f7e6e6eb36a157438b316e6d38b21))

* Prevent crash when a service is added or removed during handle_response

Services are now modified under a lock.  The service processing
is now done in a try block to ensure RuntimeError is caught
which prevents the zeroconf engine from unexpectedly
terminating. ([`4136858`](https://github.com/python-zeroconf/python-zeroconf/commit/41368588e5fcc6ec9596f306e39e2eaac2a9ec18))

* Restore IPv6 addresses output

Before this change, script `examples/browser.py` printed IPv4 only, even with `--v6` argument.
With this change, `examples/browser.py` prints both IPv4 + IPv6 by default, and IPv6 only with `--v6-only` argument.

I took the idea from the fork
https://github.com/ad3angel1s/python-zeroconf/blob/master/examples/browser.py ([`4da1612`](https://github.com/python-zeroconf/python-zeroconf/commit/4da1612b728acbcf2ab0c4bee09891c46f387bfb))


## v0.28.6 (2020-10-13)

### Unknown

* Release version 0.28.6 ([`4744427`](https://github.com/python-zeroconf/python-zeroconf/commit/474442750d5d529436a118fda98a0b5f4680dc4d))

* Merge strict and allow_underscores (#309)

Those really serve the same purpose -- are we receiving data (and want
to be flexible) or registering services (and want to be strict). ([`6a0c5dd`](https://github.com/python-zeroconf/python-zeroconf/commit/6a0c5dd4e84c30264747847e8f1045ece2a14288))

* Loosen validation to ensure get_service_info can handle production devices (#307)

Validation of names was too strict and rejected devices that are otherwise
functional.  A partial list of devices that unexpectedly triggered
a BadTypeInNameException:

  Bose Soundtouch
  Yeelights
  Rachio Sprinklers
  iDevices ([`6ab0cd0`](https://github.com/python-zeroconf/python-zeroconf/commit/6ab0cd0a0446f158a1d8a64a3bc548cf9e103179))


## v0.28.5 (2020-09-11)

### Unknown

* Release version 0.28.5 ([`eda1b3d`](https://github.com/python-zeroconf/python-zeroconf/commit/eda1b3dd17329c40a59b628b4bbca15c42af43b7))

* Fix AttributeError: module 'unittest' has no attribute 'mock' (#302)

We only had module-level unittest import before now, but code accessing
mock through unittest.mock was working because we have a test-level
import from unittest.mock which causes unittest to gain the mock
attribute and if the test was run before other tests (those using
unittest.mock.patch) all was good. If the test was not run before them,
though, they'd fail.

Closes GH-295. ([`2db7fff`](https://github.com/python-zeroconf/python-zeroconf/commit/2db7fff033937a929cdfee1fc7c93c594872799e))

* Ignore duplicate messages (#299)

When watching packet captures, I noticed that zeroconf was processing
incoming data 3x on a my Home Assistant OS install because there are
three interfaces.

We can skip processing duplicate packets in order to reduce the overhead
of decoding data we have already processed.

Before

Idle cpu ~8.3%

recvfrom 4 times

    267   recvfrom(7, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("192.168.210.102")}, [16]) = 71
    267   recvfrom(7, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("172.30.32.1")}, [16]) = 71
    267   recvfrom(8, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("192.168.210.102")}, [16]) = 71
    267   recvfrom(8, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("172.30.32.1")}, [16]) = 71

sendto 8 times

    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335
    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335
    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335
    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335
    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335
    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335
    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335
    267   sendto(8, "\0\0\204\0\0\0\0\1\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300K\0\1\200\1\0\0\0x\0\4\300\250\325\232", 335, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 335

After

Idle cpu ~4.1%

recvfrom 4 times (no change):

    267   recvfrom(7, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("192.168.210.102")}, [16]) = 71                                
    267   recvfrom(9, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("192.168.210.102")}, [16]) = 71                                
    267   recvfrom(7, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("172.30.32.1")}, [16]) = 71                                    
    267   recvfrom(9, "\0\0\204\0\0\0\0\1\0\0\0\0\v_esphomelib\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\31\26masterbed_tvcabinet_32\300\f", 8966, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("172.30.32.1")}, [16]) = 71        

sendto 2 times (reduced by 4x):

    267   sendto(9, "\0\0\204\0\0\0\0\2\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\t_services\7_dns-sd\4_udp\300!\0\f\0\1\0\0\21\224\0\2\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300p\0\1\200\1\0\0\0x\0\4\300\250\325\232", 372, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 372
    267   sendto(9, "\0\0\204\0\0\0\0\2\0\0\0\3\17_home-assistant\4_tcp\5local\0\0\f\0\1\0\0\21\224\0\7\4Home\300\f\t_services\7_dns-sd\4_udp\300!\0\f\0\1\0\0\21\224\0\2\300\f\3002\0!\200\1\0\0\0x\0)\0\0\0\0\37\273 66309dfc726446799c8a2c0f1cb0480f\300!\3002\0\20\200\1\0\0\21\224\0\305\22location_name=Home%uuid=66309dfc726446799c8a2c0f1cb0480f\24version=0.116.0.dev0\rexternal_url=(internal_url=http://192.168.213.154:8123$base_url=http://192.168.213.154:8123\32requires_api_password=True\300p\0\1\200\1\0\0\0x\0\4\300\250\325\232", 372, 0, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, 16) = 372

With debug logging on for ~5 minutes

    bash-5.0# grep 'Received from' home-assistant.log  |wc
        11458    499196  19706165
    bash-5.0# grep 'Ignoring' home-assistant.log  |wc
         9357    210562   9299687 ([`f321932`](https://github.com/python-zeroconf/python-zeroconf/commit/f3219326e65f4410d45ace05f88082354a2f7525))

* Test with the development version of Python 3.9 (#300)

There've been reports of test failures on Python 3.9, let's verify this.
Allowing failures for now until it goes stable. ([`1f81e0b`](https://github.com/python-zeroconf/python-zeroconf/commit/1f81e0bcad1cae735ba532758d167368925c8ede))


## v0.28.4 (2020-09-06)

### Unknown

* Release version 0.28.4 ([`fb876d6`](https://github.com/python-zeroconf/python-zeroconf/commit/fb876d6013979cdaa8c0ddebe81e7520e9ee8cc9))

* Add ServiceListener to __all__ for Zeroconf module (#298)

It's part of the public API. ([`0265a9d`](https://github.com/python-zeroconf/python-zeroconf/commit/0265a9d57630a4a19bcd3638a6bb3f4b18eba01b))

* Avoid copying the entires cache and reduce frequency of Reaper

The cache reaper was running at least every 10 seconds, making
a copy of the cache, and iterated all the entries to
check if they were expired so they could be removed.

In practice the reaper was actually running much more frequently
because it used self.zc.wait which would unblock any time
a record was updated, a listener was added, or when a
listener was removed.

This change ensures the reaper frequency is only every 10s, and
will first attempt to iterate the cache before falling back to
making a copy.

Previously it made sense to expire the cache more frequently
because we had places were we frequently had to enumerate
all the cache entries. With #247 and #232 we no longer
have to account for this concern.

On a mostly idle RPi running HomeAssistant and a busy
network the total time spent reaping the cache was
more than the total time spent processing the mDNS traffic.

Top 10 functions, idle RPi (before)

  %Own   %Total  OwnTime  TotalTime  Function (filename:line)
  0.00%   0.00%    2.69s     2.69s   handle_read (zeroconf/__init__.py:1367)   <== Incoming mDNS
  0.00%   0.00%    1.51s     2.98s   run (zeroconf/__init__.py:1431)           <== Reaper
  0.00%   0.00%    1.42s     1.42s   is_expired (zeroconf/__init__.py:502)     <== Reaper
  0.00%   0.00%    1.12s     1.12s   entries (zeroconf/__init__.py:1274)       <== Reaper
  0.00%   0.00%   0.620s    0.620s   do_execute (sqlalchemy/engine/default.py:593)
  0.00%   0.00%   0.620s    0.620s   read_utf (zeroconf/__init__.py:837)
  0.00%   0.00%   0.610s    0.610s   do_commit (sqlalchemy/engine/default.py:546)
  0.00%   0.00%   0.540s     1.16s   read_name (zeroconf/__init__.py:853)
  0.00%   0.00%   0.380s    0.380s   do_close (sqlalchemy/engine/default.py:549)
  0.00%   0.00%   0.340s    0.340s   write (asyncio/selector_events.py:908)

After this change, the Reaper code paths do not show up in the top
10 function sample.

  %Own   %Total  OwnTime  TotalTime  Function (filename:line)
  4.00%   4.00%    2.72s     2.72s   handle_read (zeroconf/__init__.py:1378)     <== Incoming mDNS
  4.00%   4.00%    1.81s     1.81s   read_utf (zeroconf/__init__.py:837)
  1.00%   5.00%    1.68s     3.51s   read_name (zeroconf/__init__.py:853)
  0.00%   0.00%    1.32s     1.32s   do_execute (sqlalchemy/engine/default.py:593)
  0.00%   0.00%   0.960s    0.960s   readinto (socket.py:669)
  0.00%   0.00%   0.950s    0.950s   create_connection (urllib3/util/connection.py:74)
  0.00%   0.00%   0.910s    0.910s   do_commit (sqlalchemy/engine/default.py:546)
  1.00%   1.00%   0.880s    0.880s   write (asyncio/selector_events.py:908)
  0.00%   0.00%   0.700s    0.810s   __eq__ (zeroconf/__init__.py:606)
  2.00%   2.00%   0.670s    0.670s   unpack (zeroconf/__init__.py:737) ([`1e4aaea`](https://github.com/python-zeroconf/python-zeroconf/commit/1e4aaeaa10c306b9447dacefa03b89ce1e9d7493))

* Add an author in the last changelog entry ([`9e27d12`](https://github.com/python-zeroconf/python-zeroconf/commit/9e27d126d75c73466584c417ab35c1d6cf47ca8b))


## v0.28.3 (2020-08-31)

### Unknown

* Release version 0.28.3 ([`0e49aec`](https://github.com/python-zeroconf/python-zeroconf/commit/0e49aeca6497ede18a3f0c71ea69f2343934ba19))

* Reduce the time window that the handlers lock is held

Only hold the lock if we have an update. ([`5a359bb`](https://github.com/python-zeroconf/python-zeroconf/commit/5a359bb0931fbda8444e30d07a50e59cf4ccca8e))

* Reformat using the latest black (20.8b1) ([`57d89d8`](https://github.com/python-zeroconf/python-zeroconf/commit/57d89d85e52dea1f8cb7f6d4b02c0281d5ba0540))


## v0.28.2 (2020-08-27)

### Unknown

* Release version 0.28.2 ([`f64768a`](https://github.com/python-zeroconf/python-zeroconf/commit/f64768a7253829f9d8f7796a6a5c8129b92f2aad))

* Increase test coverage for dns cache ([`3be96b0`](https://github.com/python-zeroconf/python-zeroconf/commit/3be96b014d61c94d71ae3aa23ba223eead4f4cb7))

* Don't ask already answered questions (#292)

Fixes GH-288.

Co-authored-by: Erik <erik@montnemery.com> ([`fca090d`](https://github.com/python-zeroconf/python-zeroconf/commit/fca090db06a0d481ad7f608c4fde3e936ad2f80e))

* Remove initial delay before querying for service info ([`0f73664`](https://github.com/python-zeroconf/python-zeroconf/commit/0f7366423fab8369700be086f3007c20897fde1f))


## v0.28.1 (2020-08-17)

### Unknown

* Release version 0.28.1 ([`3c5d385`](https://github.com/python-zeroconf/python-zeroconf/commit/3c5d3856e286824611712de13aa0fcbe94e4313f))

* Ensure all listeners are cleaned up on ServiceBrowser cancelation (#290)

When creating listeners for a ServiceBrowser with multiple types
they would not all be removed on cancelation. This led
to a build up of stale listeners when ServiceBrowsers were
frequently added and removed. ([`c9f3c91`](https://github.com/python-zeroconf/python-zeroconf/commit/c9f3c91da568fdbd26d571eed8a636a49e527b15))

* Gitignore some build artifacts ([`19e33a6`](https://github.com/python-zeroconf/python-zeroconf/commit/19e33a6829846008b50f408c77ac3e8e73176529))


## v0.28.0 (2020-07-07)

### Unknown

* Release version 0.28.0 ([`0fdbf5e`](https://github.com/python-zeroconf/python-zeroconf/commit/0fdbf5e197a9f76e9e9c91a5e0908a0c66370dbd))

* Advertise Python 3.8 compatibility ([`02bcad9`](https://github.com/python-zeroconf/python-zeroconf/commit/02bcad902c516a5a2d2aa3302bca9871900da6e3))

* Fix an OS X edge case (#270, #188)

This contains two major changes:

* Listen on data from respond_sockets in addition to listen_socket
* Do not bind respond sockets to 0.0.0.0 or ::/0

The description of the original change by Emil:

<<<
Without either of these changes, I get no replies at all when browsing for
services using the browser example. I'm on a corporate network, and when
connecting to a different network it works without these changes, so maybe
it's something about the network configuration in this particular network
that breaks the previous behavior.

Unfortunately, I have no idea how this affects other platforms, or what
the changes really mean. However, it works for me and it seems reasonable
to get replies back on the same socket where they are sent.
>>>

The tests pass and it's been confirmed to a reasonable degree that this
doesn't break the previously working use cases.

Additionally this removes a memory leak where data sent to some of the
respond sockets would not be ever read from them (#171).

Co-authored-by: Emil Styrke <emil.styrke@axis.com> ([`fc92b1e`](https://github.com/python-zeroconf/python-zeroconf/commit/fc92b1e2635868792aa7ebe937a9cfef2e2f0418))

* Stop using socket.if_nameindex (#282)

This improves Windows compatibility ([`a7f9823`](https://github.com/python-zeroconf/python-zeroconf/commit/a7f9823cbed254b506a09cc514d86d9f5dc61ad3))

* Make Mypy happy (#281)

Otherwise it'd complain:

    % make mypy
    mypy examples/*.py zeroconf/*.py
    zeroconf/__init__.py:2039: error: Returning Any from function declared to return "int"
    Found 1 error in 1 file (checked 6 source files)
    make: *** [mypy] Error 1 ([`4381784`](https://github.com/python-zeroconf/python-zeroconf/commit/4381784150e07625b4acd2034b253bf2ed320c5f))

* Use Adapter.index from ifaddr. (#280)

Co-authored-by: PhilippSelenium <PhilippSelenium@github.com> ([`64056ab`](https://github.com/python-zeroconf/python-zeroconf/commit/64056ab4aa55eb11c185c9879462ba1f82c7e886))

* Exclude a problematic pep8-naming version ([`023e72d`](https://github.com/python-zeroconf/python-zeroconf/commit/023e72d821faed9513ee0ef3a22a00231d87389e))

* Log listen and respond sockets just in case ([`3b6906a`](https://github.com/python-zeroconf/python-zeroconf/commit/3b6906ab94f8d9ebeb1c97b6026ab7f9be226eab))

* Fix one log format string (we use a socket object here) ([`328abfc`](https://github.com/python-zeroconf/python-zeroconf/commit/328abfc54138e68e36a9f5381650bd6997701e73))

* Add support for passing text addresses to ServiceInfo

Not sure if parsed_addresses is the best way to name the parameter, but
we already have a parsed_addresses property so for the sake of
consistency let's stick to that. ([`0a9aa8d`](https://github.com/python-zeroconf/python-zeroconf/commit/0a9aa8d31bffec5d7b7291b84fbc95222b10d189))

* Support Windows when using socket errno checks (#274)

Windows reports errno.WSAEINVAL(10022) instead of errno.EINVAL(22).
This issue is triggered when a device has two IP's assigned under
windows.

This fixes #189 ([`c31ae7f`](https://github.com/python-zeroconf/python-zeroconf/commit/c31ae7fd519df04f41939d3c60c2b88960737fd6))


## v0.27.1 (2020-06-05)

### Unknown

* Release version 0.27.1 ([`0538abf`](https://github.com/python-zeroconf/python-zeroconf/commit/0538abf135f5502d94dd883475bcb2781ce5ddd2))

* Fix false warning (#273)

When there is nothing to write, we don't need to warn about not making progress. ([`10065b9`](https://github.com/python-zeroconf/python-zeroconf/commit/10065b976247ae9247cddaff8f3e9d7b331e66d7))

* Improve logging (mainly include sockets in some messages) (#271) ([`beff998`](https://github.com/python-zeroconf/python-zeroconf/commit/beff99897f0a5ece17e224a7ea9b12ebd420044f))

* Simplify DNSHinfo constructor, cpu and os are always text (#266) ([`d6593af`](https://github.com/python-zeroconf/python-zeroconf/commit/d6593af2a3811b262d70bbc75c2c91613de41b21))

* Improve ImportError message (wrong supported Python version) ([`8045191`](https://github.com/python-zeroconf/python-zeroconf/commit/8045191ae6300da47d38e5cd82957965139359d2))

* Remove old Python 2-specific code ([`6f876a7`](https://github.com/python-zeroconf/python-zeroconf/commit/6f876a7f14f0b172860005b0d6d959d82f7c1bbf))


## v0.27.0 (2020-05-27)

### Unknown

* Release version 0.27.0 ([`0502f19`](https://github.com/python-zeroconf/python-zeroconf/commit/0502f1904b0a8b9134ea2a09333232b30b3b6897))

* Remove no longer needed typing dependency

We don't support Python older than 3.5. ([`d881aba`](https://github.com/python-zeroconf/python-zeroconf/commit/d881abaf591f260ad019f4ff86e7f70a6f018a64))

* Add --find option to example/browser.py (#263, rebased #175)

Co-authored-by: Perry Kundert <perry@hardconsulting.com> ([`781ac83`](https://github.com/python-zeroconf/python-zeroconf/commit/781ac834da38708d95bfe6e5f5ec7dd0f31efc54))

* Restore missing warnings import ([`178cec7`](https://github.com/python-zeroconf/python-zeroconf/commit/178cec75bd9a065b150b3542dfdb40682f6745b6))

* Warn on every call to missing update_service() listener method

This is in order to provide visibility to the library users that this
method exists - without it the client code may be missing data. ([`488ee1e`](https://github.com/python-zeroconf/python-zeroconf/commit/488ee1e85762dc5856d8e132da54762e5e712c5a))

* Separately send large mDNS responses to comply with RFC 6762 (#248)

This fixes issue #245

Split up large multi-response packets into separate packets instead of relying on IP Fragmentation. IP Fragmentation of mDNS packets causes ChromeCast Audios to
crash their mDNS responder processes and RFC 6762
(https://tools.ietf.org/html/rfc6762) section 17 states some
requirements for Multicast DNS Message Size, and the fourth paragraph reads:

"A Multicast DNS packet larger than the interface MTU, which is sent
using fragments, MUST NOT contain more than one resource record."

This change makes this implementation conform with this MUST NOT clause. ([`87a0fe2`](https://github.com/python-zeroconf/python-zeroconf/commit/87a0fe27a7be9d96af08f8a007f37a16105c64a0))

* Remove deprecated ServiceInfo address parameter/property (#260) ([`ab72aa8`](https://github.com/python-zeroconf/python-zeroconf/commit/ab72aa8e5a6a83e50d24d7fb187e8fa8a549a847))


## v0.26.3 (2020-05-26)

### Unknown

* Release version 0.26.3 ([`fbcefca`](https://github.com/python-zeroconf/python-zeroconf/commit/fbcefca592632304579c1b3f9c7bd3dd342e1618))

* Don't call callbacks when holding _handlers_lock (#258)

Closes #255

Background:
#239 adds the lock _handlers_lock:

python-zeroconf/zeroconf/__init__.py

    self._handlers_lock = threading.Lock()  # ensure we process a full message in one go 

Which is used in the engine thread:

     def handle_response(self, msg: DNSIncoming) -> None: 
         """Deal with incoming response packets.  All answers 
         are held in the cache, and listeners are notified.""" 
  
         with self._handlers_lock: 
  

And also by the service browser when issuing the state change callbacks:

 if len(self._handlers_to_call) > 0 and not self.zc.done: 
     with self.zc._handlers_lock: 
         handler = self._handlers_to_call.popitem(False) 
         self._service_state_changed.fire( 
             zeroconf=self.zc, service_type=self.type, name=handler[0], state_change=handler[1] 
         ) 

Both pychromecast and Home Assistant calls Zeroconf.get_service_info from the service callbacks which means the lock may be held for several seconds which will starve the engine thread. ([`fe86566`](https://github.com/python-zeroconf/python-zeroconf/commit/fe865667e4610d57067a8f710f4d818eaa5e14dc))

* Give threads unique names (#257) ([`54d116f`](https://github.com/python-zeroconf/python-zeroconf/commit/54d116fd69a66062f91be04d84ceaebcfb13cc43))

* Use equality comparison instead of identity comparison for ints

Integers aren't guaranteed to have the same identity even though they
may be equal. ([`445d7f5`](https://github.com/python-zeroconf/python-zeroconf/commit/445d7f5dbe38947bd0bd1e3a5b8d649c1819c21f))

* Merge 0.26.2 release commit

I accidentally only pushed 0.26.2 tag (commit ffb42e5836bd) without
pushing the commit to master and now I merged aa9de4de7202 so this is
the best I can do without force-pushing to master. Tag 0.26.2 will
continue to point to that dangling commit. ([`1c4d3fc`](https://github.com/python-zeroconf/python-zeroconf/commit/1c4d3fcbf34b09364e52a773783dc9c924a7b17a))

* Improve readability of logged incoming data (#254) ([`aa9de4d`](https://github.com/python-zeroconf/python-zeroconf/commit/aa9de4de7202b3ab0a60f14532d227f63d7d981b))

* Add support for multiple types to ServiceBrowsers

As each ServiceBrowser runs in its own thread there
is a scale problem when listening for many types.

ServiceBrowser can now accept a list of types
in addition to a single type. ([`a6ad100`](https://github.com/python-zeroconf/python-zeroconf/commit/a6ad100a60e8434cef6b411208eef98f68d594d3))

* Fix race condition where a listener gets
a message before the lock is created. ([`24a0619`](https://github.com/python-zeroconf/python-zeroconf/commit/24a06191ea35469948d12124a07429207b3c1b3b))

* Fix flake8 E741 in setup.py (#252) ([`4b1d953`](https://github.com/python-zeroconf/python-zeroconf/commit/4b1d953979287e08f914857867da1000634ca3af))


## v0.26.1 (2020-05-06)

### Unknown

* Release version 0.26.1 ([`4c359e2`](https://github.com/python-zeroconf/python-zeroconf/commit/4c359e2e7cdf104efca90ffd9912ea7c7792e3bf))

* Remove unwanted pylint directives

Those are results of a bad conflict resolution I did when merging [1].

[1] 552a030eb592 ("Call UpdateService on SRV & A/AAAA updates as well as TXT (#239)") ([`0dd6fe4`](https://github.com/python-zeroconf/python-zeroconf/commit/0dd6fe44ca3895375ba447fed5f138042ab12ebf))

* Avoid iterating the entire cache when an A/AAAA address has not changed (#247)

Iterating the cache is an expensive operation
when there is 100s of devices generating zeroconf
traffic as there can be 1000s of entries in the
cache. ([`0540342`](https://github.com/python-zeroconf/python-zeroconf/commit/0540342bacd859f38f6d2a3743a7959cd3ae4d02))

* Update .gitignore for Visual Studio config files (#244) ([`16431b6`](https://github.com/python-zeroconf/python-zeroconf/commit/16431b6cb51f561a4c5d2897e662b254ca4243ec))


## v0.26.0 (2020-04-26)

### Unknown

* Release version 0.26.0 ([`36941ae`](https://github.com/python-zeroconf/python-zeroconf/commit/36941aeb72711f7954d40f0abeab4802174636df))

* Call UpdateService on SRV & A/AAAA updates as well as TXT (#239)

Fix https://github.com/jstasiak/python-zeroconf/issues/235

Contains:

* Add lock around handlers list
* Reverse DNSCache order to ensure newest records take precedence

  When there are multiple records in the cache, the behaviour was
  inconsistent. Whilst the DNSCache.get() method returned the newest,
  any function which iterated over the entire cache suffered from
  a last write winds issue. This change makes this behaviour consistent
  and allows the removal of an (incorrect) wait from one of the unit tests. ([`552a030`](https://github.com/python-zeroconf/python-zeroconf/commit/552a030eb592a0c07feaa7a01ece1464da4b1d0b))


## v0.25.1 (2020-04-14)

### Unknown

* Release version 0.25.1 ([`f8fe400`](https://github.com/python-zeroconf/python-zeroconf/commit/f8fe400e4be833728f015a3d6396bfc3f7c185c0))

* Update Engine to immediately notify its worker thread (#243) ([`976e3dc`](https://github.com/python-zeroconf/python-zeroconf/commit/976e3dcf9d6d897b063ab6f0b7831bcfa6ac1814))

* Remove unstable IPv6 tests from Travis (#241) ([`cf0382b`](https://github.com/python-zeroconf/python-zeroconf/commit/cf0382ba771bcc22284fd719c80a26eaa05ba5cd))

* Switch to pytest for test running (#240)

Nose is dead for all intents and purposes (last release in 2015) and
pytest provide a very valuable feature of printing relevant extra
information in case of assertion failure (from[1]):

    ================================= FAILURES =================================
    _______________________________ test_answer ________________________________

        def test_answer():
    >       assert func(3) == 5
    E       assert 4 == 5
    E        +  where 4 = func(3)

    test_sample.py:6: AssertionError
    ========================= short test summary info ==========================
    FAILED test_sample.py::test_answer - assert 4 == 5
    ============================ 1 failed in 0.12s =============================

This should be helpful in debugging tests intermittently failing on
PyPy.

Several TestCase.assertEqual() calls have been replaced by plain
assertions now that that method no longer provides anything we can't get
without it. Few assertions have been modified to not explicitly provide
extra information in case of failure – pytest will provide this
automatically.

Dev dependencies are forced to be the latest versions to make sure
we don't fail because of outdated ones on Travis.

[1] https://docs.pytest.org/en/latest/getting-started.html#create-your-first-test ([`f071f3d`](https://github.com/python-zeroconf/python-zeroconf/commit/f071f3d49d82ab212b86f889532200c94b36aea6))


## v0.25.0 (2020-04-03)

### Unknown

* Release version 0.25.0 ([`0cbced8`](https://github.com/python-zeroconf/python-zeroconf/commit/0cbced809989283893e02914e251a94739a41062))

* Improve ServiceInfo documentation ([`e839c40`](https://github.com/python-zeroconf/python-zeroconf/commit/e839c40081ba15e228d447969b725ee42f1ef2ad))

* Remove uniqueness assertions

The assertions, added in [1] and modified in [2] introduced a
regression. When browsing in the presence of devices advertising SRV
records not marked as unique there would be an undesired crash (from [3]):

    Exception in thread zeroconf-ServiceBrowser__hap._tcp.local.:
    Traceback (most recent call last):
      File "/usr/lib/python3.7/threading.py", line 917, in _bootstrap_inner
        self.run()
      File "/home/pi/homekit-debugging/venv/lib/python3.7/site-packages/zeroconf/__init__.py", line 1504, in run
        handler(self.zc)
      File "/home/pi/homekit-debugging/venv/lib/python3.7/site-packages/zeroconf/__init__.py", line 1444, in <lambda>
        zeroconf=zeroconf, service_type=self.type, name=name, state_change=state_change
      File "/home/pi/homekit-debugging/venv/lib/python3.7/site-packages/zeroconf/__init__.py", line 1322, in fire
        h(**kwargs)
      File "browser.py", line 20, in on_service_state_change
        info = zeroconf.get_service_info(service_type, name)
      File "/home/pi/homekit-debugging/venv/lib/python3.7/site-packages/zeroconf/__init__.py", line 2191, in get_service_info
        if info.request(self, timeout):
      File "/home/pi/homekit-debugging/venv/lib/python3.7/site-packages/zeroconf/__init__.py", line 1762, in request
        out.add_answer_at_time(zc.cache.get_by_details(self.name, _TYPE_SRV, _CLASS_IN), now)
      File "/home/pi/homekit-debugging/venv/lib/python3.7/site-packages/zeroconf/__init__.py", line 907, in add_answer_at_time
        assert record.unique
    AssertionError

The intention is to bring those assertions back in a way that only
enforces uniqueness when sending records, not when receiving them.

[1] bef8f593ae82 ("Ensure all TXT, SRV, A records are unique")
[2] 5e4f496778d9 ("Refactor out unique assertion")
[3] https://github.com/jstasiak/python-zeroconf/issues/236 ([`a79015e`](https://github.com/python-zeroconf/python-zeroconf/commit/a79015e7c4bdc843d97bd5c82ef8ed4eeae01a34))

* Rationalize handling of values in TXT records

* Do not interpret received values; use None if a property has no value
* When encoding values, use either raw bytes or UTF-8 ([`8e3adf8`](https://github.com/python-zeroconf/python-zeroconf/commit/8e3adf8300a6f2b0bc0dcc4cde54d8890e0727e9))


## v0.24.5 (2020-03-08)

### Unknown

* Release version 0.24.5 ([`aba2858`](https://github.com/python-zeroconf/python-zeroconf/commit/aba28583f5431f584587770b6c149e4a607a987e))

* Resolve memory leak in DNSCache

When all the records for a given name were removed from the cache, the
name itself that contain the list was never removed.  This left an empty list
in memory for every device that was no longer broadcasting on the
network. ([`eac53f4`](https://github.com/python-zeroconf/python-zeroconf/commit/eac53f45bddb8d3d559b1d4672a926b746435771))

* Optimize handle_response cache check

The handle_response loop would encounter a unique record
it would search the cache in order to remove keys that
matched the DNSEntry for the record.

Since the cache is stored as a list of records with the key as the record name,
 we can avoid searching the entire cache each time and on
search for the DNSEntry of the record. In practice this means
with 5000 entries and records in the cache we now only need to search
4 or 5.

When looping over the cache entries for the name, we now check the expire time
first as its cheaper than calling DNSEntry.__eq__

Test environment:

  Home Assistant running on home networking with a /22
  and a significant amount of broadcast traffic

  Testing was done with py-spy v0.3.3
    (https://github.com/benfred/py-spy/releases)

  # py-spy top --pid <pid>

Before:
```
Collecting samples from '/usr/local/bin/python3 -m homeassistant --config /config' (python v3.7.6)
Total Samples 10200
GIL: 0.00%, Active: 0.00%, Threads: 35

  %Own   %Total  OwnTime  TotalTime  Function (filename:line)
  0.00%   0.00%   18.13s    18.13s   _worker (concurrent/futures/thread.py:78)
  0.00%   0.00%    2.51s     2.56s   run (zeroconf/__init__.py:1221)
  0.00%   0.00%   0.420s    0.420s   __eq__ (zeroconf/__init__.py:394)
  0.00%   0.00%   0.390s    0.390s   handle_read (zeroconf/__init__.py:1260)
  0.00%   0.00%   0.240s    0.670s   handle_response (zeroconf/__init__.py:2452)
  0.00%   0.00%   0.230s    0.230s   __eq__ (zeroconf/__init__.py:606)
  0.00%   0.00%   0.200s    0.810s   handle_response (zeroconf/__init__.py:2449)
  0.00%   0.00%   0.140s    0.150s   __eq__ (zeroconf/__init__.py:632)
  0.00%   0.00%   0.130s    0.130s   entries (zeroconf/__init__.py:1185)
  0.00%   0.00%   0.090s    0.090s   notify (threading.py:352)
  0.00%   0.00%   0.080s    0.080s   read_utf (zeroconf/__init__.py:818)
  0.00%   0.00%   0.080s    0.080s   __eq__ (zeroconf/__init__.py:678)
  0.00%   0.00%   0.070s    0.080s   __eq__ (zeroconf/__init__.py:533)
  0.00%   0.00%   0.060s    0.060s   __eq__ (zeroconf/__init__.py:677)
  0.00%   0.00%   0.050s    0.050s   get (zeroconf/__init__.py:1146)
  0.00%   0.00%   0.050s    0.050s   do_commit (sqlalchemy/engine/default.py:541)
  0.00%   0.00%   0.040s     2.86s   run (zeroconf/__init__.py:1226)
```

After
```
Collecting samples from '/usr/local/bin/python3 -m homeassistant --config /config' (python v3.7.6)
Total Samples 10200
GIL: 7.00%, Active: 61.00%, Threads: 35

  %Own   %Total  OwnTime  TotalTime  Function (filename:line)
 47.00%  47.00%   24.84s    24.84s   _worker (concurrent/futures/thread.py:78)
  5.00%   5.00%    2.97s     2.97s   run (zeroconf/__init__.py:1226)
  1.00%   1.00%   0.390s    0.390s   handle_read (zeroconf/__init__.py:1265)
  1.00%   1.00%   0.200s    0.200s   read_utf (zeroconf/__init__.py:818)
  0.00%   0.00%   0.120s    0.120s   unpack (zeroconf/__init__.py:723)
  0.00%   1.00%   0.120s    0.320s   read_name (zeroconf/__init__.py:834)
  0.00%   0.00%   0.100s    0.240s   update_record (zeroconf/__init__.py:2440)
  0.00%   0.00%   0.090s    0.090s   notify (threading.py:352)
  0.00%   0.00%   0.070s    0.070s   update_record (zeroconf/__init__.py:1469)
  0.00%   0.00%   0.060s    0.070s   __eq__ (zeroconf/__init__.py:606)
  0.00%   0.00%   0.050s    0.050s   acquire (logging/__init__.py:843)
  0.00%   0.00%   0.050s    0.050s   unpack (zeroconf/__init__.py:722)
  0.00%   0.00%   0.050s    0.050s   read_name (zeroconf/__init__.py:828)
  0.00%   0.00%   0.050s    0.050s   is_expired (zeroconf/__init__.py:494)
  0.00%   0.00%   0.040s    0.040s   emit (logging/__init__.py:1028)
  1.00%   1.00%   0.040s    0.040s   __init__ (zeroconf/__init__.py:386)
  0.00%   0.00%   0.040s    0.040s   __enter__ (threading.py:241)
``` ([`37fa0a0`](https://github.com/python-zeroconf/python-zeroconf/commit/37fa0a0d59a5b5d09295a462bf911e82d2d770ed))

* Support cooperating responders (#224) ([`1ca023f`](https://github.com/python-zeroconf/python-zeroconf/commit/1ca023fae4b586679446ceaf3e2e9955ea5bf180))

* Remove duplciate update messages sent to listeners

The prior code used to send updates even when the new record was identical to the old.

This resulted in duplciate update messages when there was in fact no update (apart from TTL refresh) ([`d8caa4e`](https://github.com/python-zeroconf/python-zeroconf/commit/d8caa4e2d71025ed42b33abb4d329329437b44fb))

* Refactor out unique assertion ([`5e4f496`](https://github.com/python-zeroconf/python-zeroconf/commit/5e4f496778d91ccfc65e946d3d94c39ab6388b29))

* Fix representation of IPv6 DNSAddress (#230) ([`f6690d2`](https://github.com/python-zeroconf/python-zeroconf/commit/f6690d2048cb87cb0fb3a7c3b832cf1a1f40e61a))

* Do not exclude interfaces with host-only netmasks from InterfaceChoice.All (#227)

Host-only netmasks do not forbid multicast.

Tested on Debian 10 running in Qubes and on Ubuntu 18.04. ([`ca8e53d`](https://github.com/python-zeroconf/python-zeroconf/commit/ca8e53de55a563f5c7049be2eda14ae0ecd1a7cf))

* Ensure all TXT, SRV, A records are unique

Fixes issues with shared records being used where they shouldn't be.

PTR records should be shared, but SRV, TXT and A/AAAA records should be unique.

Whilst mDNS and DNS-SD in theory support shared records for these types of record, they are not implemented in python-zeroconf at the moment.

See zeroconf.check_service() method which verifies the service is unique on the network before registering. ([`bef8f59`](https://github.com/python-zeroconf/python-zeroconf/commit/bef8f593ae820eb8465934de91eb27468edf6444))


## v0.24.4 (2019-12-30)

### Unknown

* Release version 0.24.4 ([`29432bf`](https://github.com/python-zeroconf/python-zeroconf/commit/29432bfffd057cf4da7636ba0c28c9d8a7ad4357))

* Clean up output of ttl remaining to be whole seconds only ([`ba1b78d`](https://github.com/python-zeroconf/python-zeroconf/commit/ba1b78dbdcc64f8d35c951e7ca53d2898e7d7900))

* Clean up format to cleanly separate [question]=ttl,answer ([`4b735dc`](https://github.com/python-zeroconf/python-zeroconf/commit/4b735dc5411f7b563f23b60b5c2aa806151cca1a))

* Update DNS entries so all subclasses of DNSRecord use to_string for display

All records based on DNSRecord now properly use to_string in repr, some were
only dumping the answer without the question (inconsistent). ([`8ccad54`](https://github.com/python-zeroconf/python-zeroconf/commit/8ccad54dab4a0ab7f573996f6fc0c2f2bad7eafe))

* Fix resetting of TTL (#209)

Fix resetting of TTL

Previously the reset_ttl method changed the time created and the TTL value, but did not change the expiration time or stale times. As a result a record would expire even when this method had been called. ([`b47efd8`](https://github.com/python-zeroconf/python-zeroconf/commit/b47efd8eed0b5ed9d3b6bca8573a6ed1916c982a))


## v0.24.3 (2019-12-23)

### Unknown

* Release version 0.24.3 ([`2316027`](https://github.com/python-zeroconf/python-zeroconf/commit/2316027e5e96d8f10fae7607da5b72a9bab819fc))

* Fix import-time TypeError on CPython 3.5.2

The error: TypeError: 'ellipsis' object is not iterable."

Explanation can be found here: https://github.com/jstasiak/python-zeroconf/issues/208

Closes GH-208. ([`f53e24b`](https://github.com/python-zeroconf/python-zeroconf/commit/f53e24bddb3a6cb242cace2a541ed507e823be33))


## v0.24.2 (2019-12-17)

### Unknown

* Release version 0.24.2 ([`76bc675`](https://github.com/python-zeroconf/python-zeroconf/commit/76bc67532ad26f54c194e1e6537d2da4390f83e2))

* Provide and enforce type hints everywhere except for tests

The tests' time will come too in the future, though, I think. I believe
nose has problems with running annotated tests right now so let's leave
it for later.

DNSEntry.to_string renamed to entry_to_string because DNSRecord
subclasses DNSEntry and overrides to_string with a different signature,
so just to be explicit and obvious here I renamed it – I don't think any
client code will break because of this.

I got rid of ServicePropertiesType in favor of generic Dict because
having to type all the properties got annoying when variance got
involved – maybe it'll be restored in the future but it seems like too
much hassle now. ([`f771587`](https://github.com/python-zeroconf/python-zeroconf/commit/f7715874c2242b95cf9815549344ea66ac107b6e))

* Fix get_expiration_time percent parameter annotation

It takes integer percentage values at the moment so let's document that. ([`5986bf6`](https://github.com/python-zeroconf/python-zeroconf/commit/5986bf66e77e77f9e0b6ba43a4758ecb0da04ff6))

* Add support for AWDL interface on macOS

The API is inspired by Apple's NetService.includesPeerToPeer
(see https://developer.apple.com/documentation/foundation/netservice/1414086-includespeertopeer) ([`fcafdc1`](https://github.com/python-zeroconf/python-zeroconf/commit/fcafdc1e285cc5c3c1f2c413ac9309d3426179f4))


## v0.24.1 (2019-12-16)

### Unknown

* Release version 0.24.1 ([`53dd06c`](https://github.com/python-zeroconf/python-zeroconf/commit/53dd06c37f6205129e81f5c6b69e508a54f94d07))

* Bugfix: TXT record's name is never equal to Service Browser's type.

TXT record's name is never equal to Service Browser's type. We should
check whether TXT record's name ends with Service Browser's type.
Otherwise, we never get updates of TXT records. ([`2a597ee`](https://github.com/python-zeroconf/python-zeroconf/commit/2a597ee80906a27effd442d033de10b5129e6900))

* Bugfix: Flush outdated cache entries when incoming record is unique.

According to RFC 6762 10.2. Announcements to Flush Outdated Cache Entries,
when the incoming record's cache-flush bit is set (record.unique == True
in this module), "Instead of merging this new record additively into the
cache in addition to any previous records with the same name, rrtype, and
rrclass, all old records with that name, rrtype, and rrclass that were
received more than one second ago are declared invalid, and marked to
expire from the cache in one second." ([`1d39b3e`](https://github.com/python-zeroconf/python-zeroconf/commit/1d39b3edd141093f9e579ab83377fe8f5ecb357d))

* Change order of equality check to favor cheaper checks first

Comparing two strings is much cheaper than isinstance, so we should try
those first

A performance test was run on a network with 170 devices running Zeroconf.
There was a ServiceBrowser running on a separate thread while a timer ran
on the main thread that forced a thread switch every 2 seconds (to include
the effect of thread switching in the measurements). Every minute,
a Zeroconf broadcast was made on the network.

This was ran this for an hour on a Macbook Air from 2015 (Intel Core
i7-5650U) using Ubuntu 19.10 and Python 3.7, both before this commit and
after.

These are the results of the performance tests:
Function		Before count		Before time	Before time per count	After count		After time		After time per count	Time reduction
DNSEntry.__eq__		528			0.001s		1.9μs			538			0.001s			1.9μs			1.9%
DNSPointer.__eq__	24369256 (24.3M)	134.641s	5.5μs			25989573 (26.0M)	86.405s			3.3μs			39.8%
DNSText.__eq__		52966716 (53.0M)	190.640s	3.6μs			53604915 (53.6M)	169.104s		3.2μs			12.4%
DNSService.__eq__	52620538 (52.6M)	171.660s	3.3μs			56557448 (56.6M)	170.222s		3.0μs			7.8% ([`815ac77`](https://github.com/python-zeroconf/python-zeroconf/commit/815ac77e9146c37afd7c5389ed45adee9f1e2e36))

* Dont recalculate the expiration and stale time every update

I have a network with 170 devices running Zeroconf. Every minute
a zeroconf request for broadcast is cast out. Then we were listening for
Zeroconf devices on that network.

To get a more realistic test, the Zeroconf ServiceBrowser is ran on
a separate thread from a main thread. On the main thread an I/O limited
call to QNetworkManager is made every 2 seconds,

in order to include performance penalties due to thread switching. The
experiment was ran on a MacBook Air 2015 (Intel Core i7-5650U) through
Ubuntu 19.10 and Python 3.7.

This was left running for exactly one hour, both before and after this commit.

Before this commit, there were 132107499 (132M) calls to the
get_expiration_time function, totalling 141.647s (just over 2 minutes).

After this commit, there were 1661203 (1.6M) calls to the
get_expiration_time function, totalling 2.068s.

This saved about 2 minutes of processing time out of the total 60 minutes,
on average 3.88% processing power on the tested CPU. It is expected to see
similar improvements on all CPU architectures. ([`2e9699c`](https://github.com/python-zeroconf/python-zeroconf/commit/2e9699c542f691fc605e4a1c03cbf496273a9835))

* Significantly improve the speed of the entries function of the cache

Tested this with Python 3.6.8, Fedora 28. This was done in a network with
a lot of discoverable devices.

before:
Total time: 1.43086 s

Line #      Hits         Time  Per Hit   % Time  Line Contents
==============================================================
  1138                                               @profile
  1139                                               def entries(self):
  1140                                                   """Returns a list of all entries"""
  1141      2063       3578.0      1.7      0.3          if not self.cache:
  1142         2          3.0      1.5      0.0              return []
  1143                                                   else:
  1144                                                       # avoid size change during iteration by copying the cache
  1145      2061      22051.0     10.7      1.5              values = list(self.cache.values())
  1146      2061    1405227.0    681.8     98.2              return reduce(lambda a, b: a + b, values)

After:
Total time: 0.43725 s

Line #      Hits         Time  Per Hit   % Time  Line Contents
==============================================================
  1138                                               @profile
  1139                                               def entries(self):
  1140                                                   """Returns a list of all entries"""
  1141      3651      10171.0      2.8      2.3          if not self.cache:
  1142         2          7.0      3.5      0.0              return []
  1143                                                   else:
  1144                                                       # avoid size change during iteration by copying the cache
  1145      3649      67054.0     18.4     15.3              values = list(self.cache.values())
  1146      3649     360018.0     98.7     82.3              return list(itertools.chain.from_iterable(values)) ([`157fc20`](https://github.com/python-zeroconf/python-zeroconf/commit/157fc2003318d785d07b362e1fd2ba3fe5d373f0))

* The the formatting of the IPv6 section in the readme ([`6ab7dbf`](https://github.com/python-zeroconf/python-zeroconf/commit/6ab7dbf27a2086e20f4486e693e2091d043af1db))


## v0.24.0 (2019-11-19)

### Unknown

* Release version 0.24.0 ([`f03dc42`](https://github.com/python-zeroconf/python-zeroconf/commit/f03dc42d6234419053bda18ca6f2b90bec1b9257))

* Improve type hint coverage ([`c827f9f`](https://github.com/python-zeroconf/python-zeroconf/commit/c827f9fdc4c58433143ea8815029c3387b500ff5))

* Add py.typed marker (closes #199)

This required changing to a proper package. ([`41b31cb`](https://github.com/python-zeroconf/python-zeroconf/commit/41b31cb338e8a8a7d1a548662db70d9014e8a352))

* Link to the documentation ([`3db9d82`](https://github.com/python-zeroconf/python-zeroconf/commit/3db9d82d888abe880bfdd2fb2c3fe3eddcb48ae9))

* Setup basic Sphinx documentation

Closes #200 ([`1c33e5f`](https://github.com/python-zeroconf/python-zeroconf/commit/1c33e5f5b44732d446d629cc13000cff3527afef))

* ENOTCONN is not an error during shutdown

When `python-zeroconf` is used in conjunction with `eventlet`, `select.select()` will return with an error code equal to `errno.ENOTCONN` instead of `errno.EBADF`. As a consequence, an exception is shown in the console during shutdown. I believe that it should not cause any harm to treat `errno.ENOTCONN` the same way as `errno.EBADF` to prevent this exception. ([`c86423a`](https://github.com/python-zeroconf/python-zeroconf/commit/c86423ab0223bab682614e18a6a09050dfc80087))

* Rework exposing IPv6 addresses on ServiceInfo

* Return backward compatibility for ServiceInfo.addresses by making
  it return V4 addresses only
* Add ServiceInfo.parsed_addresses for convenient access to addresses
* Raise TypeError if addresses are not provided as bytes (otherwise
  an ugly assertion error is raised when sending)
* Add more IPv6 unit tests ([`98a1ce8`](https://github.com/python-zeroconf/python-zeroconf/commit/98a1ce8b99ddb03de9f6cccca49396fcf177e0d0))

* Finish AAAA records support

The correct record type was missing in a few places. Also use
addresses_by_version(All) in preparation for switching addresses
to V4 by default. ([`aae7fd3`](https://github.com/python-zeroconf/python-zeroconf/commit/aae7fd3ba851d1894732c4270cef745127cc03da))

* Test with pypy3.6

Right now this is available as pypy3 in Travis CI. Running black on PyPy
needs to be disabled for now because of an issue[1] that's been patched
only recently and it's not available in Travis yet.

[1] https://bitbucket.org/pypy/pypy/issues/2985/pypy36-osreplace-pathlike-typeerror ([`fec839a`](https://github.com/python-zeroconf/python-zeroconf/commit/fec839ae4fdcb870066fff855809583dcf7d7a17))

* Stop specifying precise pypy3.5 version

This allows us to test with the latest available one. ([`c2e8bde`](https://github.com/python-zeroconf/python-zeroconf/commit/c2e8bdebc6cec128d01197d53c3402278a4b62ed))

* Simplify Travis CI configuration regarding Python 3.7

Selecting xenial manually is no longer needed. ([`5359ea0`](https://github.com/python-zeroconf/python-zeroconf/commit/5359ea0a0b4cdca0854ae97c5d11036633102c67))

* Test with Python 3.8 ([`15118c8`](https://github.com/python-zeroconf/python-zeroconf/commit/15118c837a148a37edd29a20294e598ecf09c3cf))

* Make AAAA records work (closes #52) (#191)

This PR incorporates changes from the earlier PR #179 (thanks to Mikael Pahmp), adding tests and a few more fixes to make AAAA records work in practice.

Note that changing addresses to container IPv6 addresses may be considered a breaking change, for example, for consumers that unconditionally apply inet_aton to them. I'm introducing a new function to be able to retries only addresses from one family. ([`5bb9531`](https://github.com/python-zeroconf/python-zeroconf/commit/5bb9531be48f6f1e119643677c36d9e714204a8b))

* Improve static typing coverage ([`e5323d8`](https://github.com/python-zeroconf/python-zeroconf/commit/e5323d8c9795c59019173b8d202a50a49c415039))

* Add additional recommended records to PTR responses (#184)

RFC6763 indicates a server should include the SRV/TXT/A/AAAA records
when responding to a PTR record request.  This optimization ensures
the client doesn't have to then query for these additional records.

It has been observed that when multiple Windows 10 machines are monitoring
for the same service, this unoptimized response to the PTR record
request can cause extremely high CPU usage in both the DHCP Client
& Device Association service (I suspect due to all clients having to
then sending/receiving the additional queries/responses). ([`ea64265`](https://github.com/python-zeroconf/python-zeroconf/commit/ea6426547f79c32c6d5d3bcc2d0a261bf503197a))

* Rename IpVersion to IPVersion

A follow up to 3d5787b8c5a92304b70c04f48dc7d5cec8d9aac8. ([`ceb602c`](https://github.com/python-zeroconf/python-zeroconf/commit/ceb602c0d1bc1d3a269fd233b072a9b929076438))

* First stab at supporting listening on IPv6 interfaces

This change adds basic support for listening on IPv6 interfaces.
Some limitations exist for non-POSIX platforms, pending fixes in
Python and in the ifaddr library. Also dual V4-V6 sockets may not
work on all BSD platforms. As a result, V4-only is used by default.

Unfortunately, Travis does not seem to support IPv6, so the tests
are disabled on it, which also leads to coverage decrease. ([`3d5787b`](https://github.com/python-zeroconf/python-zeroconf/commit/3d5787b8c5a92304b70c04f48dc7d5cec8d9aac8))


## v0.23.0 (2019-06-04)

### Unknown

* Release version 0.23.0 ([`7bd0436`](https://github.com/python-zeroconf/python-zeroconf/commit/7bd04363c7ff0f583a17cc2fac42f9a9c1724769))

* Add support for multiple addresses when publishing a service (#170)

This is a rebased and fixed version of PR #27, which also adds compatibility shim for ServiceInfo.address and does a proper deprecation for it.

* Present all addresses that are available.

* Add support for publishing multiple addresses.

* Add test for backwards compatibility.

* Provide proper deprecation of the "address" argument and field

* Raise deprecation warnings when address is used
* Add a compatibility property to avoid breaking existing code
  (based on suggestion by Bas Stottelaar in PR #27)
* Make addresses keyword-only, so that address can be eventually
  removed and replaced with it without breaking consumers
* Raise TypeError instead of an assertion on conflicting address
  and addresses

* Disable black on ServiceInfo.__init__ until black is fixed

Due to https://github.com/python/black/issues/759 black produces
code that is invalid Python 3.5 syntax even with --target-version py35.
This patch disables reformatting for this call (it doesn't seem to be
possible per line) until it's fixed. ([`c787610`](https://github.com/python-zeroconf/python-zeroconf/commit/c7876108150cd251786db4ab52dadd1b2283d262))

* Makefile: be specific which files to check with black (#169)

Otherwise black tries to check the "env" directory, which fails. ([`6b85a33`](https://github.com/python-zeroconf/python-zeroconf/commit/6b85a333de21fa36187f081c3c115c8af40d7055))

* Run black --check as part of CI to enforce code style ([`12477c9`](https://github.com/python-zeroconf/python-zeroconf/commit/12477c954e7f051d10152f9ab970e28fd4222b30))

* Refactor the CI script a bit to make adding black check easier ([`69ad22c`](https://github.com/python-zeroconf/python-zeroconf/commit/69ad22cf852a12622f78aa2f4e7cf20c2d395db2))

* Reformat the code using Black

We could use some style consistency in the project and Black looks like
the best tool for the job.

Two flake8 errors are being silenced from now on:

* E203 whitespace before :
* W503 line break before binary operator

Both are to satisfy Black-formatted code (and W503 is somemwhat against
the latest PEP8 recommendations regarding line breaks and binary
operators in new code). ([`beb596c`](https://github.com/python-zeroconf/python-zeroconf/commit/beb596c345b0764bdfe1a828cfa744bcc560cf32))

* Add support for MyListener call getting updates to service TXT records (2nd attempt) (#166)

Add support for MyListener call getting updates to service TXT records

At the moment, the implementation supports notification to the  ServiceListener class for additions and removals of service, but for service updates to the TXT record, the client must poll the ServiceInfo class. This draft PR provides a mechanism to have a callback on the ServiceListener class be invoked when the TXT record changes. ([`d4e06bc`](https://github.com/python-zeroconf/python-zeroconf/commit/d4e06bc54098bfa7a863bcc11bb9e2035738c8f5))

* Remove Python 3.4 from the Python compatibility section

I forgot to do this in 4a02d0489da80e8b9e8d012bb7451cd172c753ca. ([`e1c2b00`](https://github.com/python-zeroconf/python-zeroconf/commit/e1c2b00c772a1538a6682c45884bbe89c8efba60))

* Drop Python 3.4 support (it's dead now)

See https://devguide.python.org/#status-of-python-branches ([`4a02d04`](https://github.com/python-zeroconf/python-zeroconf/commit/4a02d0489da80e8b9e8d012bb7451cd172c753ca))


## v0.22.0 (2019-04-27)

### Unknown

* Prepare release 0.22.0 ([`db1dcf6`](https://github.com/python-zeroconf/python-zeroconf/commit/db1dcf682e453766b53773d70c0091b81a87a192))

* Add arguments to set TTLs via ServiceInfo ([`ecc021b`](https://github.com/python-zeroconf/python-zeroconf/commit/ecc021b7a3cec863eed5a3f71a1f28e3026c25b0))

* Use recommended TTLs with overrides via ServiceInfo ([`a7aedb5`](https://github.com/python-zeroconf/python-zeroconf/commit/a7aedb58649f557a5e372fc776f98457ce84eb39))

* ttl: modify default used to respond to _services queries ([`f25989d`](https://github.com/python-zeroconf/python-zeroconf/commit/f25989d8cdae8f77e19eba70f236dd8103b33e8f))

* Fix service removal packets not being sent on shutdown ([`57310e1`](https://github.com/python-zeroconf/python-zeroconf/commit/57310e185a4f924dd257edd64f866da685a786c6))

* Adjust query intervals to match RFC 6762 (#159)

* Limit query backoff time to one hour as-per rfc6762 section 5.2
* tests: monkey patch backoff limit to focus testing on TTL expiry
* tests: speed up integration test
* tests: add test of query backoff interval and limit
* Set initial query interval to 1 second as-per rfc6762 sec 5.2
* Add comments around timing constants
* tests: fix linting errors
* tests: fix float assignment to integer var


Sets the repeated query backoff limit to one hour as opposed to 20 seconds, reducing unnecessary network traffic
Adds a test for the behaviour of the backoff procedure
Sets the first repeated query to happen after one second as opposed to 500ms ([`bee8abd`](https://github.com/python-zeroconf/python-zeroconf/commit/bee8abdba49e2275d203e3b0b4a3afac330ec4ea))

* Turn on and address mypy check_untyped_defs ([`4218d75`](https://github.com/python-zeroconf/python-zeroconf/commit/4218d757994467ee710b0cad034ea1fb6035d3ea))

* Turn on and address mypy warn-return-any ([`006e614`](https://github.com/python-zeroconf/python-zeroconf/commit/006e614315c12e5232e6168ce0bacf0dc056ba8a))

* Turn on and address mypy no-implicit-optional ([`071c6ed`](https://github.com/python-zeroconf/python-zeroconf/commit/071c6edb924b6bc9b67859dc9860cfe09cc98d07))

* Add reminder to enable disallow_untyped_calls for mypy ([`24bb44f`](https://github.com/python-zeroconf/python-zeroconf/commit/24bb44f858cd325d7ff2892c53dc1dd9f26ed768))

* Enable some more mypy warnings ([`183a846`](https://github.com/python-zeroconf/python-zeroconf/commit/183a84636a9d4fec6306d065a4f855fec95086e4))

* Run mypy on test_zeroconf.py too

This will reveal issues with current type hints as demonstrated by a
commit/issue to be submitted later, as well as prevent some others
from cropping up meanwhile. ([`74391d5`](https://github.com/python-zeroconf/python-zeroconf/commit/74391d5c124bf6f899059db93bbf7e99b96d8aad))

* Move mypy config to setup.cfg

Removes need for a separate file, better to have more in one place. ([`2973931`](https://github.com/python-zeroconf/python-zeroconf/commit/29739319ccf71f48c06bc1b74cd193f17fb6b272))

* Don't bother with a universal wheel as we're Python >= 3 only ([`9c0f1ab`](https://github.com/python-zeroconf/python-zeroconf/commit/9c0f1ab03b90f87ff1d58278a0b9b77c16195185))

* Add unit tests for default ServiceInfo properties. ([`a12c3b2`](https://github.com/python-zeroconf/python-zeroconf/commit/a12c3b2a3b4300849e0a4dcdd4df5386286b88d3))

* Modify ServiceInfo's __init__ properties' default value.

This commit modifies the default value of the argument properties of
ServiceInfo’s __init__() to byte array (properties=b’’). This enables
to instantiate it without setting the properties argument. As it is,
and because properties is not mandatory, if a user does not specify
the argument, an exception (AssertionError) is thrown:

Traceback (most recent call last):
  File "src/zeroconf-test.py", line 72, in <module>
    zeroconf.register_service(service)
  File "/home/jmpcm/zeroconf-test/src/zeroconf.py", line 1864, in register_service
    self.send(out)
  File "/home/jmpcm/zeroconf-test/src/zeroconf.py", line 2091, in send
    packet = out.packet()
  File "/home/jmpcm/zeroconf-test/src/zeroconf.py", line 1026, in packet
    overrun_answers += self.write_record(answer, time_)
  File "/home/jmpcm/zeroconf-test/src/zeroconf.py", line 998, in write_record
    record.write(self)
  File "/home/jmpcm/zeroconf-test/src/zeroconf.py", line 579, in write
    out.write_string(self.text)
  File "/home/jmpcm/zeroconf-test/src/zeroconf.py", line 903, in write_string
    assert isinstance(value, bytes)
AssertionError

The argument can be either a dictionary or a byte array. The function
_set_properties() will always create a byte array with the user's
properties. Changing the default value to a byte array, avoids the
conversion to byte array and avoids the exception. ([`9321007`](https://github.com/python-zeroconf/python-zeroconf/commit/93210079259bd0973e3b54a90dff971e14abf595))

* Fix some spelling errors ([`88fb0e3`](https://github.com/python-zeroconf/python-zeroconf/commit/88fb0e34f902498f6ceb583ce6fa9346745a14ca))

* Require flake8 >= 3.6.0, drop pycodestyle restriction

Fixes current build breakage related to flake8 dependencies.

The breakage:

$ make flake8
flake8 --max-line-length=110 examples *.py
Traceback (most recent call last):
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/pkg_resources/__init__.py", line 2329, in resolve
    return functools.reduce(getattr, self.attrs, module)
AttributeError: module 'pycodestyle' has no attribute 'break_after_binary_operator'
During handling of the above exception, another exception occurred:
Traceback (most recent call last):
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/plugins/manager.py", line 182, in load_plugin
    self._load(verify_requirements)
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/plugins/manager.py", line 154, in _load
    self._plugin = resolve()
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/pkg_resources/__init__.py", line 2331, in resolve
    raise ImportError(str(exc))
ImportError: module 'pycodestyle' has no attribute 'break_after_binary_operator'
During handling of the above exception, another exception occurred:
Traceback (most recent call last):
  File "/home/travis/virtualenv/python3.5.6/bin/flake8", line 11, in <module>
    sys.exit(main())
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/main/cli.py", line 16, in main
    app.run(argv)
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/main/application.py", line 412, in run
    self._run(argv)
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/main/application.py", line 399, in _run
    self.initialize(argv)
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/main/application.py", line 381, in initialize
    self.find_plugins()
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/main/application.py", line 197, in find_plugins
    self.check_plugins.load_plugins()
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/plugins/manager.py", line 434, in load_plugins
    plugins = list(self.manager.map(load_plugin))
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/plugins/manager.py", line 319, in map
    yield func(self.plugins[name], *args, **kwargs)
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/plugins/manager.py", line 432, in load_plugin
    return plugin.load_plugin()
  File "/home/travis/virtualenv/python3.5.6/lib/python3.5/site-packages/flake8/plugins/manager.py", line 189, in load_plugin
    raise failed_to_load
flake8.exceptions.FailedToLoadPlugin: Flake8 failed to load plugin "pycodestyle.break_after_binary_operator" due to module 'pycodestyle' has no attribute 'break_after_binary_operator'. ([`73b3620`](https://github.com/python-zeroconf/python-zeroconf/commit/73b3620908cb5e2f54231692c17f6bbb8a42d09d))

* Drop flake8-blind-except

Obsoleted by pycodestyle 2.1's E722. ([`e3b7e40`](https://github.com/python-zeroconf/python-zeroconf/commit/e3b7e40af52d05264794e2e4d37dfdb1c5d3814a))

* Test with PyPy 3.5 5.10.1 ([`51a6f70`](https://github.com/python-zeroconf/python-zeroconf/commit/51a6f7081bd5590ca5ea5418b39172714b7ef1fe))

* Fix a changelog typo ([`e08db28`](https://github.com/python-zeroconf/python-zeroconf/commit/e08db282edd8459e35d17ae4e7278106056a0c94))


## v0.21.3 (2018-09-21)

### Unknown

* Prepare release 0.21.3 ([`059530d`](https://github.com/python-zeroconf/python-zeroconf/commit/059530d075fe1575ebbab535be67ac7d5ae7caed))

* Actually allow underscores in incoming service names

This was meant to be released earlier, but I failed to merge part of my
patch.

Fixes: ff4a262adc69 ("Allow underscores in incoming service names")
Closes #102 ([`ae3bd51`](https://github.com/python-zeroconf/python-zeroconf/commit/ae3bd517d84aae631db1cc294caf22541a7f4bd5))


## v0.21.2 (2018-09-20)

### Unknown

* Prepare release 0.21.2 ([`af33c83`](https://github.com/python-zeroconf/python-zeroconf/commit/af33c83e72d6fa4171342f78d15b2f28038f1318))

* Fix typing-related TypeError

Older typing versions don't allow what we did[1]. We don't really need
to be that precise here anyway.

The error:

    $ python
    Python 3.5.2 (default, Nov 23 2017, 16:37:01)
    [GCC 5.4.0 20160609] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import zeroconf
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/scraper/venv/lib/python3.5/site-packages/zeroconf.py", line 320, in <module>
        OptionalExcInfo = Tuple[Optional[Type[BaseException]], Optional[BaseException], Optional[TracebackType]]
      File "/usr/lib/python3.5/typing.py", line 649, in __getitem__
        return Union[arg, type(None)]
      File "/usr/lib/python3.5/typing.py", line 552, in __getitem__
        dict(self.__dict__), parameters, _root=True)
      File "/usr/lib/python3.5/typing.py", line 512, in __new__
        for t2 in all_params - {t1} if not isinstance(t2, TypeVar)):
      File "/usr/lib/python3.5/typing.py", line 512, in <genexpr>
        for t2 in all_params - {t1} if not isinstance(t2, TypeVar)):
      File "/usr/lib/python3.5/typing.py", line 1077, in __subclasscheck__
        if super().__subclasscheck__(cls):
      File "/usr/lib/python3.5/abc.py", line 225, in __subclasscheck__
        for scls in cls.__subclasses__():
    TypeError: descriptor '__subclasses__' of 'type' object needs an argument

Closes #141
Fixes: 1f33c4f8a805 ("Introduce some static type analysis to the codebase")

[1] https://github.com/python/typing/issues/266 ([`627c22e`](https://github.com/python-zeroconf/python-zeroconf/commit/627c22e19166c123244567410adc390ed368eca7))


## v0.21.1 (2018-09-17)

### Unknown

* Prepare release 0.21.1 ([`1684a46`](https://github.com/python-zeroconf/python-zeroconf/commit/1684a46d57a437fc8cc7b5887d51440424c6ded5))

* Bringing back compatibility with python 3.4 (#140)

The latest release of zeroconf in PyPI (0.21.0) breaks compatibility with python 3.4 due to an unstated dependency on the typing package. ([`919191c`](https://github.com/python-zeroconf/python-zeroconf/commit/919191ca266d8d589ad33cc6dd2c197f75092634))


## v0.21.0 (2018-09-16)

### Unknown

* Prepare release 0.21.0 ([`b03cee3`](https://github.com/python-zeroconf/python-zeroconf/commit/b03cee348973469e9ebfce6e9b0e0a367c146401))

* Allow underscores in incoming service names

There are real world cases of services broadcasting names with
underscores in them so tough luck, let's accept those to be compatible.
Registering service names with underscores in them continues to be
disallowed.

Closes https://github.com/jstasiak/python-zeroconf/issues/102 ([`ff4a262`](https://github.com/python-zeroconf/python-zeroconf/commit/ff4a262adc6926905c71e2952b3159b84a974d02))

* Don't mention unsupported Python versions ([`208ec1b`](https://github.com/python-zeroconf/python-zeroconf/commit/208ec1ba58a6ebf7160a760feffe62cf366137e5))

* using ifaddr instead of netifaces as ifaddr is a pure python lib ([`7c0500e`](https://github.com/python-zeroconf/python-zeroconf/commit/7c0500ee19869ce0e85e58a26b8fdb0868e0b142))

* Show that we actually support Python 3.7

We can't just add Python 3.7 like earlier versions because Travis
doesn't support it at the moment[1].

[1] https://github.com/travis-ci/travis-ci/issues/9815 ([`418b4b8`](https://github.com/python-zeroconf/python-zeroconf/commit/418b4b814e6483a20a5cac2178a2cd815d5b91c0))

* Introduce some static type analysis to the codebase

The main purpose of this change is to make the code easier to read and
explore. Preventing some classes of bugs is a bonus.

On top of just adding type hints and enabling mypy to verify them the
following changes were needed:
* casts in places where we know what we're doing but mypy can't know it
* RecordUpdateListener interfaces extracted out of ServiceBrowser and
  ServiceInfo classes so that we have a common name we can use in places
  where we only need an instance of one of those classes to call to call
  update_record() on it. This way we can keep mypy happy
* assert isinstance(...) blocks to provide hints for mypy as to what
  concrete types we're dealing with
* some local type mixing removed (previously we'd first assign a value
  of one type to a variable and then overwrite with another type)
* explicit "return None" in case of function that returns optionally -
  mypy enforces explicit return in this case ([`1f33c4f`](https://github.com/python-zeroconf/python-zeroconf/commit/1f33c4f8a8050cdfb051c0da7ebe80a9ff24cf25))

* Fix a logging call

The format string expects three parameters, one of them was accidentally
passed to the log_warning_once() method instead.

Fixes: aa1f48433cbd ("Improve test coverage, and fix issues found") ([`23fdcce`](https://github.com/python-zeroconf/python-zeroconf/commit/23fdcce35fa020d09267e6fa57cf21cfb744a2c4))

* Fix UTF-8 multibyte name compression ([`e11700f`](https://github.com/python-zeroconf/python-zeroconf/commit/e11700ff9ea9eb429c701dfb73c4cf2c45994015))

* Remove some legacy cruft

The latest versions of flake8 and flake8-import-order can be used just
fine now (they've been ok for some time).

Since with google style flake8-import-order would generate more issues
than with the cryptography style I decided to switch and fix one thing
it complained about.

We switch to pycodestyle instead of pinned pep8 version as that pep8
version can't be installed with latest flake8 and the name of the
package has been changed to pycodestyle. We still pin the version though
as there's a bad interaction between the latest pycodestyle and the
latest flake8. ([`6fe8132`](https://github.com/python-zeroconf/python-zeroconf/commit/6fe813212f46576cf305c17ee815536a83128fce))

* Fix UnboundLocalError for count after loop

This code throws an `UnboundLocalError` as `count` doesn't exist in the `else` branch of the for loop. ([`42c8662`](https://github.com/python-zeroconf/python-zeroconf/commit/42c866298725a8e9667bf1230be845e856cb382a))

* examples: Add an example of resolving a known service by service name

To use:
* `avahi-publish-service -s 'My Service Name' _test._tcp 0`
* `./examples/resolver.py` should print a `ServiceInfo`
* Kill the `avahi-publish-service` process
* `./examples/resolver.py` should print `None`

Signed-off-by: Simon McVittie <smcv@collabora.com> ([`703d971`](https://github.com/python-zeroconf/python-zeroconf/commit/703d97150de1c74b7c1a62b59c1ff7081dec8256))

* Handle Interface Quirck to make it work on WSL (Windows Service for Linux) ([`374f45b`](https://github.com/python-zeroconf/python-zeroconf/commit/374f45b783caf35b26f464130fbd1ff62591af2e))

* Make some variables PEP 8-compatible

Previously pep8-naming would complain about those:

test_zeroconf.py:221:10: N806 variable 'numQuestions' in function should be lowercase
        (numQuestions, numAnswers, numAuthorities, ([`49fc106`](https://github.com/python-zeroconf/python-zeroconf/commit/49fc1067245b2d3a7bcc1e7611f36ba8d9a36598))

* Fix flake8 (#131)

* flake8 and therefore Travis should be happy now

* attempt to fix flake8

* happy flake8 ([`53bc65a`](https://github.com/python-zeroconf/python-zeroconf/commit/53bc65af14ed979a5234bfa03c1295a2b27f6e40))

* implementing unicast support (#124)

* implementing unicast support

* use multicast=False for outgoing dns requests in unicast mode ([`826c961`](https://github.com/python-zeroconf/python-zeroconf/commit/826c9619797e4cf1f2c39b95ed1c93faed7eee2a))

* Remove unwanted whitespace ([`d0d1cfb`](https://github.com/python-zeroconf/python-zeroconf/commit/d0d1cfbb31f0ea6bd08b0c8ffa97ba3d7604bccc))

* Fix TTL handling for published service, align default TTL with RFC6762 (#113)

Honor TTL passed in service registration
Set default TTL to 120 s as recommended by RFC6762 ([`14e3ad5`](https://github.com/python-zeroconf/python-zeroconf/commit/14e3ad5f15f5a0f5235ad7dbb22924b4b5ae1c77))

* add import error for Python <= 3.3 (#123) ([`fe62ba3`](https://github.com/python-zeroconf/python-zeroconf/commit/fe62ba31a8ab05a948ed6036dc319b1a1fa14e66))


## v0.20.0 (2018-02-21)

### Unknown

* Release version 0.20.0 ([`0622570`](https://github.com/python-zeroconf/python-zeroconf/commit/0622570645116b0c45ee03d38b7b308be2026bd4))

* Add some missing release information ([`5978bdb`](https://github.com/python-zeroconf/python-zeroconf/commit/5978bdbdab017d06ea496ea6d7c66c672751b255))

* Drop support for Python 2 and 3.3

This simplifies the code slightly, reduces the number of dependencies
and otherwise speeds up the CI process. If someone *really* needs to use
really old Python they have the option of using older versions of the
package. ([`f22f421`](https://github.com/python-zeroconf/python-zeroconf/commit/f22f421e4e6bf1ca7671b1eb540ba09fbf1e04b1))

* Add license and readme file to source tarball (#108)

Closes #97 ([`6ad04a5`](https://github.com/python-zeroconf/python-zeroconf/commit/6ad04a5d7f6d63c1f48b5948b6ade0e56cafe258))

* Allow the usage of newer netifaces in development

We're being consistent with c5e1f65c19b2f63a09b6517f322d600911fa1e13
here. ([`7123f8e`](https://github.com/python-zeroconf/python-zeroconf/commit/7123f8ed7dfd9277245748271d8870f18299b035))

* Correct broken __eq__ in child classes to DNSRecord ([`4d6dd73`](https://github.com/python-zeroconf/python-zeroconf/commit/4d6dd73a8313b81bbfef8b074d6fe4878bce4f74))

* Refresh ServiceBrowser entries already when 'stale'
Updated integration testcase to test for this. ([`37c5211`](https://github.com/python-zeroconf/python-zeroconf/commit/37c5211980548ab701bba725feeb5395ed1af0a7))

* Add new records first in cache entry instead of last (#110)

* Add new records first in cache entry instead of last

* Added DNSCache unit test ([`8101b55`](https://github.com/python-zeroconf/python-zeroconf/commit/8101b557199c4d3d001c75a717eafa4d5544142f))


## v0.19.1 (2017-06-13)

### Unknown

* Use more recent PyPy3 on Travis CI

The default PyPy3 is really old (implements Python 3.2) and some
packages won't cooperate with it anymore. ([`d0e4712`](https://github.com/python-zeroconf/python-zeroconf/commit/d0e4712eaa696ff13470b719cb6842260a3ada11))

* Release version 0.19.1 ([`1541191`](https://github.com/python-zeroconf/python-zeroconf/commit/1541191090a92ef23b8e3747933c95f7233aa2de))

* Allow newer netifaces releases

The bug that was concerning us[1] is fixed now.

[1] https://bitbucket.org/al45tair/netifaces/issues/39/netmask-is-always-255255255255 ([`c5e1f65`](https://github.com/python-zeroconf/python-zeroconf/commit/c5e1f65c19b2f63a09b6517f322d600911fa1e13))


## v0.19.0 (2017-03-21)

### Unknown

* Release version 0.19.0 ([`ecadb8c`](https://github.com/python-zeroconf/python-zeroconf/commit/ecadb8c30cd8e75da5b6d3e0e93d024f013dbfa2))

* Fix a whitespace issue flake8 doesn't like ([`87aa4e5`](https://github.com/python-zeroconf/python-zeroconf/commit/87aa4e587221e982902233ed2c8990ed27a2290f))

* Remove outdated example ([`d8686b5`](https://github.com/python-zeroconf/python-zeroconf/commit/d8686b5642d66b2c9ecc6f40b92e1a1a28279f79))

* Remove outdated comment ([`5aa6e85`](https://github.com/python-zeroconf/python-zeroconf/commit/5aa6e8546438d76b3fba5e91f9e4d4e3a3901757))

* Work around netifaces Windows netmask bug ([`6231d6d`](https://github.com/python-zeroconf/python-zeroconf/commit/6231d6d48d89240d95de9644570baf1b07ab04b0))


## v0.18.0 (2017-02-03)

### Unknown

* Release version 0.18.0 ([`48b1949`](https://github.com/python-zeroconf/python-zeroconf/commit/48b19498724825237d3002ee7681b6296c625b12))

* Add a missing changelog entry ([`5343510`](https://github.com/python-zeroconf/python-zeroconf/commit/53435104d5fb29847ac561f58e16cb48dd97b9f8))

* Handle select errors when closing Zeroconf

Based on a pull request by someposer[1] (code adapted to work on
Python 3).

Fixes two pychromecast issues[2][3].

[1] https://github.com/jstasiak/python-zeroconf/pull/88
[2] https://github.com/balloob/pychromecast/issues/59
[3] https://github.com/balloob/pychromecast/issues/120 ([`6e229f2`](https://github.com/python-zeroconf/python-zeroconf/commit/6e229f2714c8aff6555dfee2bdff34bda980a0c3))

* Explicitly support Python 3.6 ([`0a5ea31`](https://github.com/python-zeroconf/python-zeroconf/commit/0a5ea31543941033bcb4b2cb76fa7e125cb33550))

* Pin flake8 because flake8-import-order is pinned ([`9f0d8fe`](https://github.com/python-zeroconf/python-zeroconf/commit/9f0d8fe87dedece1365149911ce9587482fe1501))

* Drop Python 2.6 support, no excuse to use 2.6 these days ([`56ea542`](https://github.com/python-zeroconf/python-zeroconf/commit/56ea54245eeab9d544d96c38d136f9f47eedcda4))


## v0.17.7 (2017-02-01)

### Unknown

* Prepare the 0.17.7 release ([`376e011`](https://github.com/python-zeroconf/python-zeroconf/commit/376e011ad60c051f27632c77e6d50b64cf1defec))

* Merge pull request #77 from stephenrauch/fix-instance-name-with-dot

Allow dots in service instance name ([`9035c6a`](https://github.com/python-zeroconf/python-zeroconf/commit/9035c6a246b6856b5087b1bba9a9f3ce5873fcda))

* Allow dots in service instance name ([`e46af83`](https://github.com/python-zeroconf/python-zeroconf/commit/e46af83d35b4430d4577481b371d569797427858))

* Merge pull request #75 from stephenrauch/Fix-name-change

Fix for #29 ([`136dce9`](https://github.com/python-zeroconf/python-zeroconf/commit/136dce985fd66c81159d48b5f40e44349d1070ef))

* Fix/Implement duplicate name change (Issue 29) ([`788a48f`](https://github.com/python-zeroconf/python-zeroconf/commit/788a48f78466e048bdfc3028618bc4eaf807ef5b))

* some docs, cleanup and a couple of small test cases ([`b629ffb`](https://github.com/python-zeroconf/python-zeroconf/commit/b629ffb9c860a30366fa83b71487b546d6edd15b))

* Merge pull request #73 from stephenrauch/simplify-and-fix-pr-70

Simplify and fix PR 70 ([`6b67c0d`](https://github.com/python-zeroconf/python-zeroconf/commit/6b67c0d562866e63b81d1ec1c7f540c56244ade1))

* Simplify and fix PR 70 ([`2006cdd`](https://github.com/python-zeroconf/python-zeroconf/commit/2006cddf99377f43b528fbafea7d98be9d6282f0))

* Merge pull request #72 from stephenrauch/Catch-and-log-sendto-exceptions

Catch and log sendto() exceptions ([`c3f563f`](https://github.com/python-zeroconf/python-zeroconf/commit/c3f563f6d108d46732a380b7912f8f5c23d5e548))

* Catch and log sendto() exceptions ([`0924310`](https://github.com/python-zeroconf/python-zeroconf/commit/0924310415b79f0fa2523494d8a60803ec295e09))

* Merge pull request #71 from stephenrauch/improved-test-coverage

Improve test coverage, and fix issues found ([`254c207`](https://github.com/python-zeroconf/python-zeroconf/commit/254c2077f727d5e130aab2aaec111d58c134bd79))

* Improve test coverage, and fix issues found ([`aa1f484`](https://github.com/python-zeroconf/python-zeroconf/commit/aa1f48433cbd4dbf52565ec0c2635e5d52a37086))

* Merge pull request #70 from stephenrauch/Limit-size-of-packet

Limit the size of the packet that can be built ([`208e221`](https://github.com/python-zeroconf/python-zeroconf/commit/208e2219a1268e637e3cf02e1838cb94a6de2f31))

* Limit the size of the packet that can be built ([`8355c85`](https://github.com/python-zeroconf/python-zeroconf/commit/8355c8556929fcdb777705c97fc99de6012367b4))

* Merge pull request #69 from stephenrauch/name-compression

Help for oversized packets ([`5d9f40d`](https://github.com/python-zeroconf/python-zeroconf/commit/5d9f40de1a8549633cb5592fafc34d34df172965))

* Implement Name Compression ([`59877eb`](https://github.com/python-zeroconf/python-zeroconf/commit/59877ebb1b20ccd2747a0601e30329162ddcba4c))

* Drop oversized packets in send() ([`035605a`](https://github.com/python-zeroconf/python-zeroconf/commit/035605ab000fc8a8af94b4b9e1be9b81880b6bca))

* Add exception handler for oversized packets ([`af19c12`](https://github.com/python-zeroconf/python-zeroconf/commit/af19c12ec2286ee49e789a11599551dc43391383))

* Add QuietLogger mixin ([`0b77872`](https://github.com/python-zeroconf/python-zeroconf/commit/0b77872f7bb06ba6949c69bbfb70e8ae21f8ff9b))

* Improve service name validation error messages ([`fad66ca`](https://github.com/python-zeroconf/python-zeroconf/commit/fad66ca696530d39d8d5ae598e1724077eba8a5e))

* Merge pull request #68 from stephenrauch/Handle-dnsincoming-exceptions

Handle DNSIncoming exceptions ([`6c0a32d`](https://github.com/python-zeroconf/python-zeroconf/commit/6c0a32d6e4bd7be0b7573b95a5325b19dfd509d2))

* Make all test cases localhost only ([`080d0c0`](https://github.com/python-zeroconf/python-zeroconf/commit/080d0c09f1e58d4f8c430dac513948e5919e3f3b))

* Handle DNS Incoming Exception

This fixes a regression from removal of some overly broad exception
handling in 0.17.6.  This change adds an explicit handler for
DNSIncoming().  Will also log at warn level the first time it sees a
particular parsing exception. ([`061a2aa`](https://github.com/python-zeroconf/python-zeroconf/commit/061a2aa3c6e8a7c954a313c8a7d396f26f544c2b))


## v0.17.6 (2016-07-08)

### Testing

* test: added test for DNS-SD subtype discovery ([`914241b`](https://github.com/python-zeroconf/python-zeroconf/commit/914241b92c3097669e1e8c1a380f6c2f23a14cf8))

### Unknown

* Fix readme to valid reStructuredText, ([`94570b7`](https://github.com/python-zeroconf/python-zeroconf/commit/94570b730aaab606db820b9c4d48b1c313fdaa98))

* Prepare release 0.17.6 ([`e168a6f`](https://github.com/python-zeroconf/python-zeroconf/commit/e168a6fa5486d92114fb02d4c40b36f8298a022f))

* Merge pull request #61 from stephenrauch/add-python3.5

Add python 3.5 to Travis ([`617d9fd`](https://github.com/python-zeroconf/python-zeroconf/commit/617d9fd0db5bef350eaebd13cfcc73803900ad24))

* Add python 3.5 to Travis ([`6198e89`](https://github.com/python-zeroconf/python-zeroconf/commit/6198e8909b968430ddac9261f4dd9c508d96db65))

* Merge pull request #60 from stephenrauch/delay_ServiceBrowser_connect

Delay connecting ServiceBrowser() until it is running ([`56d9ac1`](https://github.com/python-zeroconf/python-zeroconf/commit/56d9ac13381a3ae205cb2b9339981a50f0a2eb62))

* Delay connecting ServiceBrowser() until it is running ([`6d1370c`](https://github.com/python-zeroconf/python-zeroconf/commit/6d1370cc2aa6d2c125aa924342e224b6b92ef8d9))

* Merge pull request #57 from herczy/master

resolve issue #56: service browser initialization race ([`0225a18`](https://github.com/python-zeroconf/python-zeroconf/commit/0225a18957a26855720d7ab002f3983cb9d76e0e))

* resolve issue #56: service browser initialization race ([`1567016`](https://github.com/python-zeroconf/python-zeroconf/commit/15670161c597bc035c0e9411d0bb830b9520589f))

* Merge pull request #58 from strahlex/subtype-test

added test for DNS-SD subtype discovery ([`4a569fe`](https://github.com/python-zeroconf/python-zeroconf/commit/4a569fe389d2fb5fd4b4f294ae9ebc0e38164e4a))

* Merge pull request #53 from stephenrauch/validate_service_names

Validate service names ([`76a5e99`](https://github.com/python-zeroconf/python-zeroconf/commit/76a5e99f2e772a9462d0f4b3ab4c80f1b0a3b542))

* Service Name Validation

This change validates service, instance and subtype names against
rfc6763.

Also adds test code for subtypes and provides a fix for issue 37. ([`88fa059`](https://github.com/python-zeroconf/python-zeroconf/commit/88fa0595cd880b6d82ac8580512461e64eb32d6b))

* Test Case and fixes for DNSHInfo (#49)

* Fix ability for a cache lookup to match properly

When querying for a service type, the response is processed.  During the
processing, an info lookup is performed.  If the info is not found in
the cache, then a query is sent.  Trouble is that the info requested is
present in the same packet that triggered the lookup, and a query is not
necessary.  But two problems caused the cache lookup to fail.

1) The info was not yet in the cache.  The call back was fired before
all answers in the packet were cached.

2) The test for a cache hit did not work, because the cache hit test
uses a DNSEntry as the comparison object.  But some of the objects in
the cache are descendents of DNSEntry and have their own __eq__()
defined which accesses fields only present on the descendent.  Thus the
test can NEVER work since the descendent's __eq__() will be used.

Also continuing the theme of some other recent pull requests, add three
_GLOBAL_DONE tests to avoid doing work after the attempted stop, and
thus avoid generating (harmless, but annoying) exceptions during
shutdown

* Remove unnecessary packet send in ServiceInfo.request()

When performing an info query via request(), a listener is started, and
a packet is formed. As the packet is formed, known answers are taken
from the cache and placed into the packet.  Then the packet is sent.
The packet is self received (via multicast loopback, I assume).  At that
point the listener is fired and the answers in the packet are propagated
back to the object that started the request.  This is a really long way
around the barn.

The PR queries the cache directly in request() and then calls
update_record().  If all of the information is in the cache, then no
packet is formed or sent or received.  This approach was taken because,
for whatever reason, the reception of the packets on windows via the
loopback was proving to be unreliable.  The method has the side benefit
of being a whole lot faster.

This PR also incorporates the joins() from PR #30.  In addition it moves
the two joins() in close() to their own thread because they can take
quite a while to execute.

* Fix locking race condition in Engine.run()

This fixes a race condition in which the receive engine was waiting
against its condition variable under a different lock than the one it
used to determine if it needed to wait.  This was causing the code to
sometimes take 5 seconds to do anything useful.

When fixing the race condition, decided to also fix the other
correctness issues in the loop which was likely causing the errors that
led to the inclusion of the 'except Exception' catch all.  This in turn
allowed the use of EBADF error due to closing the socket during exit to
be used to get out of the select in a timely manner.

Finally, this allowed reorganizing the shutdown code to shutdown from
the front to the back.  That is to say, shutdown the recv socket first,
which then allows a clean join with the engine thread.  After the engine
thread exits most everything else is inert as all callbacks have been
unwound.

* Remove a now invalid test case

With the restructure of shutdown, Listener() now needs to throw EBADF on
a closed socket to allow a timely and graceful shutdown.

* Shutdown the service listeners in an organized fashion

Also adds names to the various threads to make debugging easier.

* Improve test coverage

Add more needed shutdown cleanup found via additional test coverage.

Force timeout calculation from milli to seconds to use floating point.

* init ServiceInfo._properties

* Add query support and test case for _services._dns-sd._udp.local.

* pep8 cleanup

* Add testcase and fixes for HInfo Record Generation

The DNSHInfo packet generation code was broken. There was no test case for that
functionality, and adding a test case showed four issues. Two of which were
relative to PY3 string, one of which was a typoed reference to an attribute,
and finally the two fields present in the HInfo record were using the wrong
encoding, which is what necessitated the change from write_string() to
write_character_string(). ([`6b39c70`](https://github.com/python-zeroconf/python-zeroconf/commit/6b39c70fa1ed7cfac89e02e2b3764a9038b87267))

* Merge pull request #48 from stephenrauch/Find-Service-Types

Find service types ([`1dfc40f`](https://github.com/python-zeroconf/python-zeroconf/commit/1dfc40f4da145a55d60a952df90301ee0e5d65c4))

* Add query support and test case for _services._dns-sd._udp.local. ([`cfbb157`](https://github.com/python-zeroconf/python-zeroconf/commit/cfbb1572e44c4d8af1b50cb62abc0d426fc8e3ea))

* Merge pull request #45 from stephenrauch/master

Multiple fixes to speed up querys and remove exceptions at shutdown ([`183cd81`](https://github.com/python-zeroconf/python-zeroconf/commit/183cd81d9274bf28c642314df2f9e32f1f60020b))

* init ServiceInfo._properties ([`d909942`](https://github.com/python-zeroconf/python-zeroconf/commit/d909942e2c9479819e9113ffb3a354b1d99d6814))

* Improve test coverage

Add more needed shutdown cleanup found via additional test coverage.

Force timeout calculation from milli to seconds to use floating point. ([`75232cc`](https://github.com/python-zeroconf/python-zeroconf/commit/75232ccf28a820ee723db072951078eba31145a5))

* Shutdown the service listeners in an organized fashion

Also adds names to the various threads to make debugging easier. ([`ad3c248`](https://github.com/python-zeroconf/python-zeroconf/commit/ad3c248e4b67d5d2e9a4448a56b4e4648284ecd4))

* Remove a now invalid test case

With the restructure of shutdown, Listener() now needs to throw EBADF on
a closed socket to allow a timely and graceful shutdown. ([`7bbee59`](https://github.com/python-zeroconf/python-zeroconf/commit/7bbee590e553a1ff0e4dde3b1fdcf614b7e1ecd5))

* Fix locking race condition in Engine.run()

This fixes a race condition in which the receive engine was waiting
against its condition variable under a different lock than the one it
used to determine if it needed to wait.  This was causing the code to
sometimes take 5 seconds to do anything useful.

When fixing the race condition, decided to also fix the other
correctness issues in the loop which was likely causing the errors that
led to the inclusion of the 'except Exception' catch all.  This in turn
allowed the use of EBADF error due to closing the socket during exit to
be used to get out of the select in a timely manner.

Finally, this allowed reorganizing the shutdown code to shutdown from
the front to the back.  That is to say, shutdown the recv socket first,
which then allows a clean join with the engine thread.  After the engine
thread exits most everything else is inert as all callbacks have been
unwound. ([`8a110f5`](https://github.com/python-zeroconf/python-zeroconf/commit/8a110f58b02825100f5bdb56c119495ae42ae54c))

* Remove unnecessary packet send in ServiceInfo.request()

When performing an info query via request(), a listener is started, and
a packet is formed. As the packet is formed, known answers are taken
from the cache and placed into the packet.  Then the packet is sent.
The packet is self received (via multicast loopback, I assume).  At that
point the listener is fired and the answers in the packet are propagated
back to the object that started the request.  This is a really long way
around the barn.

The PR queries the cache directly in request() and then calls
update_record().  If all of the information is in the cache, then no
packet is formed or sent or received.  This approach was taken because,
for whatever reason, the reception of the packets on windows via the
loopback was proving to be unreliable.  The method has the side benefit
of being a whole lot faster.

This PR also incorporates the joins() from PR #30.  In addition it moves
the two joins() in close() to their own thread because they can take
quite a while to execute. ([`c49145c`](https://github.com/python-zeroconf/python-zeroconf/commit/c49145c35de09b2631d8a2b4751d787a6b4dc904))

* Fix ability for a cache lookup to match properly

When querying for a service type, the response is processed.  During the
processing, an info lookup is performed.  If the info is not found in
the cache, then a query is sent.  Trouble is that the info requested is
present in the same packet that triggered the lookup, and a query is not
necessary.  But two problems caused the cache lookup to fail.

1) The info was not yet in the cache.  The call back was fired before
all answers in the packet were cached.

2) The test for a cache hit did not work, because the cache hit test
uses a DNSEntry as the comparison object.  But some of the objects in
the cache are descendents of DNSEntry and have their own __eq__()
defined which accesses fields only present on the descendent.  Thus the
test can NEVER work since the descendent's __eq__() will be used.

Also continuing the theme of some other recent pull requests, add three
_GLOBAL_DONE tests to avoid doing work after the attempted stop, and
thus avoid generating (harmless, but annoying) exceptions during
shutdown ([`d8562fd`](https://github.com/python-zeroconf/python-zeroconf/commit/d8562fd3546d6cd27b1ba9e95105ea534649a43e))


## v0.17.5 (2016-03-14)

### Unknown

* Prepare release 0.17.5 ([`f33b8f9`](https://github.com/python-zeroconf/python-zeroconf/commit/f33b8f9c182245b14b9b73a86aefedcee4520eb5))

* resolve issue #38: size change during iteration ([`fd9d531`](https://github.com/python-zeroconf/python-zeroconf/commit/fd9d531f294e7fa5b9b934f192b061f56eaf1d37))

* Installation on system with ASCII encoding

The default open function in python2 made a best effort to open text files of any encoding.
After 3.0 the encoding has to be set correctly and it defaults to the user preferences. ([`6007537`](https://github.com/python-zeroconf/python-zeroconf/commit/60075379d57664f94fa41a96dea7c7c64489ef3d))

* Revert "Switch from netifaces to psutil"

psutil doesn't seem to work on pypy3:

    Traceback (most recent call last):
      File "/home/travis/virtualenv/pypy3-2.4.0/site-packages/nose/failure.py", line 39, in runTest
        raise self.exc_val.with_traceback(self.tb)
      File "/home/travis/virtualenv/pypy3-2.4.0/site-packages/nose/loader.py", line 414, in loadTestsFromName
        addr.filename, addr.module)
      File "/home/travis/virtualenv/pypy3-2.4.0/site-packages/nose/importer.py", line 47, in importFromPath
        return self.importFromDir(dir_path, fqname)
      File "/home/travis/virtualenv/pypy3-2.4.0/site-packages/nose/importer.py", line 94, in importFromDir
        mod = load_module(part_fqname, fh, filename, desc)
      File "/home/travis/build/jstasiak/python-zeroconf/test_zeroconf.py", line 17, in <module>
        import zeroconf as r
      File "/home/travis/build/jstasiak/python-zeroconf/zeroconf.py", line 35, in <module>
        import psutil
      File "/home/travis/virtualenv/pypy3-2.4.0/site-packages/psutil/__init__.py", line 62, in <module>
        from . import _pslinux as _psplatform
      File "/home/travis/virtualenv/pypy3-2.4.0/site-packages/psutil/_pslinux.py", line 23, in <module>
        from . import _psutil_linux as cext
    ImportError: unable to load extension module
        '/home/travis/virtualenv/pypy3-2.4.0/site-packages/psutil/_psutil_linux.pypy3-24.so':
        /home/travis/virtualenv/pypy3-2.4.0/site-packages/psutil/_psutil_linux.pypy3-24.so: undefined symbol: PyModule_GetState

Additionally netifaces turns out to be possible to install on Python 3,
therefore making it necessary to investigate the original issue.

This reverts commit dd907f2eed3768a3c1e3889af84b5dbeb700a1e7. ([`6349d19`](https://github.com/python-zeroconf/python-zeroconf/commit/6349d197b442209331a0ff8676541967f7142991))

* fix issue #23 race-condition on ServiceBrowser startup ([`30bd44f`](https://github.com/python-zeroconf/python-zeroconf/commit/30bd44f04f94a9b26622a7213dd9950ae57df21c))

* Switch from netifaces to psutil

netifaces installation on Python 3.x is broken and there doesn't seem to
be any plan to release a working version on PyPI, instead of using its
fork I decided to use another package providing the required
information.

This closes https://github.com/jstasiak/python-zeroconf/issues/31

[1] https://bitbucket.org/al45tair/netifaces/issues/13/0104-install-is-broken-on-python-3x ([`dd907f2`](https://github.com/python-zeroconf/python-zeroconf/commit/dd907f2eed3768a3c1e3889af84b5dbeb700a1e7))

* Fix multicast TTL and LOOP options on OpenBSD

IP_MULTICAST_TTL and IP_MULTICAST_LOOP socket options on OpenBSD don't
accept int, only unsigned char. Otherwise you will get an error:
[Errno 22] Invalid argument. ([`0f46a06`](https://github.com/python-zeroconf/python-zeroconf/commit/0f46a0609931e6dc299c0473312e434e84abe7b0))


## v0.17.4 (2015-09-22)

### Unknown

* Prepare release 0.17.4 ([`0b9093d`](https://github.com/python-zeroconf/python-zeroconf/commit/0b9093de863928d7f13092aaf2be1f0a33f4ead2))

* Support kernel versions <3.9

added catch of OSError
added catch of socket.error for python2 ([`023426e`](https://github.com/python-zeroconf/python-zeroconf/commit/023426e0f8982640f46bca3dfcd3abeee2cb832f))

* Make it explicit who says what in the readme ([`ddb1048`](https://github.com/python-zeroconf/python-zeroconf/commit/ddb10485ef17aec3f37ef70dcb37af167271bfe1))


## v0.17.3 (2015-08-19)

### Unknown

* Make the package's status explicit ([`f29c0f4`](https://github.com/python-zeroconf/python-zeroconf/commit/f29c0f475be76f70ecbb1586deb4618180dd1969))

* Prepare release 0.17.3 ([`9c3a81a`](https://github.com/python-zeroconf/python-zeroconf/commit/9c3a81af84c3450459795e5fc5142300f9680804))

* Add a DNSText __repr__ test

The test helps making sure the situation fixed by
e8299c0527c965f83c1326b18e484652a9eb829c doesn't happen again. ([`c7567d6`](https://github.com/python-zeroconf/python-zeroconf/commit/c7567d6b065d7460e2022b8cde5dd0b52a3828a7))

* Fix DNSText repr Python 3 issue

Prevents following exception:
```
  File "/Users/paulus/dev/python/netdisco/lib/python3.4/site-packages/zeroconf.py", line 412, in __repr__
    return self.to_string(self.text[:7] + "...")
TypeError: can't concat bytes to str
``` ([`e8299c0`](https://github.com/python-zeroconf/python-zeroconf/commit/e8299c0527c965f83c1326b18e484652a9eb829c))


## v0.17.2 (2015-07-12)

### Unknown

* Release version 0.17.2 ([`d1ee5ce`](https://github.com/python-zeroconf/python-zeroconf/commit/d1ee5ce7558060ea8d92f804172f67f960f814bb))

* Fix a typo, meant strictly lesser than 0.6 :< ([`dadbbfc`](https://github.com/python-zeroconf/python-zeroconf/commit/dadbbfc9e1787561981807d3e008433a107c1e5e))

* Restrict flake8-import-order version

There seems to be a bug in 0.6.x, see
https://github.com/public/flake8-import-order/issues/42 ([`4435a2a`](https://github.com/python-zeroconf/python-zeroconf/commit/4435a2a4ae1c0b0877785f1a5047f65bb80a14bd))

* Use enum-compat instead of enum34 directly

This is in order for the package's installation to work on Python 3.4+,
solves the same issue as
https://github.com/jstasiak/python-zeroconf/pull/22. ([`ba89455`](https://github.com/python-zeroconf/python-zeroconf/commit/ba894559f43fa6955989b92533c06fd8e8b92c74))


## v0.17.1 (2015-04-10)

### Unknown

* Restrict pep8 version as something depends on it ([`4dbd04b`](https://github.com/python-zeroconf/python-zeroconf/commit/4dbd04b807813384108ff8e4cb5291c2560eed6b))

* Bump version to 0.17.1 ([`0b8936b`](https://github.com/python-zeroconf/python-zeroconf/commit/0b8936b94011c0783c7d0469b9ebae76cd4d1976))

* Fix some typos in the readme ([`7c64ebf`](https://github.com/python-zeroconf/python-zeroconf/commit/7c64ebf6129fb6c0c533a1fed618c9d5926d5100))

* Update README.rst ([`44fa62a`](https://github.com/python-zeroconf/python-zeroconf/commit/44fa62a738335781ecdd789ad636f82e6542ecd2))

* Update README.rst ([`a22484a`](https://github.com/python-zeroconf/python-zeroconf/commit/a22484af90c7c4cbdee849d2b75efab2772c3592))

* Getting an EADDRNOTAVAIL error when adding an address to the multicast group on windows. ([`93d34f9`](https://github.com/python-zeroconf/python-zeroconf/commit/93d34f925cd8913ff6836f9393cdce15679e4794))


## v0.17.0 (2015-04-10)

### Unknown

* Do 0.17.0 release ([`a6d75b3`](https://github.com/python-zeroconf/python-zeroconf/commit/a6d75b3d63a0c13c63473910b832e6db12635e79))

* Advertise pypy3 support ([`4783611`](https://github.com/python-zeroconf/python-zeroconf/commit/4783611de72ac11bdbfea9e4324e58746a91e70a))

* Handle recent flake8 change ([`0009b5e`](https://github.com/python-zeroconf/python-zeroconf/commit/0009b5ea2bca77f395eb2bacc69d0dcfa5dd37dc))

* Describe recent changes ([`5c32a27`](https://github.com/python-zeroconf/python-zeroconf/commit/5c32a27a6ae0cccf7af25961cd98560a5173b065))

* Add pypy3 build ([`a298785`](https://github.com/python-zeroconf/python-zeroconf/commit/a298785cf63d26b184495f972c619d31515a1468))

* Restore old listener interface (and example) for now ([`c748294`](https://github.com/python-zeroconf/python-zeroconf/commit/c748294fdc6f3bf527f62d4c0cb76ace32890128))

* Fix test breakage ([`b5fb3e8`](https://github.com/python-zeroconf/python-zeroconf/commit/b5fb3e86a688f6161c1292ccdffeec9f455c1fbd))

* Prepare for new release ([`275a22b`](https://github.com/python-zeroconf/python-zeroconf/commit/275a22b997331d499526293b98faff11ca6edea5))

* Move self test example out of main module ([`ac5a63e`](https://github.com/python-zeroconf/python-zeroconf/commit/ac5a63ece96fbf9d64e41e7a4867cc1d8b2f6b96))

* Fix using binary strings as property values

Previously it'd fall trough and set the value to False ([`b443027`](https://github.com/python-zeroconf/python-zeroconf/commit/b4430274ba8355ceaadc2d89a84752f1ac1485e7))

* Reformat a bit ([`2190818`](https://github.com/python-zeroconf/python-zeroconf/commit/219081860d28e49b1ae71a78e1a0da459689ab9c))

* Make examples' output quiet by default ([`08e0dc2`](https://github.com/python-zeroconf/python-zeroconf/commit/08e0dc2c7c1551ffa9a1e7297112b0f46b7ccc4e))

* Change ServiceBrowser interface experimentally ([`d162e54`](https://github.com/python-zeroconf/python-zeroconf/commit/d162e54c6aad175505028aa7beb8a1a0cb7a231d))

* Handle exceptions better ([`7cad7a4`](https://github.com/python-zeroconf/python-zeroconf/commit/7cad7a43179e3f547796b125e3ed8169ef3f4157))

* Add some debug logging ([`451c072`](https://github.com/python-zeroconf/python-zeroconf/commit/451c0729e2490ac6283010ddcbbcc723d86e6765))

* Make the code nicer

This includes:

* rearranging code to make it more readable
* catching KeyError instead of all exceptions and making it obvious what
  can possibly raise there
* renaming things ([`df88670`](https://github.com/python-zeroconf/python-zeroconf/commit/df88670963e8c3a1f11a6af026b484ff4343d271))

* Remove redundant parentheses ([`3775c47`](https://github.com/python-zeroconf/python-zeroconf/commit/3775c47d8cf3c941603fa393265b86d05f61b915))

* Make examples nicer and make them show all logs ([`193ee64`](https://github.com/python-zeroconf/python-zeroconf/commit/193ee64d6212ff9a814b76b13f9ef46676025dc3))

* Remove duplicates from all interfaces list

It has been mentioned in GH #12 that the list of all machine's network
interfaces can contain duplicates; it shouldn't break anything but
there's no need to open multiple sockets in such case. ([`af5e363`](https://github.com/python-zeroconf/python-zeroconf/commit/af5e363e7fcb392081dc98915defd93c5002c3fc))

* Don't fail when the netmask is unknown ([`463428f`](https://github.com/python-zeroconf/python-zeroconf/commit/463428ff8550a4f0e12b60e6f6a35efedca31271))

* Skip host only network interfaces

On Ubuntu Linux treating such interface (network mask 255.255.255.255)
would result in:

* EADDRINUSE "Address already in use" when trying to add multicast group
  membership using IP_ADD_MEMBERSHIP
* success when setting the interface as outgoing multicast interface
  using IP_MULTICAST_IF
* EINVAL "Invalid argument" when trying to send multicast datagram using
  socket with that interface set as the multicast outgoing interface ([`b5e9e94`](https://github.com/python-zeroconf/python-zeroconf/commit/b5e9e944e6f3c990862b3b03831bb988579ed340))

* Configure logging during the tests ([`0208228`](https://github.com/python-zeroconf/python-zeroconf/commit/0208228d8c760f3672954f5434c2ea54d7fd4196))

* Use all network interfaces by default ([`193cf47`](https://github.com/python-zeroconf/python-zeroconf/commit/193cf47a1144afc9158f0075a886c1f754d96f18))

* Ignore EADDRINUSE when appropriate

On some systems it's necessary to do so ([`0f7c64f`](https://github.com/python-zeroconf/python-zeroconf/commit/0f7c64f8cdacae34c227edd5da4f445ece12da89))

* Export Error and InterfaceChoice ([`500a76b`](https://github.com/python-zeroconf/python-zeroconf/commit/500a76bb1332fe34b45e681c767baddfbece4916))

* Fix ServiceInfo repr and text on Python 3

Closes #1 ([`f3fd4cd`](https://github.com/python-zeroconf/python-zeroconf/commit/f3fd4cd69e9707221d8bd5ee6b3bb86b0985f604))

* Add preliminary support for mulitple net interfaces ([`442a599`](https://github.com/python-zeroconf/python-zeroconf/commit/442a59967f7b0f2d5c2ef512874ad2ab13dedae4))

* Rationalize error handling when sending data ([`a0ee3d6`](https://github.com/python-zeroconf/python-zeroconf/commit/a0ee3d62db7b5350a21091e37824e187ebf99348))

* Make Zeroconf.socket private ([`78449ef`](https://github.com/python-zeroconf/python-zeroconf/commit/78449ef1e07dc68b63bb68038cb66f22e083fdfe))

* Refactor Condition usage to use context manager interface ([`8d32fa4`](https://github.com/python-zeroconf/python-zeroconf/commit/8d32fa4b12e1b52d72a7ba9588437c4c787e0ffd))

* Use six for Python 2/3 compatibility ([`f0c3979`](https://github.com/python-zeroconf/python-zeroconf/commit/f0c39797869175cf88d76c75d39835abb2052f88))

* Use six for Python 2/3 compatibility ([`54ed4b7`](https://github.com/python-zeroconf/python-zeroconf/commit/54ed4b79bb8de9523b5a5b74a79b01c8aa2291a7))

* Refactor version detection in the setup script

This doesn't depend on zeroconf module being importable when setup is
ran ([`1c2205d`](https://github.com/python-zeroconf/python-zeroconf/commit/1c2205d5c9b364a825d51acd03add4de91cb645a))

* Drop "zero dependencies" feature ([`d8c1ec8`](https://github.com/python-zeroconf/python-zeroconf/commit/d8c1ec8ee13191e8ec4412770994f0676ace442c))

* Stop dropping multicast group membership

It'll be taken care of by socket being closed ([`f6425d1`](https://github.com/python-zeroconf/python-zeroconf/commit/f6425d1d727edfa124264bcabeffd77397809965))

* Remove dead code ([`88f5a51`](https://github.com/python-zeroconf/python-zeroconf/commit/88f5a5193ba2ab0eefc99481ccc6a1b911d8dbea))

* Stop using Zeroconf.group attribute ([`903cb78`](https://github.com/python-zeroconf/python-zeroconf/commit/903cb78d3ff7bc8762bf23910562b8f5042c2f85))

* Remove some unused methods ([`80e8e10`](https://github.com/python-zeroconf/python-zeroconf/commit/80e8e1008bc28c8ab9ca966b89109146112d0edd))

* Refactor exception handling here ([`4b8f68b`](https://github.com/python-zeroconf/python-zeroconf/commit/4b8f68b39230bb9cc3c202395b58cc822b8fe862))

* Update README.rst ([`8f18609`](https://github.com/python-zeroconf/python-zeroconf/commit/8f1860956ee9c86b7ba095fc1293919933e1c0ad))

* Release as 0.16.0 ([`4e54b67`](https://github.com/python-zeroconf/python-zeroconf/commit/4e54b6738a490dcc7d2f9e7e1040c5da53727155))

* Tune logging ([`05c3c02`](https://github.com/python-zeroconf/python-zeroconf/commit/05c3c02044d2b4bff946e00803d0ddb2619f0927))

* Migrate from clazz to class_ ([`4a67e12`](https://github.com/python-zeroconf/python-zeroconf/commit/4a67e124cd8f8c4d19f8c6c4a455d075bb948362))

* Migrate more camel case names to snake case ([`92e4713`](https://github.com/python-zeroconf/python-zeroconf/commit/92e47132dc761a9a722caec261ae53de1785838f))

* Switch to snake case and clean up import order

Closes #2 ([`5429748`](https://github.com/python-zeroconf/python-zeroconf/commit/5429748190950a5daf7e9cf91de824dfbd06ee7a))

* Rationalize exception handling a bit and setup logging ([`ada563c`](https://github.com/python-zeroconf/python-zeroconf/commit/ada563c5a1f6d7c54f2ae5c495503079c395438f))

* Update README.rst ([`47ff62b`](https://github.com/python-zeroconf/python-zeroconf/commit/47ff62bae1fd69ffd953c82bd480e4770bfee97b))

* Update README.rst ([`b290965`](https://github.com/python-zeroconf/python-zeroconf/commit/b290965ecd589ca4feb1f88a4232d1ec2725dc44))

* Create universal wheels ([`bf97c14`](https://github.com/python-zeroconf/python-zeroconf/commit/bf97c1459a9d91d6aa88d7bf34c5f8b4cd3cedc5))


## v0.15.1 (2014-07-10)

### Unknown

* Bump version to 0.15.1 ([`9e81863`](https://github.com/python-zeroconf/python-zeroconf/commit/9e81863de37e2ab972d5a76a1dc2d5c517f83cc6))

* Update README.rst ([`161743e`](https://github.com/python-zeroconf/python-zeroconf/commit/161743ea387c961d3554488239f93df4b39be18c))

* Add coverage badge to the readme ([`8502a7e`](https://github.com/python-zeroconf/python-zeroconf/commit/8502a7e1c9770a42e44b4f1beb34c887212e7d48))

* Send coverage to coveralls ([`1d90a9f`](https://github.com/python-zeroconf/python-zeroconf/commit/1d90a9f91f87753a1ea649ce5da1bc6a7da4013d))

* Fix socket.error handling

This closes #4 ([`475e80b`](https://github.com/python-zeroconf/python-zeroconf/commit/475e80b90e96364a183c63f09fa3858f34aa3646))

* Add test_coverage make target ([`89531e6`](https://github.com/python-zeroconf/python-zeroconf/commit/89531e641f15b24a60f9fb2e9f71a7aa8450363a))

* Add PyPI version badge to the readme ([`4c852d4`](https://github.com/python-zeroconf/python-zeroconf/commit/4c852d424d07925ae01c24a51ffc36ecae49b48d))

* Refactor integration test to use events ([`922eab0`](https://github.com/python-zeroconf/python-zeroconf/commit/922eab05596b72d141d459e83146a4cdb6c84389))

* Fix readme formatting ([`7b23734`](https://github.com/python-zeroconf/python-zeroconf/commit/7b23734356f85ccaa6ca66ffaeea8484a2d45d3d))

* Update README.rst ([`83fd618`](https://github.com/python-zeroconf/python-zeroconf/commit/83fd618328aff29892c71f9ba5b9ff983fe4a202))

* Refactor browser example ([`8328aed`](https://github.com/python-zeroconf/python-zeroconf/commit/8328aed1444781b6fac854eb722ae0fef14a3cc4))

* Update README.rst ([`49af263`](https://github.com/python-zeroconf/python-zeroconf/commit/49af26350390484bc6f4b66dab4f6b004040cd4a))

* Bump version to 0.15 ([`77bcadd`](https://github.com/python-zeroconf/python-zeroconf/commit/77bcaddbd1964fb0b494e98ec3ae6d66ea42c509))

* Add myself to authors ([`b9f886b`](https://github.com/python-zeroconf/python-zeroconf/commit/b9f886bf2815c86c7004e123146293c48ea68f1e))

* Reuse one Zeroconf instance in browser example ([`1ee00b3`](https://github.com/python-zeroconf/python-zeroconf/commit/1ee00b318eab386b709351ffae81c8293f4e6d4d))

* Update README.rst ([`fba4215`](https://github.com/python-zeroconf/python-zeroconf/commit/fba4215be1804a13e454e609ed6df2cf98e149f2))

* Update README.rst ([`c7bfe63`](https://github.com/python-zeroconf/python-zeroconf/commit/c7bfe63f9a7eff9a1ede0ac63a329a316d3192ab))

* Rename examples ([`3502198`](https://github.com/python-zeroconf/python-zeroconf/commit/3502198768062b49564121b48a792ce5e7b7b288))

* Refactor examples ([`2ce95f5`](https://github.com/python-zeroconf/python-zeroconf/commit/2ce95f52e7a02c7f1113ba7ebee3c89babb9a26e))

* Update README.rst ([`6a7cd31`](https://github.com/python-zeroconf/python-zeroconf/commit/6a7cd3197ee6ae5690b29b6543fc86d1b1a420d8))

* Advertise Python 3 support ([`d330918`](https://github.com/python-zeroconf/python-zeroconf/commit/d330918970d719d6b26a3f81e83dbb8b8adac0a4))

* Update README.rst ([`6aae20e`](https://github.com/python-zeroconf/python-zeroconf/commit/6aae20e1c1bef8413573139d62d3d2b889fe8776))

* Move examples to examples directory ([`c83891c`](https://github.com/python-zeroconf/python-zeroconf/commit/c83891c9dd2f20e8dee44f1b412a536d20cbcbe3))

* Fix regression introduced with Python 3 compat ([`0a0f7e0`](https://github.com/python-zeroconf/python-zeroconf/commit/0a0f7e0e72d7f9ed08231d94b66ff44bcff60151))

* Mark threads as daemonic (at least for now) ([`b8cfc79`](https://github.com/python-zeroconf/python-zeroconf/commit/b8cfc7996941afded5c9c7e7903378279590b20f))

* Update README.rst ([`cd7ca98`](https://github.com/python-zeroconf/python-zeroconf/commit/cd7ca98010044eb965bc988c23a8be59e09eb69a))

* Add Python 3 support ([`9a99aa7`](https://github.com/python-zeroconf/python-zeroconf/commit/9a99aa727f4e041a726aed3736c0a8ab625c4cb6))

* Update README.rst ([`09a1f4f`](https://github.com/python-zeroconf/python-zeroconf/commit/09a1f4f9d76f64cc8c85f0525e05bdac53de210c))

* Update README.rst ([`6feec34`](https://github.com/python-zeroconf/python-zeroconf/commit/6feec3459d2561f00402d627ea91a8a4981ad309))

* Tune package description ([`b819174`](https://github.com/python-zeroconf/python-zeroconf/commit/b8191741d4ef8e347f6dd138fa48da5aec9b6549))

* Gitignore build/ ([`0ef1b0d`](https://github.com/python-zeroconf/python-zeroconf/commit/0ef1b0d3481b68a752efe822ff4e9ce8356bcffa))

* Add setup.py ([`916bd38`](https://github.com/python-zeroconf/python-zeroconf/commit/916bd38ddb48a959c597ae1763193b4c2c74334f))

* Update README.rst ([`35eced3`](https://github.com/python-zeroconf/python-zeroconf/commit/35eced310fbe1782fd87eb33e7f4befcb0a78499))

* Run actual tests on Travis ([`f8cea82`](https://github.com/python-zeroconf/python-zeroconf/commit/f8cea82177cea3577d2b4f70fec32e85229abdce))

* Advertise Python 2.6 and PyPy support ([`43b182c`](https://github.com/python-zeroconf/python-zeroconf/commit/43b182cce40bcb21eb1e052a0bc42bf367a963ca))

* Move readme to README.rst ([`fd3401e`](https://github.com/python-zeroconf/python-zeroconf/commit/fd3401efb55ae91324d12ba80affd2f3b3ebcf5e))

* Move readme to README.rst ([`353b700`](https://github.com/python-zeroconf/python-zeroconf/commit/353b700df79b49c49db62e0a6e6eb0eae3ccb444))

* Stop catching BaseExceptions ([`41a013c`](https://github.com/python-zeroconf/python-zeroconf/commit/41a013c8a051b3f80018f37d4f254263cc890a68))

* Set up Travis build ([`a2a6125`](https://github.com/python-zeroconf/python-zeroconf/commit/a2a6125dd03d9a810dac72163d545e413387217b))

* PEP8ize and clean up ([`e2964ed`](https://github.com/python-zeroconf/python-zeroconf/commit/e2964ed48263e72159e95cb0691af0dcb9ba498b))

* Updated for 0.14. ([`83aa0f3`](https://github.com/python-zeroconf/python-zeroconf/commit/83aa0f3803cdf79470f4a754c7b9ab616544eea1))

* Although SOL_IP is considered more correct here, it's undefined on some
systems, where IPPROTO_IP is available. (Both equate to 0.) Reported by
Mike Erdely. ([`443aca8`](https://github.com/python-zeroconf/python-zeroconf/commit/443aca867d694432d466d20bdf7c49ebc7a4e684))

* Obsolete comment. ([`eee7196`](https://github.com/python-zeroconf/python-zeroconf/commit/eee7196626773eae2dc0dc1a68de03a99d778139))

* Really these should be network order. ([`5e10a20`](https://github.com/python-zeroconf/python-zeroconf/commit/5e10a20a9cb6bbc09356cbf957f3f7fa3e169ff2))

* Docstrings for examples; shorter timeout; struct.unpack() vs. ord(). ([`0884d6a`](https://github.com/python-zeroconf/python-zeroconf/commit/0884d6a56afc6fb559b6c90a923762393187e50a))

* Make examples executable. ([`5e5e78e`](https://github.com/python-zeroconf/python-zeroconf/commit/5e5e78e27240e7e03d1c8aa96ee0e1f7877d0d5d))

* Unneeded. ([`2ac738f`](https://github.com/python-zeroconf/python-zeroconf/commit/2ac738f84bbcf29d03bad289cb243182ecdf48d6))

* getText() is redundant with getProperties(). ([`a115187`](https://github.com/python-zeroconf/python-zeroconf/commit/a11518726321b15059be255b6329cba591887197))

* Allow graceful exit from announcement test. ([`0f3b413`](https://github.com/python-zeroconf/python-zeroconf/commit/0f3b413b269f8b95b6f8073ba39d11f156ae632c))

* More readable display in browser; automatically quit after giving ten
seconds to respond. ([`eee4530`](https://github.com/python-zeroconf/python-zeroconf/commit/eee4530d7b8216338634282f3097cb96932aa28e))

* New names, numbers. ([`2a000c5`](https://github.com/python-zeroconf/python-zeroconf/commit/2a000c589302147129eed990c842b38ac61f7514))

* Updated FSF address. ([`4e39602`](https://github.com/python-zeroconf/python-zeroconf/commit/4e396025ed666775973d54a50b69e8f635e28658))

* De-DOSification. ([`1dc3436`](https://github.com/python-zeroconf/python-zeroconf/commit/1dc3436e6357b66d0bb53f9b285f123b164984da))

* Lowercase imports. ([`e292868`](https://github.com/python-zeroconf/python-zeroconf/commit/e292868f9c7e817cb04dfce2d545f45db4041e5e))

* The great lowercasing. ([`5541813`](https://github.com/python-zeroconf/python-zeroconf/commit/5541813fbb8e1d7b233d09ee2d20ac0ca322a9f2))

* Renamed tests. ([`4bb88b0`](https://github.com/python-zeroconf/python-zeroconf/commit/4bb88b0952833b84c15c85190c0a9cac01922cbe))

* Replaced unwrapped "lgpl.txt" with traditional "COPYING". ([`ad6b1ec`](https://github.com/python-zeroconf/python-zeroconf/commit/ad6b1ecf9fa71a5ec14f7a08fc3d6a689a19e6d2))

* Don't need range() here. ([`b36e7d5`](https://github.com/python-zeroconf/python-zeroconf/commit/b36e7d5dd5922b1739911878b29aba921ec9ecb6))

* testNumbersAnswers() was identical to testNumbersQuestions().
(Presumably it was intended to test addAnswer() instead...) ([`416054d`](https://github.com/python-zeroconf/python-zeroconf/commit/416054d407013af8678928b949d6579df4044d46))

* Extraneous spaces. ([`f6615a9`](https://github.com/python-zeroconf/python-zeroconf/commit/f6615a9d7632f3510d2f0a36cab155ac753141ab))

* Moved history to README; updated version number, etc. ([`015bae2`](https://github.com/python-zeroconf/python-zeroconf/commit/015bae258b5ce73a2a12361e4c9295107126963c))

* Meaningless. ([`6147a6e`](https://github.com/python-zeroconf/python-zeroconf/commit/6147a6ed20222851ba4438dd65366f907b4c189f))

* Also unexceptional. ([`c36e3af`](https://github.com/python-zeroconf/python-zeroconf/commit/c36e3af2f6e0ea857f383f9b014f50b65fca641c))

* If name isn't in self.names, it's unexceptional. (And yes, I actually
tested, and this is faster.) ([`f772d4e`](https://github.com/python-zeroconf/python-zeroconf/commit/f772d4e5e208431378bf01d75eddc7df5119dff7))

* Excess spaces; don't use "len" as a label. After eblot. ([`df986ee`](https://github.com/python-zeroconf/python-zeroconf/commit/df986eed46e3ec7dadc6604d0b26e4fcf0b6291a))

* Outdated docs. ([`21d7c95`](https://github.com/python-zeroconf/python-zeroconf/commit/21d7c950f50827bc8ac6dd18fb0577c11b5cefac))

* Untab the test programs. ([`c13e4fa`](https://github.com/python-zeroconf/python-zeroconf/commit/c13e4fab3b0b95674fbc93cd2ac30fd2ba462a24))

* Remove the comment about the test programs. ([`8adab79`](https://github.com/python-zeroconf/python-zeroconf/commit/8adab79a64a73e76841b37e53e55fe8aad8eb580))

* Allow for the failure of getServiceInfo(). Not sure why it's happening,
though. ([`0a05f42`](https://github.com/python-zeroconf/python-zeroconf/commit/0a05f423ad591454a25c515d811556d10e5fc99f))

* Don't test for NonLocalNameException, since I killed it. ([`d89ddfc`](https://github.com/python-zeroconf/python-zeroconf/commit/d89ddfcecc7b336aa59a4ff784cb8b810772d24f))

* Describe this fork. ([`656f959`](https://github.com/python-zeroconf/python-zeroconf/commit/656f959c26310629953cc661ffad681194295131))

* Write only a byte. ([`d346107`](https://github.com/python-zeroconf/python-zeroconf/commit/d34610768812906ff07974c1314f6073b431d96e))

* Although beacons _should_ fit within single packets, maybe we should allow for the possibility that they won't? (Or, does this even make sense with sendto()?) ([`ac91642`](https://github.com/python-zeroconf/python-zeroconf/commit/ac91642b0ea90a3c84b605e19d562b897e2cd1fd))

* Update the version to indicate a fork. ([`a81f3ab`](https://github.com/python-zeroconf/python-zeroconf/commit/a81f3ababc585acca4bacc51a832703286ec5cfb))

* HHHHHH -> 6H ([`9a94953`](https://github.com/python-zeroconf/python-zeroconf/commit/9a949532484a55e52f1d2f14eb27277a5133ce29))

* In Zeroconf, use the same method of determining the default IP as elsewhere, instead of the unreliable gethostbyname(gethostname()) method (but fall back to that). ([`f6d4731`](https://github.com/python-zeroconf/python-zeroconf/commit/f6d47316a47d9d04539f1a4215dd7eec06c33d4c))

* More again. ([`2420505`](https://github.com/python-zeroconf/python-zeroconf/commit/24205054309e110238fc5a986cdc27b17c44abef))

* More. ([`b8baed3`](https://github.com/python-zeroconf/python-zeroconf/commit/b8baed3a2876c126cac65a7d95bb88661b31483c))

* Minor style things for Zeroconf (use True/False instead of 1/0, etc.). ([`173350e`](https://github.com/python-zeroconf/python-zeroconf/commit/173350e415e66c9629d553f820677453bdbe5724))

* Clearer. ([`3e718b5`](https://github.com/python-zeroconf/python-zeroconf/commit/3e718b55becd883324bf40eda700431b302a0da8))

* 80-column fixes for Zeroconf. ([`e5d930b`](https://github.com/python-zeroconf/python-zeroconf/commit/e5d930bb681f5544827fc0c9f37daa778dec5930))

* Minor simplification of the pack/unpack routines in Zeroconf. ([`e814dd1`](https://github.com/python-zeroconf/python-zeroconf/commit/e814dd1e6848d8c7ec03660d347ea4a34390c37d))

* Skip unknown resource records in Zeroconf -- https://bugs.launchpad.net/pyzeroconf/+bug/498411 ([`488de88`](https://github.com/python-zeroconf/python-zeroconf/commit/488de8826ddd58646358900d057a4a1632492948))

* Some people are reporting bogus data coming back from Zeroconf scans, causing exceptions. ([`fe77e37`](https://github.com/python-zeroconf/python-zeroconf/commit/fe77e371cc68ea211508908e6180867c420ca042))

* Don't need the string module here. ([`f76529c`](https://github.com/python-zeroconf/python-zeroconf/commit/f76529c685868dcdb62b6477f15ecb1122310cc5))

* Suppress EBADF errors in Zeroconf.py. ([`4c8aac9`](https://github.com/python-zeroconf/python-zeroconf/commit/4c8aac95613df62d001bd7192ec75247a2bb9b9d))

* This doesn't seem to be necessary, and it's generating a lot of exceptions... ([`f80df7b`](https://github.com/python-zeroconf/python-zeroconf/commit/f80df7b0f8b9124970e109c51f7a49b7bd75906c))

* Untab Zeroconf. ([`892a4f0`](https://github.com/python-zeroconf/python-zeroconf/commit/892a4f095c23379a6cf5a0ef31521f9f90cb5276))

* has_key() is deprecated. ([`f998e39`](https://github.com/python-zeroconf/python-zeroconf/commit/f998e39cbb8d2c5556c10203957ff6a9ab2f546d))

* The initial version I committed to HME for Python back in 2008. This is
a step back in some respects (re-inserting tabs that will be undone a
couple patches hence), so that I can apply the patches going forward. ([`d952a9c`](https://github.com/python-zeroconf/python-zeroconf/commit/d952a9c117ae539cf4778d76618fe813b10a9a34))

* Remove the executable bit. ([`f0d095d`](https://github.com/python-zeroconf/python-zeroconf/commit/f0d095d0f1c2767be6da47f885f5ed019e9fa363))

* Removed pyc file ([`38d0a18`](https://github.com/python-zeroconf/python-zeroconf/commit/38d0a184c13772dae3c14d3c46a30c68497c54db))

* First commit ([`c3a39f8`](https://github.com/python-zeroconf/python-zeroconf/commit/c3a39f874a5c10e91ee2315271f13ae74ee381fd))
