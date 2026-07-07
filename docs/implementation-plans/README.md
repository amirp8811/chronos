# Advanced CHRONOS implementation plans

This directory contains focused plans for the remaining high-difficulty implementation areas.

Plans:

1. [Production-grade PIR with formal privacy guarantees](production_pir_plan.md)
2. [Real kernel io_uring I/O](io_uring_plan.md)
3. [Real AF_XDP UMEM/ring I/O](af_xdp_plan.md)
4. [Privileged NIC RSS netlink/ethtool execution](nic_rss_netlink_plan.md)
5. [Fully tested browser WebTransport in real browsers](browser_webtransport_plan.md)
6. [Full iOS/Android apps](mobile_apps_plan.md)

Recommended order:

1. Browser WebTransport/WebSocket testing path, because it yields the fastest end-to-end user-visible client.
2. io_uring, because it is easier to validate than AF_XDP and improves relay I/O.
3. NIC RSS control, because it is narrower than AF_XDP but needs privileged/hardware testing.
4. AF_XDP, after protocol/data-plane abstractions are stable.
5. Mobile apps, once browser/client APIs stabilize.
6. Production PIR, in parallel with cryptographic review, because it has the highest correctness/privacy risk.

Each plan is written as a staged implementation path with validation gates. Do not treat a stage as complete unless its validation gates pass.
