import ./generic.nix {
  hash = "sha256-LYQ7PFYLjXGqztovhvfJ9XR7xpinPvMvKZgiqsAUvbc=";
  version = "7.0.2";
  vendorHash = "sha256-huplVEZrpV5jI2nXJcmtFeY5SPDBSYwoZ1EtvEUY5Q0=";
  patches = fetchpatch: [
    # incusd/instance/lxc: Reject line breaks in LXC config values
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e933b9f920e16af8932c30d4565e293675828dc1.patch";
      hash = "sha256-ytJM4vhmmVuMZvoYrjjXuJcXojmyxLiGEt1HKXG8MeY=";
      name = "GHSA-3wxw-5gh2-j2x2.1.patch";
    })
    # incusd/instance/lxc: Only parse config.json for OCI containers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/084e2d482010fa9b86d20c21312bdeffa8099d31.patch";
      hash = "sha256-IEmcercBGbTsj+7ws2ThDayBlEoH2Y5/f3nSi/QCILw=";
      name = "GHSA-3wxw-5gh2-j2x2.2.patch";
    })
    # incusd/instance/lxc: Keep loader variables out of the forklxc environment
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e00b75d4ac0393ab46eecd07a7c7abfb697c89f0.patch";
      hash = "sha256-iayuWDj891XOFgVazMblQULCsAPJW9NXh/QOWan6wxM=";
      name = "GHSA-3wxw-5gh2-j2x2.3.patch";
    })
    # incusd/dev_incus: Anchor the cgroup based monitor detection
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/83eaa5e19345a4719df46bcdb2850547d069b88e.patch";
      hash = "sha256-5bCdkiKjIMezelVBzWiMcxgs9TCRsmlhcDjQZwCQ4FA=";
      name = "GHSA-v736-5xp3-jghf.patch";
    })
    # incusd: Check resource creation against the effective project
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/929041ead77a385d7318e001403d36520fb75b93.patch";
      hash = "sha256-MuMCCQMiRBZQQfICAggYNvCk0bpvEMTSmg5WpbpWimk=";
      name = "GHSA-5c64-j5m6-8433.patch";
    })
    # incusd/auth/tls: Restrict inherited reads to the certificate's projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/131d0f6dcd755bd52957a1a1d25d7930c844420d.patch";
      hash = "sha256-IknnK/5YMQmrntjYWjAWacpxaZWWYVP4fMPAjTSqxwY=";
      name = "GHSA-8r3h-vc36-6xpx.patch";
    })
    # incusd/operations: Protect token operations from events and cancellation
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/150b8c512f6fc00034b3324406dbf6a4edb3dc52.patch";
      hash = "sha256-07+/mpq9GBLEOIomDVPVNPelAIr43LcS9xMX925jY9I=";
      name = "GHSA-cwg9-8mc4-hf7j.patch";
    })
    # incusd/storage/s3: Verify signed payloads without buffering
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2b589bc682c9e5c76a2947d9cad993035c503277.patch";
      hash = "sha256-tZz43cqb1vDmR3+KnFYrDvY8SMs5DVViRgH2hOWZy24=";
      name = "GHSA-8mgx-h4v8-xqv2.patch";
    })
    # incusd/storage: Validate dependent volumes received through migration
    (fetchpatch {
      url = "https://salsa.debian.org/go-team/packages/incus/-/raw/380a16d82b8688d45a6693a7cf42fafb9fbba606/debian/patches/104-GHSA-q9fc-p923-6vp7.patch";
      hash = "sha256-MPq38ZQtoVFvGYIsB5ZKdh0ZDsXepJpYQZaQiKDllTk=";
      name = "GHSA-q9fc-p923-6vp7.patch";
    })
    # incusd/storage: Validate snapshot names from the backup index on import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f7a97ee92b10e1b2bc3118453e9c0089d2dc17df.patch";
      hash = "sha256-HdjlSa9Y0Gajb4GBc15Wl31m2jxM7Hcm7EC57a9wxXk=";
      name = "GHSA-p45f-gqqj-6qq3.patch";
    })
    # incusd: Only trust the key-proven client certificate
    (fetchpatch {
      url = "https://salsa.debian.org/go-team/packages/incus/-/raw/380a16d82b8688d45a6693a7cf42fafb9fbba606/debian/patches/102a-cherry-pick-CheckTrustStateIssuer.patch";
      hash = "sha256-QLR6mW9gs3TegabKMZErprBhwvNWXsL7sXxYmWlWB2o=";
    })
    (fetchpatch {
      url = "https://salsa.debian.org/go-team/packages/incus/-/raw/380a16d82b8688d45a6693a7cf42fafb9fbba606/debian/patches/102b-GHSA-xg75-xf37-cph9.patch";
      hash = "sha256-DQdddXdXnS6U5sjz7zjC8jMwsxa3+Fc+Q5tFKH1QS6k=";
      name = "GHSA-xg75-xf37-cph9.patch";
    })
    # incusd/dev_incus: Pin image export to the instance's project
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/00bb61411e5df26a866288482363e3baf75da563.patch";
      hash = "sha256-hXup/fYYoxM+k5mkTVz0dCAhOAGenXk/FyA/99UGRRc=";
      name = "GHSA-f7xp-22ph-v444.patch";
    })
    # incusd/events: Restrict network-acl events to privileged viewers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/ed41dec85ffde702bad04270eb9ed844a64acf79.patch";
      hash = "sha256-BDXTIaQrRXkibyjd6ep88/MnPnj/DxMB2yA/faqJwbQ=";
      name = "GHSA-9f75-5fjw-5jvv.patch";
    })
    # incusd/instance/lxc: Allocate an idmap when none is set at start
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e23bcb8b7e1dd223140668a67907b3312c562f42.patch";
      hash = "sha256-tdBGAcolz6RgdStHU7rVpGqEsQKlUvIofUlObnOa+bg=";
      name = "GHSA-9c46-v3hw-v6m8.patch";
    })
    # incusd: Authorize effective project on resource creation
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c738b760352413c48c58bd1fbe7bd27ab41c84c1.patch";
      hash = "sha256-tfrSMkjuK+bRIrjPSEWPal4rSA8MZuCWk4Ky7weMYoA=";
      name = "GHSA-jcw9-v2ff-8m79.patch";
    })
    # incusd: Fix cross-project disclosure in recursive and all-projects listings
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9721b743bc89baebeb3e0a7a2a306c924256a8c7.patch";
      hash = "sha256-sKO8ibBLGL3hUg6uBZNDCt32gWPUdxc7ir/3XY4IQrk=";
      name = "GHSA-pf5w-m8m6-5265.patch";
    })
    # incusd/storage: Strip non-regular files from instance metadata
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/724ab0fee1a85b5f741fe58b3e432c5f6b4ef414.patch";
      hash = "sha256-IQTS1+txrJR/E97rgMOczMDjVA9IbHdZDN/Lp6eWM00=";
      name = "GHSA-5pgx-q9xx-j3qv.patch";
    })
    # incusd/instance/qemu: Confine NBD migration sockets to the run directory
    (fetchpatch {
      url = "https://salsa.debian.org/go-team/packages/incus/-/raw/380a16d82b8688d45a6693a7cf42fafb9fbba606/debian/patches/108a-cherry-pick-helpers.patch";
      hash = "sha256-iDVkR9aw2n9MVdqEuAGFaA8Rf9T4y0DVMmuSbOhpThI=";
    })
    (fetchpatch {
      url = "https://salsa.debian.org/go-team/packages/incus/-/raw/380a16d82b8688d45a6693a7cf42fafb9fbba606/debian/patches/108b-GHSA-3rgf-297m-775x.patch";
      hash = "sha256-2CL6Rcos94L1wMQKNobsA84eVJi67rFn8Xu14rfyYdI=";
      name = "GHSA-3rgf-297m-775x.patch";
    })
    # incusd: Reject null snapshot entries on backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/dcc80425594819ee1978110aa0071453308f6fa9.patch";
      hash = "sha256-xxcYsCB4yMfFvge1m6egLoE378fWm4lJ085fiafbM5c=";
      name = "GHSA-x6pw-mh5w-pq73.patch";
    })
    # incusd/operations: Keep websocket secrets out of events and queries
    (fetchpatch {
      url = "https://salsa.debian.org/go-team/packages/incus/-/raw/380a16d82b8688d45a6693a7cf42fafb9fbba606/debian/patches/110-GHSA-h2j8-4crh-vhfc.patch";
      hash = "sha256-/ob+k/eVhuXvSkkk/sErQhtLhLbMfvr102vquUAK/R0=";
      name = "GHSA-h2j8-4crh-vhfc.patch";
    })
    # incusd: Check certificate ownership on every non-admin update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9afe1c7f7beea641381c41d90c111b369fc8ea35.patch";
      hash = "sha256-OdTOluEv3Ia9mEYkF7URp5bgSfwlbq85BM93H+a18ME=";
      name = "GHSA-7643-2vqq-56p3.patch";
    })
    # incusd/auth/tls: Only inherit default project objects through a project using them
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6fa7b9f380af81d86effabdde97c261f101a24f3.patch";
      hash = "sha256-bZOB8Y15wuO5vintUJFIsLhO9nmCLvDycjZ6qUISCxc=";
      name = "GHSA-3c9p-936j-gv99.patch";
    })
    # incusd: Authorize dependent volumes on backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c9a51adde210c3abde7857c3b99881c4359fd505.patch";
      hash = "sha256-SHjRWAnWzHWrxwmI8wz/DARvtdQNEp5F+qbb7nA4gDw=";
      name = "GHSA-hm9p-jjr8-3jp8.patch";
    })
    # incusd/operations: Strip the state secret from renders too
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4269b6f210b8449cfa6d8e4620b678114f8753bd.patch";
      hash = "sha256-KYgSQtnPNba2CgwkejZjm5HmCbd3d+/diCBgMBEeOno=";
      name = "GHSA-j5qp-xv8h-whfp.patch";
    })
    # incusd/storage/s3: Bound aws-chunked chunk sizes
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/74d6d87b0fe31d49286dd26820f645c48eb5225c.patch";
      hash = "sha256-mso5a9geciRt3RDJ7yLTZSmJxXdIPEx0GX4sMIDcPuc=";
      name = "GHSA-537m-jhcr-hxmm.patch";
    })
    # incusd: Limit non-streaming bodies on large request endpoints
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/91ac578127234ba27bc2af043ed0d82138052334.patch";
      hash = "sha256-1cqexBKQ6cHTrfuivgxD0iAPuf/e3UjBfH4KXmpLiL4=";
      name = "GHSA-cxqx-x785-5926.patch";
    })
    # incusd: Forbid push mode migration in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7d2172f325256eaae34401d7f192e2155694b425.patch";
      hash = "sha256-vbFydx4Ez3aIzs0TGWWQyTpkMhA+g4gXpxiFOOvLW9Q=";
      name = "GHSA-chhj-pwx6-9cx3.1.patch";
    })
    # incusd/storage: Check project restrictions on instance volume config
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/35d913984479d2f4b4cc0f64ca6fd2032d777a09.patch";
      hash = "sha256-g8pNF/pFUNZTNcki16jwheRpf1eWwY8OCxq9VjeVNn0=";
      name = "GHSA-cm79-v2v8-5grh.patch";
    })
    # incusd/migration: Bound the size of protocol messages
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c726d64d563fd5b70c848a8aaa108d7b3c5d2070.patch";
      hash = "sha256-huH2pu9fZEXgro4G5DZZ0YNCcIOYJlWumTAZqSjXCMM=";
      name = "GHSA-r69q-f272-2qmr.patch";
    })
    # incusd/instance/qemu: Reject quotes and line breaks in qemu.conf values
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/861a27133200a41a6283e82d568b09f25a1c827a.patch";
      hash = "sha256-efNby+aZ4j9sDPKynFHnWRNK9UprvP4AVce9tEPyNOQ=";
      name = "GHSA-r69f-pwfc-cwrr.patch";
    })
    # incusd/device/tpm: Read device numbers from sysfs
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/20039141d6ce8338b5e9f2c34ab1a83e0ff1b511.patch";
      hash = "sha256-CqRzfUi9VGhn8lZuAy+bvneXCm9+f0ytzo2vkOaCpDk=";
      name = "GHSA-wgg4-rrw6-c64w.patch";
    })
    # incusd/device/nic_bridged: Restrict host-side routes in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9730077ec928c578f18137b7a72d469695c7e368.patch";
      hash = "sha256-5kLScnS21TOfVtIsKVX28hIXS591ryKcIVbdh3dhvz0=";
      name = "GHSA-cwm9-v375-rgvv.patch";
    })
    # incusd/storage: Validate snapshot names received through migration
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6be02496fa1e199674ba75ed45e882d2ce6386ab.patch";
      hash = "sha256-d/DWY6M8OSgVwBajJUfdHUEaCDnyibM6WS5Bb/NMbWA=";
      name = "GHSA-hfwr-h8hx-pw2g.patch";
    })
    # incusd/metrics: Escape label values
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8f43646c43566da60965be2807bcce46ecd2a445.patch";
      hash = "sha256-mRf7d/gi+MlWF1qTHdCj1vnojlIxrn5kdJDVZdzpl+o=";
      name = "GHSA-25w7-6vhq-9xqg.patch";
    })
    # incusd/instances: Enforce restricted.snapshots on copy, migration and import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/04a39ab69ada973e70effc89063071ec2d8434dc.patch";
      hash = "sha256-8oigx4/u959vsEmZOKvIqvXoyU24hGjFVtLcZUHVsps=";
      name = "GHSA-m976-4gjw-7vhp.patch";
    })
    # incusd/storage: Reject a symlinked block file when unpacking backups and images
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/21060562cd840c83a8e3628ccbdbde3db1a339c7.patch";
      hash = "sha256-gWWAoZ138H7DRYKGYWB9vcI0rrrLb65RcBcTu7FGFsk=";
      name = "GHSA-f886-r3x9-fp2r.1.patch";
    })
    # incusd/instance/lxc: Enable the devices cgroup for all containers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e8ebd25fc2ec8cd772e8f80077d66fce55d35ac4.patch";
      hash = "sha256-/frstEp3dbWReVakju/P/gCQCdaW/nP9RIIt10ed8qs=";
      name = "GHSA-f886-r3x9-fp2r.2.patch";
    })
    # tests: Allow snapshots in the restricted backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/896e6eb70f6d69e90dac551cddb5571a03fe414b.patch";
      hash = "sha256-WIn9haEiUatFPwwXjWEd4M3urZgib36QQAIP2G2sHG0=";
    })
    # incusd/auth: Treat unknown certificates as restricted in the router
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f17b193de4ad55a2b851935109527df928b7b7df.patch";
      hash = "sha256-F3i0sQDeEbkMhF90kBpMwcKHn68qlCeoujtxihaxsI8=";
      name = "GHSA-9m5m-cr24-m367.1.patch";
    })
    # incusd: Ignore client-supplied forwarded requestor headers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/13f60bb2c9dd558529734aa88b18b0ca56dc4d6a.patch";
      hash = "sha256-WmRmvYMQMg2Gp0XWIAwNA8vgyfYlXOCXn28CLIy2y5k=";
      name = "GHSA-9m5m-cr24-m367.2.patch";
    })
    # incusd/auth: Keep metrics certificates to metrics access
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a61b3f37b2bdbe7d824682094b5e4443054b7920.patch";
      hash = "sha256-chQSv8R/1DJ/Qqw/kFO1MgvkD5dhHCLVmVq4b/BYO4o=";
      name = "GHSA-9m5m-cr24-m367.3.patch";
    })
    # incusd: Block remote clients during startup
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6517962438c1bd3c0e287b9e4e28b9373908b89f.patch";
      hash = "sha256-RIx/ipWRJW0AwKkcI1u2OGlUEOCgn6qa3l39ZT1sXTI=";
      name = "GHSA-9m5m-cr24-m367.4.patch";
    })
    # incusd: Don't let the owner re-key a CA-trusted restricted certificate
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/cb76316e743d8379ccebbd90b901046592fa6726.patch";
      hash = "sha256-NgG02kKxmyH1TNmEqp4n7s8uEd6b6ELtkvJWCec1ZwI=";
      name = "GHSA-9m5m-cr24-m367.5.patch";
    })
    # incusd: Identify CA-issued certificates by their signed body
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/cddba23e0e9735263f0a0c0e813cfc29e2e3f47e.patch";
      hash = "sha256-h6W/xUxk4f2m29Y+7Be5rpdOKPVMOD+S0cOlUkw5LZk=";
      name = "GHSA-9m5m-cr24-m367.6.patch";
    })
    # incusd/auth/oidc: Bind JWT access tokens to the client and a subject
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5e275748d44433908b86c1ba9ea79d7412fa8d69.patch";
      hash = "sha256-DjpXzru8JKZhowwUmavtXG+1sTWJD6PDIPCX4ybMCTk=";
      name = "GHSA-cp5w-98j2-x2hv.1.patch";
    })
    # incusd: Stop restricted clients rewriting their certificate projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e996b99cef062cf6b2059bf558017c9c0f6b89f6.patch";
      hash = "sha256-zEBsFCCkGLqAqJetGmUKygvaBNUeANAd/OKwjJlISS8=";
      name = "GHSA-9m5m-cr24-m367.7.patch";
    })
    # incusd: Keep a cluster member's server certificate name in sync
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b951c75e8a85a55ca36890a064edea2e2e8e0474.patch";
      hash = "sha256-LAZD/x/WRNfj+jAjHegHrigHNYdMstj7DDr2MV2vqlI=";
      name = "GHSA-9m5m-cr24-m367.8.patch";
    })
    # incusd: Don't resolve locale or NSS modules from the instance
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6c2a84801e5a510482f7b145c39573a39731985f.patch";
      hash = "sha256-LIBk50fBs1zaM8JwJmdDd6KTsqCPX3pxacQogi20KrA=";
      name = "GHSA-28m6-7v43-rr8m.1.patch";
    })
    # incusd: Don't leak descriptors into the intercepted mount.fuse
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0602016fc25fb3d39a1f5df07d75e89a8d1cd0d1.patch";
      hash = "sha256-7bwKjxopVMooVkuOLQikaHO9yVl/r+dpGMGxG76XzAg=";
      name = "GHSA-28m6-7v43-rr8m.2.patch";
    })
    # incusd/rsync: Only accept the rsync helper on the transfer socket
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4abd7ad0cb5c1af829d038286c4d36b89ea8a3af.patch";
      hash = "sha256-QGNPgxax19N4g+7ZyTFVgkieJxIZ1CHR1/L9vXZRLs4=";
      name = "GHSA-p8fx-6xxm-25wh.1.patch";
    })
    # incusd: Harden forkproxy unix socket handling
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/938384c63e307474a841770944acfb93e51536e7.patch";
      hash = "sha256-pGBy5VuMvgLZ1H+Esoa9tEMIpi8NZPLoYZB/ybdEUwo=";
      name = "GHSA-p8fx-6xxm-25wh.2.patch";
    })
    # incusd/seccomp: Validate the notification before acting on mknod
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8e031ba28743c768c1b6d73614c1b758b95ab327.patch";
      hash = "sha256-9ojsJcD8jP590oQ1WLjnf9R/krWRreeVC60SgTnrIQ8=";
      name = "GHSA-28m6-7v43-rr8m.3.patch";
    })
    # incusd: Lock read-only on hot-plugged idmapped disks
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0e7f08c297a6e1b181638a5458dbcfc9908b7887.patch";
      hash = "sha256-mfeI4eT8DsunGRaQ29eqpxP8jxb3d0wDvcqVaijWNUo=";
      name = "GHSA-28m6-7v43-rr8m.4.patch";
    })
    # incusd: Confine backup and publish walks to the volume
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5727c8712536003a8cf3209875b9f01f29e7f258.patch";
      hash = "sha256-2VlBdJjjAiWs/njvoCiqk+PBFhj5AInKz+clvy/28sA=";
      name = "GHSA-42x8-664j-84w8.1.patch";
    })
    # incusd/storage: Match the volume content type on file, SFTP and NBD
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2f83ca2b9ce8cf8f62e8d129684a8e4f32aaee40.patch";
      hash = "sha256-eCjW8jlWdGfe+ZybjYja7QTyVHGLLFo/q3Bz/ZVKbsg=";
      name = "GHSA-42x8-664j-84w8.2.patch";
    })
    # incusd/storage: Reject a custom volume refresh that changes content type
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1c599b892c20b488429692ee62dba10c4e91d8d3.patch";
      hash = "sha256-vW6KHQ67vqm0pad8fiqgUlsN6KHSl3mi6zGE82BeyQk=";
      name = "GHSA-42x8-664j-84w8.3.patch";
    })
    # incusd/storage: Resolve bucket backup before export
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a5db4dfa5169a8d589b2f533bde0ce03cdbcdce5.patch";
      hash = "sha256-QwtNIR1z3HTMlCRFA7MNTNe3gTSTpiSHwnYGcywSmFY=";
      name = "GHSA-42x8-664j-84w8.4.patch";
    })
    # incusd: Validate the image fingerprint before recording it
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/eab65b6f54696a18bd67b36265553e189b497ccb.patch";
      hash = "sha256-HzsZs1BD3rKP5zld+dbqiZETqm4tVqSG10PVMJqFmfQ=";
      name = "GHSA-42x8-664j-84w8.5.patch";
    })
    # incusd/storage: Validate initial.mode as an octal mode
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/84ba4aa7748bb9fec9a933647e380a463cfc3afd.patch";
      hash = "sha256-iiS5IlaH6SUdxSJuRCM105bSknVZRUy1JVOScS8m3QA=";
      name = "GHSA-42x8-664j-84w8.6.patch";
    })
    # incusd: Restrict image delta base to an owned fingerprint
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3e73903d811920510bf181c0ec93387a936fe32a.patch";
      hash = "sha256-TAw2XPiCtDgAqLJFKiz9XJlw6f0uKeg2yQG1gihKnBg=";
      name = "GHSA-42x8-664j-84w8.7.patch";
    })
    # incusd/storage: Serialize custom volume content against access
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/677ad35afcbe8a7aa8d30eb38673c611af55e356.patch";
      hash = "sha256-BsCii3thge3j+5oxeHwqdDG46oE5uOZQ28+fDLY8d+c=";
      name = "GHSA-42x8-664j-84w8.8.patch";
    })
    # incusd: Lock the instance during rebuild
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5c61a3a2dc3ceab0f50c304e0c5a4a7bba78658c.patch";
      hash = "sha256-S8QjLK3ICadeaQa9jN7VBCmcv0iEQaD3LHeRc29ctXo=";
      name = "GHSA-42x8-664j-84w8.9.patch";
    })
    # incusd: Lock the instance during rename
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/56e1896a503125536fa58b08fcb6fb3c581d0b06.patch";
      hash = "sha256-U53EPJ1TOySVgnH3/uFBOPaARh+iqh2yX113fKjnE2g=";
      name = "GHSA-42x8-664j-84w8.10.patch";
    })
    # incusd/storage: Reject rootfs content in a split image metadata tarball
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/90e37b694d707437cf5454e3a7aabf61302721d3.patch";
      hash = "sha256-z6ICGoQd56hQhX10WXVqwz5GICjprdHY2Hxa6EqZkaE=";
      name = "GHSA-f5f6-6x9q-gh3f.patch";
    })
    # incusd: Keep instance volume directories root-owned on receive
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1708d41f6dacf572e2b42f40ca89bbada12b0792.patch";
      hash = "sha256-rKc9J+uFw/kVY1AhVMOXXwG0vmQ9/5k9azSxmrZoUKc=";
      name = "GHSA-p8fx-6xxm-25wh.3.patch";
    })
    # incusd/device: Reject ".." components in device mount paths
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b341c973290a787b1d649881ac75dd371b5cf8e5.patch";
      hash = "sha256-kpZvqab3O/l2GlwSvCpHPJFsBZhMuGJowhqRTan8ryk=";
      name = "GHSA-4375-qwr5-8vjj.1.patch";
    })
    # incusd/device: Mount disk staging bind mounts nosuid
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1b8c299840ed5f84d6ce6be00935ef8d6f41bbfd.patch";
      hash = "sha256-g3mN+9DCwnU2buOLdBQz+cSHF5EcNqEWULD1D09dflg=";
      name = "GHSA-p8fx-6xxm-25wh.4.patch";
    })
    # incusd: Take VM disk format from config on publish and NBD
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1749df21f8f3513c027f542ee343c8d64673ea61.patch";
      hash = "sha256-7r3j3OM3LiMvNC01YjfVZ/fs+I5qwlOGe/Da4BHJxrQ=";
      name = "GHSA-4375-qwr5-8vjj.2.patch";
    })
    # incusd/storage: Reject non-self-contained VM images on unpack
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0974c7a904c2254e76cc796b539b2028dfe6e9de.patch";
      hash = "sha256-FZysgq0O3M0NaPYIiWr0GOadRtoWCyrCqyIkvjCTNu8=";
      name = "GHSA-4375-qwr5-8vjj.3.patch";
    })
    # incusd/device: Forbid guest root on restricted VM disk shares
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5f9bc490e5dd22b749edc3503983954edd2884ab.patch";
      hash = "sha256-dtJPZ8xbzx/vUK4B/oDI05+RPrJ8Evl6yuxojVOn+oE=";
      name = "GHSA-4375-qwr5-8vjj.4.patch";
    })
    # incusd/project: Forbid raw.idmap mapping onto container root in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a65b87c3381042bf91b2a6b370c0e6593342f540.patch";
      hash = "sha256-KvGeql13hpNiZazODruWK3TyF6Q4Bkv4NMnr8pK7h2M=";
      name = "GHSA-4375-qwr5-8vjj.5.patch";
    })
    # incusd/device: Treat a source as external ceph only without a pool
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/cb30f82ab49aff0ba51db1bcfbbdd53f9db897c5.patch";
      hash = "sha256-Y/1msYn2EE3X8jyqOJtZjKZcum62WfMTt7NiatnMiI0=";
      name = "GHSA-4375-qwr5-8vjj.6.patch";
    })
    # incusd: Don't let an image plant a liblxc config file
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b23a49ebb5b2d06d7e44bd834ed0ff2987d29c12.patch";
      hash = "sha256-jFoH8YLv8En8ssPhnvhj8Z6bbkfehknscRPXI65HIpw=";
      name = "GHSA-mmh3-jfjc-6vc2.1.patch";
    })
    # incusd/project: Fail closed when the checked profile or instance is gone
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8ecf92d5a13c9c87841531ce0f1ba6d47415ac94.patch";
      hash = "sha256-rMfKjFM8MCcCo3fMS8udwM2Kt8ItEVoifesJz9L9kmU=";
      name = "GHSA-mmh3-jfjc-6vc2.2.patch";
    })
    # incusd: Serialize instance rewrites on volume rename and profile update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1c60f9f52c4492fa2c9d9f95453fda3e7b2c9f98.patch";
      hash = "sha256-qubufQFC76J8T6oyPPiF2b6tP3u7tSuvS3nbOkpE0UM=";
      name = "GHSA-mmh3-jfjc-6vc2.3.patch";
    })
    # incusd/instance: Return a copy of the local config from Render
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e7e6def86b6c189b3c0d5ca4a05dd71322ac5790.patch";
      hash = "sha256-NcQSBhOvCowyAYZ+05CPRD91D/WyzFZcKmDuVn/uTxY=";
      name = "GHSA-5pf7-5wqc-rp52.1.patch";
    })
    # incusd: Check project restrictions after the move pool override
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4728ce2a2daf5bada1a85143fdceed2afdd1d812.patch";
      hash = "sha256-N6zsIG2xVeiWkj1go3Vz4kXh29lhcJyVhikAOhf3ClQ=";
      name = "GHSA-5pf7-5wqc-rp52.2.patch";
    })
    # incusd/project: Treat volatile.selinux.context as a restricted key
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4888d70e0cb5bf9d6738477937c99c3083c7f728.patch";
      hash = "sha256-aGlTxF6EqaJXnRyN2thIrATFwW0cusQmKtz5mXClLO0=";
      name = "GHSA-5pf7-5wqc-rp52.3.patch";
    })
    # incusd: Keep the imported root disk on the import pool
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1d0f96377d18f38c622243823880d1a0a5f58484.patch";
      hash = "sha256-RP1ai1CZt2fsf+L21o5QzQrLzJXP30KoACcmMBZQUlU=";
      name = "GHSA-5pf7-5wqc-rp52.4.patch";
    })
    # incusd/network/ovn: Validate pinned uplink addresses against the ranges
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/ea4218d0c54ab758d8b95776c8f68d0e8a9eca10.patch";
      hash = "sha256-fVF+hJhQUeetzlEN7LCcFBORYogpj9zOLDy+7Xa85C8=";
      name = "GHSA-5pf7-5wqc-rp52.5.patch";
    })
    # incusd/seccomp: Keep intercepted syscall strings NUL-terminated
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d91072dad789207d93c807384d44de72ee6fd923.patch";
      hash = "sha256-1s/lfUBWlJjc+QJULPhpcM+l+hxExpu0SLstAcG88Sw=";
      name = "GHSA-28m6-7v43-rr8m.5.patch";
    })
    # incusd/instance/qemu: Keep secrets out of the QMP log
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1fc0cc625b76948047920f68e007d3d8ecf7f0bb.patch";
      hash = "sha256-9i/RoogTd4MALut4385ktunWG1QhbgRN2iB6Bej3Q6k=";
      name = "GHSA-44g3-g988-46rg.1.patch";
    })
    # incusd/storage: Validate bucket key names and credentials
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b12046d5a8d49c46bde6c18e622a7985f6297237.patch";
      hash = "sha256-QKwg4V2av/OAZJUl3TPCbzIyI53lPj0fjnHIQ6fk7E8=";
      name = "GHSA-44g3-g988-46rg.2.patch";
    })
    # incusd/storage: Keep the pool config out of exports and migrations
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/722251e65e48da91e288d4abcae8c8f51aa194d6.patch";
      hash = "sha256-hKpBcGGyDdaokJWJ5skQUktv7qYi8DTqrtO17jmIl48=";
      name = "GHSA-44g3-g988-46rg.3.patch";
    })
    # incusd: Hide credentials in the server config from non-editors
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9c369d22df95d98581163bda2fd29d7bd836a738.patch";
      hash = "sha256-hPKcsFO7X4/FrNr7DK4J/A5CTuC/NnZfuF0wUa/+V3E=";
      name = "GHSA-44g3-g988-46rg.4.patch";
    })
    # incusd/db: Scope backup records to their owner
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/729b70a2f3677dbfb03abffb4fb48e36a8758411.patch";
      hash = "sha256-IdStBw/gqK5isfkeUDC4vIzoSE0pFQWPk3YGmiHumSc=";
      name = "GHSA-8m9x-vx2q-7f9q.1.patch";
    })
    # incusd: Validate instance and bucket backup names
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9efd61edd7800f001685fd3ff17b6d05462530f6.patch";
      hash = "sha256-bxrHswijTe/pqELSD/ZeckoDLsaH9xExGklTO0bmjHA=";
      name = "GHSA-8m9x-vx2q-7f9q.2.patch";
    })
    # incusd: Don't follow a symlinked exec output directory
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8caa454b5d678d25c329e27120f6046e429d7e6b.patch";
      hash = "sha256-mRVIQVBdScyFyky98IFRpaxwFQI+wjrof3OX/d3giH8=";
      name = "GHSA-8m9x-vx2q-7f9q.3.patch";
    })
    # incusd: Only serve custom volumes on the file and SFTP endpoints
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4aab94338e1235e2223ac6e19e9b9aad2a7fa0b3.patch";
      hash = "sha256-iEErtHnkvL7wHYKsI9dBK8RyK5zVzKjpjWsFTUXMD+c=";
      name = "GHSA-8m9x-vx2q-7f9q.4.patch";
    })
    # incusd: Serve the targeted member's volume on the file and SFTP endpoints
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0004c6d6aa19ba048890bc8baf65b92135ce7391.patch";
      hash = "sha256-npeiMuTIuCrXLNANZeFhjdDXOAwFZYdFm7eCEniFhvc=";
      name = "GHSA-8m9x-vx2q-7f9q.5.patch";
    })
    # incusd: Migrate the requested volume on a cross-member move
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d81225cad43bb4a5ca87d5873f32ae75d2f375ce.patch";
      hash = "sha256-vNHpHg6tqzzWt3Btx+v7RZGHRT3NCdu1gNquUa1vMj4=";
      name = "GHSA-8m9x-vx2q-7f9q.6.patch";
    })
    # incusd: Don't let restricted projects claim another project's volume as dependent
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/08269c3189968aafb602dd9ad2e235069919e2f0.patch";
      hash = "sha256-hVhtyeP0UGv9WC8c1Dh8SvYCr+F7+mw1/a0lbBFEweY=";
      name = "GHSA-8m9x-vx2q-7f9q.7.patch";
    })
    # incusd: Check the project's cluster groups on backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0d7c43649e11113784882ef5c0b8d951bf7f515e.patch";
      hash = "sha256-xiuhbjSGoWImbdkMTwx/NsyKFpuL80xC1l2+h5WlGcQ=";
      name = "GHSA-8m9x-vx2q-7f9q.8.patch";
    })
    # incusd: Check the project's cluster groups on volume and bucket placement
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1cb456420f0f02c37cb9e19296728f6ea79eb365.patch";
      hash = "sha256-/7UE14squ+h+332o5wlvP6s0gdAmYBDELvsZ+JsXPZE=";
      name = "GHSA-8m9x-vx2q-7f9q.9.patch";
    })
    # incusd: Refuse access to the volumes holding the daemon's data
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8f0a85f2548c34d390558fdbcd54a715d1e7ce45.patch";
      hash = "sha256-iQjcDWDMk4pIAh0wayy0GzM+XihhZ3pdtoXUeP+h2bk=";
      name = "GHSA-8m9x-vx2q-7f9q.10.patch";
    })
    # incusd: Require edit access on the target of a refresh
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/10b2f3be43d9caf6889c01fb920740af07ddaade.patch";
      hash = "sha256-JPnUwEDcXb/tXMSyHhkauOOGuYnviYl9j8nCLbec3Og=";
      name = "GHSA-8553-6xmq-7g3g.1.patch";
    })
    # incusd: Check image access when creating or rebuilding from a local image
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e4184a2be9a7741396dd7e0bd4ae044a18b49308.patch";
      hash = "sha256-uLnNS7/S7SG7XmxnJzrUER1sOjXfPyTyPOU+ZCSixI0=";
      name = "GHSA-8553-6xmq-7g3g.2.patch";
    })
    # incusd: Check access to profiles and volumes attached through an update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6131a67f25bac103232df20fe094799487c08694.patch";
      hash = "sha256-kcI9mNiHlRDjLYMw+OZ5FuVhG+XH3AEqGLnBR7B7Kus=";
      name = "GHSA-8553-6xmq-7g3g.3.patch";
    })
    # incusd: Require edit access to migrate a snapshot
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0cd02e6adfb0d8125e60e8ce33f051512e8795d5.patch";
      hash = "sha256-7V/Iz855Fj52cNTtuFhcSDhZO56qDNo9X0mlZLYqyHw=";
      name = "GHSA-8553-6xmq-7g3g.4.patch";
    })
    # incusd: Only restore an instance from its own snapshots
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/92ff6295f3631890f0304ad47e4bc82abffcfb0f.patch";
      hash = "sha256-y18KsR9PZMK/yYWl4iJquTs85Ue+TVNH37w9TqY8CBY=";
      name = "GHSA-8553-6xmq-7g3g.5.patch";
    })
    # incusd/images: Require edit access to rewrite an existing image on copy
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f93d1a24b77e0a38f3a2f5364764513499900dbb.patch";
      hash = "sha256-dEZakvNlo5mLG68A+bi5RxuRbgMLBZR5WhV3Rm6sbFk=";
      name = "GHSA-8553-6xmq-7g3g.6.patch";
    })
    # incusd/project: Keep container runtime state out of restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/50023941ef963782402c1ebf7a74a3378d79863f.patch";
      hash = "sha256-q/TQEYZY+ur8v1nVSozc9Hrbz2V242ZvLsJ2ft39ed8=";
      name = "GHSA-8553-6xmq-7g3g.7.patch";
    })
    # incusd/network/ovn: Only remove VLAN interfaces the network created
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4d793188f22ad4e3f5507d37beef66057a54da75.patch";
      hash = "sha256-1Ojhqdn2Dj6GuJJKUlMFiei0fC90xkaBenuRmPq0wWw=";
      name = "GHSA-fg2p-r659-c4q8.1.patch";
    })
    # incusd/device: Check the interface an instance hands back
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/25ddeff57a45234c2de04f161952e5e9509a990a.patch";
      hash = "sha256-drA4oEWvN/VhadnyYcb/R4NMZZlaRlSBaMTV/mgTqxo=";
      name = "GHSA-fg2p-r659-c4q8.2.patch";
    })
    # incusd/device: Count NICs on managed networks as VLAN interface users
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/827e185de6d20281718b43d3101eefd473c4c303.patch";
      hash = "sha256-WZjX5HC8dJYQpkfjwrkzliBs9wnEDq2F0p1sNpo1UXk=";
      name = "GHSA-fg2p-r659-c4q8.3.patch";
    })
    # incusd/device: Validate the NIC host_name option
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/610b85d51ea126ebf762bdea216b471ab2f4e79b.patch";
      hash = "sha256-pYt8r1KUEzj1+FCGQ263pgeIxZXFHevUQf2UzPiFPrs=";
      name = "GHSA-fg2p-r659-c4q8.4.patch";
    })
    # incusd/network/ovn: Forbid host interfaces and tunnels in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7cd8909f30e039c78eae1d46c4ceaf19b3d2256b.patch";
      hash = "sha256-7oMOzKMd5knVf5Ldby4x8tDQ+6etUdhqyf9BwmUPz+A=";
      name = "GHSA-fg2p-r659-c4q8.5.patch";
    })
    # incusd/network: Check restricted.networks.zones on network zone keys
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/43fa11cb11d8e849345c3613ccb3ff50804499d1.patch";
      hash = "sha256-DoIvjymfba5UQnsH+lKEajv4pc+zKNnrgO5g3tAuj+Q=";
      name = "GHSA-fg2p-r659-c4q8.6.patch";
    })
    # incusd/network: Keep long VLAN interface names unique per parent
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7815baf7930b19f6822b710d526d19e9e36de302.patch";
      hash = "sha256-4E4DV89bxozu+LzXTYJtoeCg4cRBXaiYSisE7EEizHM=";
      name = "GHSA-fg2p-r659-c4q8.7.patch";
    })
    # incusd/instance/qemu: Only mirror known UEFI variables file names
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a55d4b2c8229a20564d46641446b5801d6a47f6d.patch";
      hash = "sha256-diPX3Mw0GHk0P/Gi2mT49mUm7Snkv5ARIQ8kPLaSCps=";
      name = "GHSA-4375-qwr5-8vjj.7.patch";
    })
    # incusd/forknet: Enter the network namespace through init's pidfd
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3bc858291b0ada42f200d47607884da1630210a0.patch";
      hash = "sha256-lmed10rGh52SpR4lA0t4h6t5f/IEuiuFLaRR+m9bm24=";
      name = "GHSA-fg2p-r659-c4q8.8.patch";
    })
    # incusd/storage: Keep the full name on loaded bucket backups
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a17a3a29922ce6d27ab9556199f05ed252bad363.patch";
      hash = "sha256-fsi14I7Qtv45eZIdHSuaPuxTSnpHW5PWqlOjxUi5sRk=";
      name = "GHSA-8m9x-vx2q-7f9q.11.patch";
    })
    # incusd: Only reuse public images from other projects on refresh
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0581b5584dea8c2bfe1059aed486d0ba4890b839.patch";
      hash = "sha256-kRdmt4II5Eqr+162D6FhG7Zq0oovT4Su0nz3vk7uyzs=";
      name = "GHSA-4j59-4pqh-f3qm.1.patch";
    })
    # incusd: Give image upload tokens their own operation type
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0378aabeac850240eb1544749478dfa9ee74c2db.patch";
      hash = "sha256-SdFYVLakE4/nivB87HtPwjCIvINLVtE3RefZBmfiw08=";
      name = "GHSA-4j59-4pqh-f3qm.2.patch";
    })
    # incusd: Limit image token callers to the raw upload
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2b81c0757a6a098cdbe85a90df05c108d1d4f4c7.patch";
      hash = "sha256-VV6u3ERTByH4BNyZbM2yWGzo4Apn/0mwZrz44Pfnwu4=";
      name = "GHSA-4j59-4pqh-f3qm.3.patch";
    })
    # incusd: Never replace stored image files on upload
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/418d88e1a2bf6ce1ac279e489b09dcd09e2b766d.patch";
      hash = "sha256-x29x0t7LjcS2FRmyWOXibiepWgb6r5E/T9Nt0f0KsCY=";
      name = "GHSA-4j59-4pqh-f3qm.4.patch";
    })
    # incusd: Remove replaced image volumes only once unreferenced
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6714a95bed3647146b72c8a55309c19a6ed7c2bb.patch";
      hash = "sha256-/trBEn6W33n+o14cUU/mOieydGg0WL70uSE0uhjvo8c=";
      name = "GHSA-4j59-4pqh-f3qm.5.patch";
    })
    # client/oci: Fingerprint the manifest and pin the copy to it
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1f3b2372413d5ecb441c210c500a44f817c2f965.patch";
      hash = "sha256-touQIDHNuli6iUhMMpcLAGLBHHtTpO+CCxB7z3lbX2c=";
      name = "GHSA-4j59-4pqh-f3qm.6.patch";
    })
    # incusd: Store downloaded images under the hash of their content
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/07e1a22c88bce2e486c0e48c7393cb1503e5dc6a.patch";
      hash = "sha256-9Y55dxoS1ABVQA+vsNW8gGRObXBSvMf33TnrUAQuJAk=";
      name = "GHSA-4j59-4pqh-f3qm.7.patch";
    })
    # tests: Expect image volumes to stay while a project uses the image
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1c244fa3c21d4c14974605cb4e276a9b2d0b1ba2.patch";
      hash = "sha256-GrH+Ji2I1vSjC3yS6laZuMbgDijBbjR77RVsmIQ1fFM=";
    })
    # tests: Skip DAD on the peering host address
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/63a6c21becd5661ade9c9c19748dc4551da11c67.patch";
      hash = "sha256-UhJZU7YIb2pfCEeBlI9HzEGAuVpRWTyRDLaFvHwmDNY=";
    })
    # incusd: Check certificate ownership on every non-admin update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9afe1c7f7beea641381c41d90c111b369fc8ea35.patch";
      hash = "sha256-OdTOluEv3Ia9mEYkF7URp5bgSfwlbq85BM93H+a18ME=";
      name = "GHSA-7643-2vqq-56p3.patch";
    })
    # incusd/auth/tls: Only inherit default project objects through a project using them
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6fa7b9f380af81d86effabdde97c261f101a24f3.patch";
      hash = "sha256-bZOB8Y15wuO5vintUJFIsLhO9nmCLvDycjZ6qUISCxc=";
      name = "GHSA-3c9p-936j-gv99.patch";
    })
    # incusd: Authorize dependent volumes on backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c9a51adde210c3abde7857c3b99881c4359fd505.patch";
      hash = "sha256-SHjRWAnWzHWrxwmI8wz/DARvtdQNEp5F+qbb7nA4gDw=";
      name = "GHSA-hm9p-jjr8-3jp8.patch";
    })
    # incusd/operations: Strip the state secret from renders too
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4269b6f210b8449cfa6d8e4620b678114f8753bd.patch";
      hash = "sha256-KYgSQtnPNba2CgwkejZjm5HmCbd3d+/diCBgMBEeOno=";
      name = "GHSA-j5qp-xv8h-whfp.patch";
    })
    # incusd/storage/s3: Bound aws-chunked chunk sizes
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/74d6d87b0fe31d49286dd26820f645c48eb5225c.patch";
      hash = "sha256-mso5a9geciRt3RDJ7yLTZSmJxXdIPEx0GX4sMIDcPuc=";
      name = "GHSA-537m-jhcr-hxmm.patch";
    })
    # incusd: Limit non-streaming bodies on large request endpoints
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/91ac578127234ba27bc2af043ed0d82138052334.patch";
      hash = "sha256-1cqexBKQ6cHTrfuivgxD0iAPuf/e3UjBfH4KXmpLiL4=";
      name = "GHSA-cxqx-x785-5926.patch";
    })
    # incusd: Forbid push mode migration in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7d2172f325256eaae34401d7f192e2155694b425.patch";
      hash = "sha256-vbFydx4Ez3aIzs0TGWWQyTpkMhA+g4gXpxiFOOvLW9Q=";
      name = "GHSA-chhj-pwx6-9cx3.1.patch";
    })
    # incusd/storage: Check project restrictions on instance volume config
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/35d913984479d2f4b4cc0f64ca6fd2032d777a09.patch";
      hash = "sha256-g8pNF/pFUNZTNcki16jwheRpf1eWwY8OCxq9VjeVNn0=";
      name = "GHSA-cm79-v2v8-5grh.patch";
    })
    # incusd/migration: Bound the size of protocol messages
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c726d64d563fd5b70c848a8aaa108d7b3c5d2070.patch";
      hash = "sha256-huH2pu9fZEXgro4G5DZZ0YNCcIOYJlWumTAZqSjXCMM=";
      name = "GHSA-r69q-f272-2qmr.patch";
    })
    # incusd/instance/qemu: Reject quotes and line breaks in qemu.conf values
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/861a27133200a41a6283e82d568b09f25a1c827a.patch";
      hash = "sha256-efNby+aZ4j9sDPKynFHnWRNK9UprvP4AVce9tEPyNOQ=";
      name = "GHSA-r69f-pwfc-cwrr.patch";
    })
    # incusd/device/tpm: Read device numbers from sysfs
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/20039141d6ce8338b5e9f2c34ab1a83e0ff1b511.patch";
      hash = "sha256-CqRzfUi9VGhn8lZuAy+bvneXCm9+f0ytzo2vkOaCpDk=";
      name = "GHSA-wgg4-rrw6-c64w.patch";
    })
    # incusd/device/nic_bridged: Restrict host-side routes in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9730077ec928c578f18137b7a72d469695c7e368.patch";
      hash = "sha256-5kLScnS21TOfVtIsKVX28hIXS591ryKcIVbdh3dhvz0=";
      name = "GHSA-cwm9-v375-rgvv.patch";
    })
    # incusd/storage: Validate snapshot names received through migration
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6be02496fa1e199674ba75ed45e882d2ce6386ab.patch";
      hash = "sha256-d/DWY6M8OSgVwBajJUfdHUEaCDnyibM6WS5Bb/NMbWA=";
      name = "GHSA-hfwr-h8hx-pw2g.patch";
    })
    # incusd/metrics: Escape label values
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8f43646c43566da60965be2807bcce46ecd2a445.patch";
      hash = "sha256-mRf7d/gi+MlWF1qTHdCj1vnojlIxrn5kdJDVZdzpl+o=";
      name = "GHSA-25w7-6vhq-9xqg.patch";
    })
    # incusd/instances: Enforce restricted.snapshots on copy, migration and import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/04a39ab69ada973e70effc89063071ec2d8434dc.patch";
      hash = "sha256-8oigx4/u959vsEmZOKvIqvXoyU24hGjFVtLcZUHVsps=";
      name = "GHSA-m976-4gjw-7vhp.patch";
    })
    # incusd/storage: Reject a symlinked block file when unpacking backups and images
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/21060562cd840c83a8e3628ccbdbde3db1a339c7.patch";
      hash = "sha256-gWWAoZ138H7DRYKGYWB9vcI0rrrLb65RcBcTu7FGFsk=";
      name = "GHSA-f886-r3x9-fp2r.1.patch";
    })
    # incusd/instance/lxc: Enable the devices cgroup for all containers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e8ebd25fc2ec8cd772e8f80077d66fce55d35ac4.patch";
      hash = "sha256-/frstEp3dbWReVakju/P/gCQCdaW/nP9RIIt10ed8qs=";
      name = "GHSA-f886-r3x9-fp2r.2.patch";
    })
    # tests: Allow snapshots in the restricted backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/896e6eb70f6d69e90dac551cddb5571a03fe414b.patch";
      hash = "sha256-WIn9haEiUatFPwwXjWEd4M3urZgib36QQAIP2G2sHG0=";
    })
    # incusd/auth: Treat unknown certificates as restricted in the router
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f17b193de4ad55a2b851935109527df928b7b7df.patch";
      hash = "sha256-F3i0sQDeEbkMhF90kBpMwcKHn68qlCeoujtxihaxsI8=";
      name = "GHSA-9m5m-cr24-m367.1.patch";
    })
    # incusd: Ignore client-supplied forwarded requestor headers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/13f60bb2c9dd558529734aa88b18b0ca56dc4d6a.patch";
      hash = "sha256-WmRmvYMQMg2Gp0XWIAwNA8vgyfYlXOCXn28CLIy2y5k=";
      name = "GHSA-9m5m-cr24-m367.2.patch";
    })
    # incusd/auth: Keep metrics certificates to metrics access
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a61b3f37b2bdbe7d824682094b5e4443054b7920.patch";
      hash = "sha256-chQSv8R/1DJ/Qqw/kFO1MgvkD5dhHCLVmVq4b/BYO4o=";
      name = "GHSA-9m5m-cr24-m367.3.patch";
    })
    # incusd: Block remote clients during startup
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6517962438c1bd3c0e287b9e4e28b9373908b89f.patch";
      hash = "sha256-RIx/ipWRJW0AwKkcI1u2OGlUEOCgn6qa3l39ZT1sXTI=";
      name = "GHSA-9m5m-cr24-m367.4.patch";
    })
    # incusd: Don't let the owner re-key a CA-trusted restricted certificate
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/cb76316e743d8379ccebbd90b901046592fa6726.patch";
      hash = "sha256-NgG02kKxmyH1TNmEqp4n7s8uEd6b6ELtkvJWCec1ZwI=";
      name = "GHSA-9m5m-cr24-m367.5.patch";
    })
    # incusd: Identify CA-issued certificates by their signed body
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/cddba23e0e9735263f0a0c0e813cfc29e2e3f47e.patch";
      hash = "sha256-h6W/xUxk4f2m29Y+7Be5rpdOKPVMOD+S0cOlUkw5LZk=";
      name = "GHSA-9m5m-cr24-m367.6.patch";
    })
    # incusd/auth/oidc: Bind JWT access tokens to the client and a subject
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5e275748d44433908b86c1ba9ea79d7412fa8d69.patch";
      hash = "sha256-DjpXzru8JKZhowwUmavtXG+1sTWJD6PDIPCX4ybMCTk=";
      name = "GHSA-cp5w-98j2-x2hv.1.patch";
    })
    # incusd: Stop restricted clients rewriting their certificate projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e996b99cef062cf6b2059bf558017c9c0f6b89f6.patch";
      hash = "sha256-zEBsFCCkGLqAqJetGmUKygvaBNUeANAd/OKwjJlISS8=";
      name = "GHSA-9m5m-cr24-m367.7.patch";
    })
    # incusd: Keep a cluster member's server certificate name in sync
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b951c75e8a85a55ca36890a064edea2e2e8e0474.patch";
      hash = "sha256-LAZD/x/WRNfj+jAjHegHrigHNYdMstj7DDr2MV2vqlI=";
      name = "GHSA-9m5m-cr24-m367.8.patch";
    })
    # incusd: Don't resolve locale or NSS modules from the instance
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6c2a84801e5a510482f7b145c39573a39731985f.patch";
      hash = "sha256-LIBk50fBs1zaM8JwJmdDd6KTsqCPX3pxacQogi20KrA=";
      name = "GHSA-28m6-7v43-rr8m.1.patch";
    })
    # incusd: Don't leak descriptors into the intercepted mount.fuse
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0602016fc25fb3d39a1f5df07d75e89a8d1cd0d1.patch";
      hash = "sha256-7bwKjxopVMooVkuOLQikaHO9yVl/r+dpGMGxG76XzAg=";
      name = "GHSA-28m6-7v43-rr8m.2.patch";
    })
    # incusd/rsync: Only accept the rsync helper on the transfer socket
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4abd7ad0cb5c1af829d038286c4d36b89ea8a3af.patch";
      hash = "sha256-QGNPgxax19N4g+7ZyTFVgkieJxIZ1CHR1/L9vXZRLs4=";
      name = "GHSA-p8fx-6xxm-25wh.1.patch";
    })
    # incusd: Harden forkproxy unix socket handling
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/938384c63e307474a841770944acfb93e51536e7.patch";
      hash = "sha256-pGBy5VuMvgLZ1H+Esoa9tEMIpi8NZPLoYZB/ybdEUwo=";
      name = "GHSA-p8fx-6xxm-25wh.2.patch";
    })
    # incusd/seccomp: Validate the notification before acting on mknod
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8e031ba28743c768c1b6d73614c1b758b95ab327.patch";
      hash = "sha256-9ojsJcD8jP590oQ1WLjnf9R/krWRreeVC60SgTnrIQ8=";
      name = "GHSA-28m6-7v43-rr8m.3.patch";
    })
    # incusd: Lock read-only on hot-plugged idmapped disks
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0e7f08c297a6e1b181638a5458dbcfc9908b7887.patch";
      hash = "sha256-mfeI4eT8DsunGRaQ29eqpxP8jxb3d0wDvcqVaijWNUo=";
      name = "GHSA-28m6-7v43-rr8m.4.patch";
    })
    # incusd: Confine backup and publish walks to the volume
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5727c8712536003a8cf3209875b9f01f29e7f258.patch";
      hash = "sha256-2VlBdJjjAiWs/njvoCiqk+PBFhj5AInKz+clvy/28sA=";
      name = "GHSA-42x8-664j-84w8.1.patch";
    })
    # incusd/storage: Match the volume content type on file, SFTP and NBD
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2f83ca2b9ce8cf8f62e8d129684a8e4f32aaee40.patch";
      hash = "sha256-eCjW8jlWdGfe+ZybjYja7QTyVHGLLFo/q3Bz/ZVKbsg=";
      name = "GHSA-42x8-664j-84w8.2.patch";
    })
    # incusd/storage: Reject a custom volume refresh that changes content type
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1c599b892c20b488429692ee62dba10c4e91d8d3.patch";
      hash = "sha256-vW6KHQ67vqm0pad8fiqgUlsN6KHSl3mi6zGE82BeyQk=";
      name = "GHSA-42x8-664j-84w8.3.patch";
    })
    # incusd/storage: Resolve bucket backup before export
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a5db4dfa5169a8d589b2f533bde0ce03cdbcdce5.patch";
      hash = "sha256-QwtNIR1z3HTMlCRFA7MNTNe3gTSTpiSHwnYGcywSmFY=";
      name = "GHSA-42x8-664j-84w8.4.patch";
    })
    # incusd: Validate the image fingerprint before recording it
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/eab65b6f54696a18bd67b36265553e189b497ccb.patch";
      hash = "sha256-HzsZs1BD3rKP5zld+dbqiZETqm4tVqSG10PVMJqFmfQ=";
      name = "GHSA-42x8-664j-84w8.5.patch";
    })
    # incusd/storage: Validate initial.mode as an octal mode
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/84ba4aa7748bb9fec9a933647e380a463cfc3afd.patch";
      hash = "sha256-iiS5IlaH6SUdxSJuRCM105bSknVZRUy1JVOScS8m3QA=";
      name = "GHSA-42x8-664j-84w8.6.patch";
    })
    # incusd: Restrict image delta base to an owned fingerprint
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3e73903d811920510bf181c0ec93387a936fe32a.patch";
      hash = "sha256-TAw2XPiCtDgAqLJFKiz9XJlw6f0uKeg2yQG1gihKnBg=";
      name = "GHSA-42x8-664j-84w8.7.patch";
    })
    # incusd/storage: Serialize custom volume content against access
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/677ad35afcbe8a7aa8d30eb38673c611af55e356.patch";
      hash = "sha256-BsCii3thge3j+5oxeHwqdDG46oE5uOZQ28+fDLY8d+c=";
      name = "GHSA-42x8-664j-84w8.8.patch";
    })
    # incusd: Lock the instance during rebuild
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5c61a3a2dc3ceab0f50c304e0c5a4a7bba78658c.patch";
      hash = "sha256-S8QjLK3ICadeaQa9jN7VBCmcv0iEQaD3LHeRc29ctXo=";
      name = "GHSA-42x8-664j-84w8.9.patch";
    })
    # incusd: Lock the instance during rename
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/56e1896a503125536fa58b08fcb6fb3c581d0b06.patch";
      hash = "sha256-U53EPJ1TOySVgnH3/uFBOPaARh+iqh2yX113fKjnE2g=";
      name = "GHSA-42x8-664j-84w8.10.patch";
    })
    # incusd/storage: Reject rootfs content in a split image metadata tarball
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/90e37b694d707437cf5454e3a7aabf61302721d3.patch";
      hash = "sha256-z6ICGoQd56hQhX10WXVqwz5GICjprdHY2Hxa6EqZkaE=";
      name = "GHSA-f5f6-6x9q-gh3f.patch";
    })
    # incusd: Keep instance volume directories root-owned on receive
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1708d41f6dacf572e2b42f40ca89bbada12b0792.patch";
      hash = "sha256-rKc9J+uFw/kVY1AhVMOXXwG0vmQ9/5k9azSxmrZoUKc=";
      name = "GHSA-p8fx-6xxm-25wh.3.patch";
    })
    # incusd/device: Reject ".." components in device mount paths
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b341c973290a787b1d649881ac75dd371b5cf8e5.patch";
      hash = "sha256-kpZvqab3O/l2GlwSvCpHPJFsBZhMuGJowhqRTan8ryk=";
      name = "GHSA-4375-qwr5-8vjj.1.patch";
    })
    # incusd/device: Mount disk staging bind mounts nosuid
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1b8c299840ed5f84d6ce6be00935ef8d6f41bbfd.patch";
      hash = "sha256-g3mN+9DCwnU2buOLdBQz+cSHF5EcNqEWULD1D09dflg=";
      name = "GHSA-p8fx-6xxm-25wh.4.patch";
    })
    # incusd: Take VM disk format from config on publish and NBD
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1749df21f8f3513c027f542ee343c8d64673ea61.patch";
      hash = "sha256-7r3j3OM3LiMvNC01YjfVZ/fs+I5qwlOGe/Da4BHJxrQ=";
      name = "GHSA-4375-qwr5-8vjj.2.patch";
    })
    # incusd/storage: Reject non-self-contained VM images on unpack
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0974c7a904c2254e76cc796b539b2028dfe6e9de.patch";
      hash = "sha256-FZysgq0O3M0NaPYIiWr0GOadRtoWCyrCqyIkvjCTNu8=";
      name = "GHSA-4375-qwr5-8vjj.3.patch";
    })
    # incusd/device: Forbid guest root on restricted VM disk shares
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5f9bc490e5dd22b749edc3503983954edd2884ab.patch";
      hash = "sha256-dtJPZ8xbzx/vUK4B/oDI05+RPrJ8Evl6yuxojVOn+oE=";
      name = "GHSA-4375-qwr5-8vjj.4.patch";
    })
    # incusd/project: Forbid raw.idmap mapping onto container root in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a65b87c3381042bf91b2a6b370c0e6593342f540.patch";
      hash = "sha256-KvGeql13hpNiZazODruWK3TyF6Q4Bkv4NMnr8pK7h2M=";
      name = "GHSA-4375-qwr5-8vjj.5.patch";
    })
    # incusd/device: Treat a source as external ceph only without a pool
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/cb30f82ab49aff0ba51db1bcfbbdd53f9db897c5.patch";
      hash = "sha256-Y/1msYn2EE3X8jyqOJtZjKZcum62WfMTt7NiatnMiI0=";
      name = "GHSA-4375-qwr5-8vjj.6.patch";
    })
    # incusd: Don't let an image plant a liblxc config file
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b23a49ebb5b2d06d7e44bd834ed0ff2987d29c12.patch";
      hash = "sha256-jFoH8YLv8En8ssPhnvhj8Z6bbkfehknscRPXI65HIpw=";
      name = "GHSA-mmh3-jfjc-6vc2.1.patch";
    })
    # incusd/project: Fail closed when the checked profile or instance is gone
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8ecf92d5a13c9c87841531ce0f1ba6d47415ac94.patch";
      hash = "sha256-rMfKjFM8MCcCo3fMS8udwM2Kt8ItEVoifesJz9L9kmU=";
      name = "GHSA-mmh3-jfjc-6vc2.2.patch";
    })
    # incusd: Serialize instance rewrites on volume rename and profile update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1c60f9f52c4492fa2c9d9f95453fda3e7b2c9f98.patch";
      hash = "sha256-qubufQFC76J8T6oyPPiF2b6tP3u7tSuvS3nbOkpE0UM=";
      name = "GHSA-mmh3-jfjc-6vc2.3.patch";
    })
    # incusd/instance: Return a copy of the local config from Render
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e7e6def86b6c189b3c0d5ca4a05dd71322ac5790.patch";
      hash = "sha256-NcQSBhOvCowyAYZ+05CPRD91D/WyzFZcKmDuVn/uTxY=";
      name = "GHSA-5pf7-5wqc-rp52.1.patch";
    })
    # incusd: Check project restrictions after the move pool override
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4728ce2a2daf5bada1a85143fdceed2afdd1d812.patch";
      hash = "sha256-N6zsIG2xVeiWkj1go3Vz4kXh29lhcJyVhikAOhf3ClQ=";
      name = "GHSA-5pf7-5wqc-rp52.2.patch";
    })
    # incusd/project: Treat volatile.selinux.context as a restricted key
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4888d70e0cb5bf9d6738477937c99c3083c7f728.patch";
      hash = "sha256-aGlTxF6EqaJXnRyN2thIrATFwW0cusQmKtz5mXClLO0=";
      name = "GHSA-5pf7-5wqc-rp52.3.patch";
    })
    # incusd: Keep the imported root disk on the import pool
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1d0f96377d18f38c622243823880d1a0a5f58484.patch";
      hash = "sha256-RP1ai1CZt2fsf+L21o5QzQrLzJXP30KoACcmMBZQUlU=";
      name = "GHSA-5pf7-5wqc-rp52.4.patch";
    })
    # incusd/network/ovn: Validate pinned uplink addresses against the ranges
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/ea4218d0c54ab758d8b95776c8f68d0e8a9eca10.patch";
      hash = "sha256-fVF+hJhQUeetzlEN7LCcFBORYogpj9zOLDy+7Xa85C8=";
      name = "GHSA-5pf7-5wqc-rp52.5.patch";
    })
    # incusd/seccomp: Keep intercepted syscall strings NUL-terminated
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d91072dad789207d93c807384d44de72ee6fd923.patch";
      hash = "sha256-1s/lfUBWlJjc+QJULPhpcM+l+hxExpu0SLstAcG88Sw=";
      name = "GHSA-28m6-7v43-rr8m.5.patch";
    })
    # incusd/instance/qemu: Keep secrets out of the QMP log
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1fc0cc625b76948047920f68e007d3d8ecf7f0bb.patch";
      hash = "sha256-9i/RoogTd4MALut4385ktunWG1QhbgRN2iB6Bej3Q6k=";
      name = "GHSA-44g3-g988-46rg.1.patch";
    })
    # incusd/storage: Validate bucket key names and credentials
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b12046d5a8d49c46bde6c18e622a7985f6297237.patch";
      hash = "sha256-QKwg4V2av/OAZJUl3TPCbzIyI53lPj0fjnHIQ6fk7E8=";
      name = "GHSA-44g3-g988-46rg.2.patch";
    })
    # incusd/storage: Keep the pool config out of exports and migrations
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/722251e65e48da91e288d4abcae8c8f51aa194d6.patch";
      hash = "sha256-hKpBcGGyDdaokJWJ5skQUktv7qYi8DTqrtO17jmIl48=";
      name = "GHSA-44g3-g988-46rg.3.patch";
    })
    # incusd: Hide credentials in the server config from non-editors
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9c369d22df95d98581163bda2fd29d7bd836a738.patch";
      hash = "sha256-hPKcsFO7X4/FrNr7DK4J/A5CTuC/NnZfuF0wUa/+V3E=";
      name = "GHSA-44g3-g988-46rg.4.patch";
    })
    # incusd/db: Scope backup records to their owner
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/729b70a2f3677dbfb03abffb4fb48e36a8758411.patch";
      hash = "sha256-IdStBw/gqK5isfkeUDC4vIzoSE0pFQWPk3YGmiHumSc=";
      name = "GHSA-8m9x-vx2q-7f9q.1.patch";
    })
    # incusd: Validate instance and bucket backup names
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9efd61edd7800f001685fd3ff17b6d05462530f6.patch";
      hash = "sha256-bxrHswijTe/pqELSD/ZeckoDLsaH9xExGklTO0bmjHA=";
      name = "GHSA-8m9x-vx2q-7f9q.2.patch";
    })
    # incusd: Don't follow a symlinked exec output directory
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8caa454b5d678d25c329e27120f6046e429d7e6b.patch";
      hash = "sha256-mRVIQVBdScyFyky98IFRpaxwFQI+wjrof3OX/d3giH8=";
      name = "GHSA-8m9x-vx2q-7f9q.3.patch";
    })
    # incusd: Only serve custom volumes on the file and SFTP endpoints
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4aab94338e1235e2223ac6e19e9b9aad2a7fa0b3.patch";
      hash = "sha256-iEErtHnkvL7wHYKsI9dBK8RyK5zVzKjpjWsFTUXMD+c=";
      name = "GHSA-8m9x-vx2q-7f9q.4.patch";
    })
    # incusd: Serve the targeted member's volume on the file and SFTP endpoints
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0004c6d6aa19ba048890bc8baf65b92135ce7391.patch";
      hash = "sha256-npeiMuTIuCrXLNANZeFhjdDXOAwFZYdFm7eCEniFhvc=";
      name = "GHSA-8m9x-vx2q-7f9q.5.patch";
    })
    # incusd: Migrate the requested volume on a cross-member move
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d81225cad43bb4a5ca87d5873f32ae75d2f375ce.patch";
      hash = "sha256-vNHpHg6tqzzWt3Btx+v7RZGHRT3NCdu1gNquUa1vMj4=";
      name = "GHSA-8m9x-vx2q-7f9q.6.patch";
    })
    # incusd: Don't let restricted projects claim another project's volume as dependent
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/08269c3189968aafb602dd9ad2e235069919e2f0.patch";
      hash = "sha256-hVhtyeP0UGv9WC8c1Dh8SvYCr+F7+mw1/a0lbBFEweY=";
      name = "GHSA-8m9x-vx2q-7f9q.7.patch";
    })
    # incusd: Check the project's cluster groups on backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0d7c43649e11113784882ef5c0b8d951bf7f515e.patch";
      hash = "sha256-xiuhbjSGoWImbdkMTwx/NsyKFpuL80xC1l2+h5WlGcQ=";
      name = "GHSA-8m9x-vx2q-7f9q.8.patch";
    })
    # incusd: Check the project's cluster groups on volume and bucket placement
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1cb456420f0f02c37cb9e19296728f6ea79eb365.patch";
      hash = "sha256-/7UE14squ+h+332o5wlvP6s0gdAmYBDELvsZ+JsXPZE=";
      name = "GHSA-8m9x-vx2q-7f9q.9.patch";
    })
    # incusd: Refuse access to the volumes holding the daemon's data
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8f0a85f2548c34d390558fdbcd54a715d1e7ce45.patch";
      hash = "sha256-iQjcDWDMk4pIAh0wayy0GzM+XihhZ3pdtoXUeP+h2bk=";
      name = "GHSA-8m9x-vx2q-7f9q.10.patch";
    })
    # incusd: Require edit access on the target of a refresh
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/10b2f3be43d9caf6889c01fb920740af07ddaade.patch";
      hash = "sha256-JPnUwEDcXb/tXMSyHhkauOOGuYnviYl9j8nCLbec3Og=";
      name = "GHSA-8553-6xmq-7g3g.1.patch";
    })
    # incusd: Check image access when creating or rebuilding from a local image
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e4184a2be9a7741396dd7e0bd4ae044a18b49308.patch";
      hash = "sha256-uLnNS7/S7SG7XmxnJzrUER1sOjXfPyTyPOU+ZCSixI0=";
      name = "GHSA-8553-6xmq-7g3g.2.patch";
    })
    # incusd: Check access to profiles and volumes attached through an update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6131a67f25bac103232df20fe094799487c08694.patch";
      hash = "sha256-kcI9mNiHlRDjLYMw+OZ5FuVhG+XH3AEqGLnBR7B7Kus=";
      name = "GHSA-8553-6xmq-7g3g.3.patch";
    })
    # incusd: Require edit access to migrate a snapshot
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0cd02e6adfb0d8125e60e8ce33f051512e8795d5.patch";
      hash = "sha256-7V/Iz855Fj52cNTtuFhcSDhZO56qDNo9X0mlZLYqyHw=";
      name = "GHSA-8553-6xmq-7g3g.4.patch";
    })
    # incusd: Only restore an instance from its own snapshots
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/92ff6295f3631890f0304ad47e4bc82abffcfb0f.patch";
      hash = "sha256-y18KsR9PZMK/yYWl4iJquTs85Ue+TVNH37w9TqY8CBY=";
      name = "GHSA-8553-6xmq-7g3g.5.patch";
    })
    # incusd/images: Require edit access to rewrite an existing image on copy
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f93d1a24b77e0a38f3a2f5364764513499900dbb.patch";
      hash = "sha256-dEZakvNlo5mLG68A+bi5RxuRbgMLBZR5WhV3Rm6sbFk=";
      name = "GHSA-8553-6xmq-7g3g.6.patch";
    })
    # incusd/project: Keep container runtime state out of restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/50023941ef963782402c1ebf7a74a3378d79863f.patch";
      hash = "sha256-q/TQEYZY+ur8v1nVSozc9Hrbz2V242ZvLsJ2ft39ed8=";
      name = "GHSA-8553-6xmq-7g3g.7.patch";
    })
    # incusd/network/ovn: Only remove VLAN interfaces the network created
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4d793188f22ad4e3f5507d37beef66057a54da75.patch";
      hash = "sha256-1Ojhqdn2Dj6GuJJKUlMFiei0fC90xkaBenuRmPq0wWw=";
      name = "GHSA-fg2p-r659-c4q8.1.patch";
    })
    # incusd/device: Check the interface an instance hands back
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/25ddeff57a45234c2de04f161952e5e9509a990a.patch";
      hash = "sha256-drA4oEWvN/VhadnyYcb/R4NMZZlaRlSBaMTV/mgTqxo=";
      name = "GHSA-fg2p-r659-c4q8.2.patch";
    })
    # incusd/device: Count NICs on managed networks as VLAN interface users
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/827e185de6d20281718b43d3101eefd473c4c303.patch";
      hash = "sha256-WZjX5HC8dJYQpkfjwrkzliBs9wnEDq2F0p1sNpo1UXk=";
      name = "GHSA-fg2p-r659-c4q8.3.patch";
    })
    # incusd/device: Validate the NIC host_name option
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/610b85d51ea126ebf762bdea216b471ab2f4e79b.patch";
      hash = "sha256-pYt8r1KUEzj1+FCGQ263pgeIxZXFHevUQf2UzPiFPrs=";
      name = "GHSA-fg2p-r659-c4q8.4.patch";
    })
    # incusd/network/ovn: Forbid host interfaces and tunnels in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7cd8909f30e039c78eae1d46c4ceaf19b3d2256b.patch";
      hash = "sha256-7oMOzKMd5knVf5Ldby4x8tDQ+6etUdhqyf9BwmUPz+A=";
      name = "GHSA-fg2p-r659-c4q8.5.patch";
    })
    # incusd/network: Check restricted.networks.zones on network zone keys
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/43fa11cb11d8e849345c3613ccb3ff50804499d1.patch";
      hash = "sha256-DoIvjymfba5UQnsH+lKEajv4pc+zKNnrgO5g3tAuj+Q=";
      name = "GHSA-fg2p-r659-c4q8.6.patch";
    })
    # incusd/network: Keep long VLAN interface names unique per parent
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7815baf7930b19f6822b710d526d19e9e36de302.patch";
      hash = "sha256-4E4DV89bxozu+LzXTYJtoeCg4cRBXaiYSisE7EEizHM=";
      name = "GHSA-fg2p-r659-c4q8.7.patch";
    })
    # incusd/instance/qemu: Only mirror known UEFI variables file names
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a55d4b2c8229a20564d46641446b5801d6a47f6d.patch";
      hash = "sha256-diPX3Mw0GHk0P/Gi2mT49mUm7Snkv5ARIQ8kPLaSCps=";
      name = "GHSA-4375-qwr5-8vjj.7.patch";
    })
    # incusd/forknet: Enter the network namespace through init's pidfd
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3bc858291b0ada42f200d47607884da1630210a0.patch";
      hash = "sha256-lmed10rGh52SpR4lA0t4h6t5f/IEuiuFLaRR+m9bm24=";
      name = "GHSA-fg2p-r659-c4q8.8.patch";
    })
    # incusd/storage: Keep the full name on loaded bucket backups
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a17a3a29922ce6d27ab9556199f05ed252bad363.patch";
      hash = "sha256-fsi14I7Qtv45eZIdHSuaPuxTSnpHW5PWqlOjxUi5sRk=";
      name = "GHSA-8m9x-vx2q-7f9q.11.patch";
    })
    # incusd: Only reuse public images from other projects on refresh
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0581b5584dea8c2bfe1059aed486d0ba4890b839.patch";
      hash = "sha256-kRdmt4II5Eqr+162D6FhG7Zq0oovT4Su0nz3vk7uyzs=";
      name = "GHSA-4j59-4pqh-f3qm.1.patch";
    })
    # incusd: Give image upload tokens their own operation type
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0378aabeac850240eb1544749478dfa9ee74c2db.patch";
      hash = "sha256-SdFYVLakE4/nivB87HtPwjCIvINLVtE3RefZBmfiw08=";
      name = "GHSA-4j59-4pqh-f3qm.2.patch";
    })
    # incusd: Limit image token callers to the raw upload
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2b81c0757a6a098cdbe85a90df05c108d1d4f4c7.patch";
      hash = "sha256-VV6u3ERTByH4BNyZbM2yWGzo4Apn/0mwZrz44Pfnwu4=";
      name = "GHSA-4j59-4pqh-f3qm.3.patch";
    })
    # incusd: Never replace stored image files on upload
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/418d88e1a2bf6ce1ac279e489b09dcd09e2b766d.patch";
      hash = "sha256-x29x0t7LjcS2FRmyWOXibiepWgb6r5E/T9Nt0f0KsCY=";
      name = "GHSA-4j59-4pqh-f3qm.4.patch";
    })
    # incusd: Remove replaced image volumes only once unreferenced
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6714a95bed3647146b72c8a55309c19a6ed7c2bb.patch";
      hash = "sha256-/trBEn6W33n+o14cUU/mOieydGg0WL70uSE0uhjvo8c=";
      name = "GHSA-4j59-4pqh-f3qm.5.patch";
    })
    # client/oci: Fingerprint the manifest and pin the copy to it
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1f3b2372413d5ecb441c210c500a44f817c2f965.patch";
      hash = "sha256-touQIDHNuli6iUhMMpcLAGLBHHtTpO+CCxB7z3lbX2c=";
      name = "GHSA-4j59-4pqh-f3qm.6.patch";
    })
    # incusd: Store downloaded images under the hash of their content
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/07e1a22c88bce2e486c0e48c7393cb1503e5dc6a.patch";
      hash = "sha256-9Y55dxoS1ABVQA+vsNW8gGRObXBSvMf33TnrUAQuJAk=";
      name = "GHSA-4j59-4pqh-f3qm.7.patch";
    })
    # tests: Expect image volumes to stay while a project uses the image
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1c244fa3c21d4c14974605cb4e276a9b2d0b1ba2.patch";
      hash = "sha256-GrH+Ji2I1vSjC3yS6laZuMbgDijBbjR77RVsmIQ1fFM=";
    })
    # tests: Skip DAD on the peering host address
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/63a6c21becd5661ade9c9c19748dc4551da11c67.patch";
      hash = "sha256-UhJZU7YIb2pfCEeBlI9HzEGAuVpRWTyRDLaFvHwmDNY=";
    })
    # incusd/network: Check the client ID length when parsing leases
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/075b0944f6a7a4b234e68b59efe07bf1b43280a6.patch";
      hash = "sha256-qzGjrpdY/K/GwxIJlSaGIQHQMDRNMnOK9OjdjrvjHoc=";
      name = "GHSA-v855-hxm9-5pwg.1.patch";
    })
    # incusd/images: Use the reused image's fingerprint on transfer
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/61a7d88757f1bb2dd4b27b1a9327d69fd0867b11.patch";
      hash = "sha256-V2cBd9yhqQUo9L02Heg+syFycb7Ig6fzQqoUv2fwX60=";
      name = "GHSA-v855-hxm9-5pwg.2.patch";
    })
    # incusd/operations: Read the run hook under the lock
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b5610d00cd163c92236071a4b097f932a630f7d9.patch";
      hash = "sha256-Xx7WWMBHtqjEo2jATMCWFSGi1byAr7kAqYVGobv5qc4=";
      name = "GHSA-v855-hxm9-5pwg.3.patch";
    })
    # incusd/db: Give every loaded instance a config map
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b68464b58c07d0a9164a4b656e1933d86069a97c.patch";
      hash = "sha256-Fhk29QbKIn7b2kki0rVCDbZ0RuZ1JBQBGExaBit7hK8=";
      name = "GHSA-v855-hxm9-5pwg.4.patch";
    })
    # incusd: Reject template entries without a definition
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/bd894dee34ffc2316ac2499ece65079e31b2c4a7.patch";
      hash = "sha256-maoZrQminxxOelrmgMKOsx3w44soLf5Pyhd9LtlxQFU=";
      name = "GHSA-v855-hxm9-5pwg.5.patch";
    })
    # incusd/images: Create the properties map when the metadata has none
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/58123540f5e2b1bf90e1e63765c1482e608a6926.patch";
      hash = "sha256-43cjOzziTMbw3Tnas/O7vLsgT1FQCy95dAFlVXO246s=";
      name = "GHSA-v855-hxm9-5pwg.6.patch";
    })
    # incusd: Create the expanded config map on backup import
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7c0980522035a39715ba48f29efae5dcd7b6aec7.patch";
      hash = "sha256-WD3MvXm0EYMYgvMw4aPmfZkbdOR+Ai26yQnJhSrkYas=";
      name = "GHSA-v855-hxm9-5pwg.7.patch";
    })
    # incusd/instance/qemu: Copy the recorded instance state on read
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f92db161b9733cb654e17eaca1a5fe415e70ad92.patch";
      hash = "sha256-rBGHpu9Tb2SaqT7kaEj2TYfVZ2opS6B2PDB87Eo7nnI=";
      name = "GHSA-v855-hxm9-5pwg.8.patch";
    })
    # shared/ws: Stop reading a websocket once a read failed
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/815cf6d85d59f1419af2abc92d87b5160b3254e2.patch";
      hash = "sha256-70GgPEyx/AXO6cu4WkiVGFDu1UmocHG5Dslu37mKHps=";
      name = "GHSA-v855-hxm9-5pwg.9.patch";
    })
    # shared/uefi: Refuse a variable without data
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/74f7385ac85519f832500f220afc9f202c624617.patch";
      hash = "sha256-hXVxxJakqxYtYt2xGbO7yS6rnj/yneW7o5mrg+zr2CA=";
      name = "GHSA-v855-hxm9-5pwg.10.patch";
    })
    # incusd: Validate the syscall allow and deny lists
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e437a84475484e27c0aabaa2185d3a6c297b1222.patch";
      hash = "sha256-Rkr8m9QfLX3e0rMFd3fCyIh1xoTCxhJA0LWkSYarFL4=";
      name = "GHSA-mmh3-jfjc-6vc2.4.patch";
    })
    # incusd: Forbid backup upload targets in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e63b43893e18a384eb4df4153e2ef0fa3832d5c3.patch";
      hash = "sha256-M3PYmIfiekvCiDzaCEEW4dmnagBVUXb7Qwyo3CiGyng=";
      name = "GHSA-chhj-pwx6-9cx3.2.patch";
    })
    # incusd/images: Check the export target against the project's image servers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2bfaf0893962da6bc23e422388e932f342c127e2.patch";
      hash = "sha256-fgzHAxhErqUnPrXXv2TfueWd+6+Tx5poR+RWLLJNP9g=";
      name = "GHSA-chhj-pwx6-9cx3.3.patch";
    })
    # incusd/firewall: Drop unwanted frames before the bridge filter accepts
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/97171a0c106366b7ec12b7f192c4a12c808787c5.patch";
      hash = "sha256-1A7Qnwf/XY3hoi5APuq47K2NJmX3Tr8G6A9PTyGDjMM=";
      name = "GHSA-fg2p-r659-c4q8.9.patch";
    })
    # incusd/network: Only trust neighbor addresses within the bridge subnets
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/74098d1141984fc710b456aa7260fa6f40fa6a07.patch";
      hash = "sha256-gEdvssKrCwTMGFtBCZgBSUgU7kobCNX8XyeQ5oQtJR4=";
      name = "GHSA-fg2p-r659-c4q8.10.patch";
    })
    # incusd/forknet: Ignore DHCP domain names that can't fit on one line
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0c36b189f558f2d7e4eacd37b78379ba7c0e8a29.patch";
      hash = "sha256-d3fQbUyO28aSyEGsTnaWHlatDT73MBPqO+Gyhj2G60s=";
      name = "GHSA-fg2p-r659-c4q8.11.patch";
    })
    # incusd: Validate volatile hardware addresses
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/372ee119a6ac062f56ad0605ad56c804a2bed0c8.patch";
      hash = "sha256-8gRqHYDLqDMMSZPAwqOdH+vh8mJVnvUJCGIhh5Z18w0=";
      name = "GHSA-mmh3-jfjc-6vc2.5.patch";
    })
    # incusd/network: Keep instances from claiming other instances' DNS names
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5b6354a242affdf2c9eba4e38ecb5a663296953f.patch";
      hash = "sha256-gQ9sqG9aY0PjrWAPmfLLqXrA8ucwoBmOfu8UVZ+vAG4=";
      name = "GHSA-fg2p-r659-c4q8.12.patch";
    })
    # incusd/network/zone: Keep zone inputs to a single zone file line
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7fb457bbb2c273633c558e33878e8687263e0d21.patch";
      hash = "sha256-SoX71C3ZejRN5yA6xTYXqmqcia14VK9jOqwI3J6UoGw=";
      name = "GHSA-fg2p-r659-c4q8.13.patch";
    })
    # incusd: Contact the image server outside of the database transaction
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e64b9418c33a162e07b6329ac7d1d650e8b9b2c3.patch";
      hash = "sha256-lhKYW7tTUpfZt8WfQUeqxobw3vdCgIaRFRpHJDYRH+U=";
      name = "GHSA-v855-hxm9-5pwg.11.patch";
    })
    # incusd/project: Reject a negative limits.processes in the aggregate check
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/23c12941599c4fb991e07163df3a819ef1a85556.patch";
      hash = "sha256-9rWuTzA3ZKKTuWQPtR4BllFD2VIK2+rm4gj7psUraHw=";
      name = "GHSA-9pvj-5r2h-r873.1.patch";
    })
    # incusd/project: Refuse overflowing aggregate limit totals
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/25d2a16fc86efd8e3d03323ca260d102de06a3f6.patch";
      hash = "sha256-zi3I/SCi+gOP0IkUl2MYRg/DU9R+K1z/d5kNN7PxQGU=";
      name = "GHSA-9pvj-5r2h-r873.2.patch";
    })
    # incusd/project: Treat a zero disk size as unset in the aggregate check
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d4e107f949d6996435cfac267030943ba0dd403c.patch";
      hash = "sha256-y509OfHM9pcsd53KRKrlQ45IzhZQHIx6p/krXPicQNA=";
      name = "GHSA-9pvj-5r2h-r873.3.patch";
    })
    # incusd/project: Count stored images against limits.disk
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a9ede7a84ed19ae76e3f9ed06ccba6582531934e.patch";
      hash = "sha256-wH27njexTw1CHEzeLw5dFT4gjERQKYvV4CzApDtuYZk=";
      name = "GHSA-9pvj-5r2h-r873.4.patch";
    })
    # incusd/images: Apply the project disk budget on image refresh
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c6825b031fcfeffca2b2b854e473af66b63f70c2.patch";
      hash = "sha256-DngQ/FdiUjZqPuz/JERiroe5VU//qetBdISn2efLgnA=";
      name = "GHSA-9pvj-5r2h-r873.5.patch";
    })
    # incusd: Read the file path from the URL only
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/26a2c091e534cd8a5c1d4e58f3b7f79affec5c31.patch";
      hash = "sha256-jWlX5YhxFwnW4Y5dWTm9kPuuS/N6Y5k5owA+cxYJ9uU=";
      name = "GHSA-8m9x-vx2q-7f9q.12.patch";
    })
    # incusd/instance: Re-check project limits when recording an update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/fb8e482cddc1521edd15b0c0d3c191a8fb87ca2d.patch";
      hash = "sha256-ZYGMRTHvI1qX7ItLlRhoDzVGfiu5t3MIrwisQYsKgeM=";
      name = "GHSA-9pvj-5r2h-r873.6.patch";
    })
    # incusd/storage: Bound a backup's block image to the volume size
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3f09ab430fb0dadc4f02071df46142ad946866f3.patch";
      hash = "sha256-5kTPMBo0BS1vtvXabpJGUscmqSwc1+s9rSUFo8HY4Bc=";
      name = "GHSA-9pvj-5r2h-r873.7.patch";
    })
    # incusd/storage: Bound a unified VM image's content to the volume size
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c2bdcd0d858e1973a9e9a0baa47de8bca4d9b20f.patch";
      hash = "sha256-MDmNSY0N8UdwZ8rVRdvgo4yYoQp8xjnpd6WGjaINIwc=";
      name = "GHSA-9pvj-5r2h-r873.8.patch";
    })
    # incusd/backup: Hold stored backups and squashfs conversion to the disk budget
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3e484ab22e07efcaf996078f4a0a56d03575f366.patch";
      hash = "sha256-e2FXW3KCf6EcS+CZlh30Nty9y5Q1jtLXcBL/nbhjdgU=";
      name = "GHSA-9pvj-5r2h-r873.9.patch";
    })
    # incusd/profiles: Validate changed devices against instances before saving
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5f85d409228df97da9b9413150abc90f58084782.patch";
      hash = "sha256-tw44OB31mTKmfnIUW4h6zpEPGolZ3HCbartMe7ZIJ6o=";
      name = "GHSA-9pvj-5r2h-r873.10.patch";
    })
    # incusd/instance/qemu: Bound the agent upgrade handshake
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f220b214ac80c66e49cfc1dac068010c46a52da6.patch";
      hash = "sha256-i/xGq+vAxnCsDbjy+mukJQwD7jGYAQnhyN+dwi6heVE=";
      name = "GHSA-23fc-ggg4-5r2r.1.patch";
    })
    # incusd/guestapi: Limit request body size
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/35ef104b4a2d20ba4b9da39f9e3504c9f4d43001.patch";
      hash = "sha256-8Jmcvp4N9WFpUNMXO/uz0WKKNAoqDfzdFsGDWZRF7Cs=";
      name = "GHSA-23fc-ggg4-5r2r.2.patch";
    })
    # incusd/guestapi: Bound the command line read when finding the caller
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b8feedc81f184c8e0faff4a0f5c8a7742d7f59b2.patch";
      hash = "sha256-62hzq2GP1JNTV7mb6aX8512tjqWSHBnAgV87D/QSoOo=";
      name = "GHSA-23fc-ggg4-5r2r.3.patch";
    })
    # incusd/netutils: Bound the number of interfaces and addresses collected
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d179e95e942c7ba40fb70e96018400c59253313e.patch";
      hash = "sha256-JfKk5Oy1BS8wviAVXCwOey1wcn5ZHdGetPozG1gJwZA=";
      name = "GHSA-23fc-ggg4-5r2r.4.patch";
    })
    # incusd/util: Stop following redirects after ten hops
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7569cda48f8006cbbd88246f3d4874faaf41e361.patch";
      hash = "sha256-L3TEC2GHqFVO/UIQKHalOf6dv71otSMrhh1C3CEV2fE=";
      name = "GHSA-v855-hxm9-5pwg.12.patch";
    })
    # incusd: Bound directory listings on the file API
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d4aa2e9f1e5ea1a8d635fb83110ff3f32aa7c87e.patch";
      hash = "sha256-GLLHkAsc7Vxh+9cH+0wexJH8f1Ny8o4jtP5tlx4hs+8=";
      name = "GHSA-v855-hxm9-5pwg.13.patch";
    })
    # incusd/backup: Bound the upload target's responses and stalls
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/133caa77eab2547df840f918c9e27c6b21f2a219.patch";
      hash = "sha256-GPE8oRrfWq516/Tdxn4Hf95o+exK2oL87dpSlRdJAHQ=";
      name = "GHSA-3jgx-fpg2-x499.1.patch";
    })
    # incusd/images: Stream split publish files through the hash
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f73fbc53367a19365b99ed0476ce1447cbe70d42.patch";
      hash = "sha256-s2BpJWgh7LbRcDiJFzUMjsXsQL+wNR3tGKsAMK/Wxr4=";
      name = "GHSA-4j59-4pqh-f3qm.8.patch";
    })
    # incusd/apparmor: Bound the qemu-img output kept in memory
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f5563d0e5976783af9842a59dc964a5b1d0e6337.patch";
      hash = "sha256-C5wxJsi9zMr37xWMGyPFB+LVd5E0fesAMOTRVscCeM0=";
      name = "GHSA-v855-hxm9-5pwg.14.patch";
    })
    # shared/archive: Limit xz decompression memory
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b46427bd2b963f60212a1c2c09a5d5df30490b08.patch";
      hash = "sha256-HU5ijhRSAiBNhQiognSyqHvjvwSikS0oSR8Ugrvwki0=";
      name = "GHSA-v855-hxm9-5pwg.15.patch";
    })
    # shared: Bound CPU and NUMA set expansion
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f95ae12a2e26e68dc44d2fb8d5520794598ccd95.patch";
      hash = "sha256-X+nm4o7230KMo5Ls0sKfSPEbVXwgSYS7GQybjkxZa80=";
      name = "GHSA-v855-hxm9-5pwg.16.patch";
    })
    # incusd/device: Bound VLAN list expansion
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/34ab18a689e55017590a99b5990f4e765f886a54.patch";
      hash = "sha256-hfaglhc3re2Sr0zg+AmKBOLUEw/b1Gyc1RmTX1Ahjjk=";
      name = "GHSA-v855-hxm9-5pwg.17.patch";
    })
    # incusd/network: Bound port range expansion
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/1281cd04c4e47a577186a3cd459ad6b17ca3f588.patch";
      hash = "sha256-Soq2pv0kFYbIOG1n23ETO3sjp0/Rr7C3BW2FyruO+7s=";
      name = "GHSA-v855-hxm9-5pwg.18.patch";
    })
    # incusd/images: Expire and bound image tokens
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f73f1591fa33ce2331b008fc5355f36290be88ac.patch";
      hash = "sha256-DlYeVTCIqLcBI+HRkg2pRt2w6zgo6/npnamvRs+9bjs=";
      name = "GHSA-4j59-4pqh-f3qm.9.patch";
    })
    # client/oci: Check the unpacked size against the image budget
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/406699c9f15a503472ab47e0319a35241bc0d8c2.patch";
      hash = "sha256-CM6U3KpFJsKFIkBkSZFyGWN2NsJJoCxXiQYcD5cB56Y=";
      name = "GHSA-9pvj-5r2h-r873.11.patch";
    })
    # incusd: Filter network integration used_by by what the caller may view
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a486e8f842b7b238244f842a7319ec34de6f39a5.patch";
      hash = "sha256-mP1EDeomKgGTqGMAcm1347xcJJbiGrZ2I6sYDp3YpCU=";
      name = "GHSA-44g3-g988-46rg.5.patch";
    })
    # incusd: Filter network ACL and cluster group used_by by what the caller may view
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f1180a23b28e9ed8b89d15b7a5b7dabaea142112.patch";
      hash = "sha256-hO7gZrxiLXZVanNIJyiVtjXUs+5c9LhBDTQqBgmI2Cg=";
      name = "GHSA-44g3-g988-46rg.6.patch";
    })
    # incusd: Judge all-projects network listings by the caller's projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/873e0c49a38fd74df7d9074c204bbce24fc75f01.patch";
      hash = "sha256-7kX7LEyckHi03jpoBoCflx4laKSRbj6Q6YADy04A+3Q=";
      name = "GHSA-44g3-g988-46rg.7.patch";
    })
    # incusd: Keep other projects' instances out of profile update errors
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/db663921298ab559a125d79631680ae9906023ae.patch";
      hash = "sha256-1dP/uF+x/jj+HVDU9TzfVSuDv9SIe/uftPdAZETCTAw=";
      name = "GHSA-44g3-g988-46rg.8.patch";
    })
    # incusd: Apply profile patches on every cluster member
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/aee3a342bde31344be0b45bd8be148277e069a41.patch";
      hash = "sha256-W5HNHtNHf84ZJbTZZcDpF9wVfQN51qwwTNtZ9r+bksc=";
      name = "GHSA-fg2p-r659-c4q8.14.patch";
    })
    # incusd/storage: Remove a bucket's backups with the bucket
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8443aa3d0867439e32427d29b97bbc3e7a285bdf.patch";
      hash = "sha256-827yZsfbc2DfSlz//6AnW2YhyLFGl/WxKWfoX5darUo=";
      name = "GHSA-8m9x-vx2q-7f9q.13.patch";
    })
    # incusd/network/ovn: Keep a forward whose address an instance NIC still uses
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c266736183993babc66bcfa0133019c4fcb17527.patch";
      hash = "sha256-mJU2u7PCF/J3Eycd/V1yIOwZicMLSk6bcxM9XOB7J14=";
      name = "GHSA-fg2p-r659-c4q8.15.patch";
    })
    # incusd/network/ovn: Skip addresses in use by forwards when allocating uplink IPs
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/6dbbb972e07fda5efbcd4d9af913fce26a50c2c0.patch";
      hash = "sha256-Qm3V255xETPTdkcFX3/HLXPj30Acxzlyrzf0iwEJWmg=";
      name = "GHSA-fg2p-r659-c4q8.16.patch";
    })
    # incusd: Name automatic volume snapshots from the volume's own snapshots
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f74e37edf91c7d7326764033371d1a7965633bba.patch";
      hash = "sha256-M04lQ/bh+ANMYLYCoUH/gvetmhmdG256tuCrCNnyb8U=";
      name = "GHSA-8m9x-vx2q-7f9q.14.patch";
    })
    # incusd/device/nic_bridged: Only count running instances of other projects as conflicts
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/806b7cc4210be1a2144a17997cfccd587a9a91c9.patch";
      hash = "sha256-d6k5isNUkA9cMIAwNihmG+c0B//IiR7HRek1J+wpBfU=";
      name = "GHSA-fg2p-r659-c4q8.17.patch";
    })
    # incusd/instance/lxc: Give exec a real file for every unused stream
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/447227b3a3343edac7370dfb9c4071f907d27fa0.patch";
      hash = "sha256-OWY+3F3rXfTUS4nRVj/0nV2CAgWifW8oNEKWTLgM/IM=";
      name = "GHSA-44g3-g988-46rg.9.patch";
    })
    # incusd/forkexec: Take the environment from a pipe rather than the command line
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2828f121cf0fcbdc409cc317b0ce5122a8b36acc.patch";
      hash = "sha256-3YpspQMSEn3vOXb9zlncpQO/COSKiYytyTpPNc0f2Sw=";
      name = "GHSA-44g3-g988-46rg.10.patch";
    })
    # incusd/network/acl: Resolve the ACL project per NIC rather than per instance
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f3695e75645f6d4448aba5d8495ada9e84cac0e0.patch";
      hash = "sha256-/BAiTu1FW/fpEb2wldp9nTyGTTTKoNFhVJtIsGR5PQk=";
      name = "GHSA-fg2p-r659-c4q8.18.patch";
    })
    # incusd/network/acl: Track bridged NICs that name their bridge as parent
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3d09ab2d3ce461a6ac535798fc481e76fdd30b0e.patch";
      hash = "sha256-PZme/6lOCCbAk5nQz+Ga4u56m6vnALCzEX6+7gP1rv8=";
      name = "GHSA-fg2p-r659-c4q8.19.patch";
    })
    # shared/validate: Check security tag duplicates with a map
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/91e4fff467f02bc0f22297f74a3c4fd9f1772145.patch";
      hash = "sha256-UBjzquoUX+9Ym4YZSCfnFfbQnfXGqsvWaPP2atLpNx8=";
      name = "GHSA-v855-hxm9-5pwg.19.patch";
    })
    # incusd: Fail a volume migration on an unexpected control message
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f130849c68f3c3e9fee0eea4a2c6c76006a6e78e.patch";
      hash = "sha256-kVCgTAKgGnWbciGJzUDk7MsH8092IA+ewxowAwLiN3M=";
      name = "GHSA-v855-hxm9-5pwg.20.patch";
    })
    # shared/osarch: Bound the OS release file reads
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/789db9211d601f537f6799f9f53379b261054fb6.patch";
      hash = "sha256-rJ5fWYcQtYV4/rESep7mukwwBlPcfpJEOLFBRRsKXGw=";
      name = "GHSA-23fc-ggg4-5r2r.5.patch";
    })
    # shared/archive: Bound the captured error output
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8bd46759d8e2645d8d245ef26aa04f9ce9c16791.patch";
      hash = "sha256-SR4G2gvI9XeW0kqab6n1LUIDQHzYj8gngIOY/R3Qo5k=";
      name = "GHSA-3jgx-fpg2-x499.2.patch";
    })
    # incusd/rsync: Bound the captured rsync output
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5badd142c66c73f0a1abc5f8bcac95583de21dc4.patch";
      hash = "sha256-73+zqK1afiolTROOD4Lm+l/Fq6srWPFNhcK9wP65nJY=";
      name = "GHSA-23fc-ggg4-5r2r.6.patch";
    })
    # incusd/instance/qemu: Bound the VM console log
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/93c472580953b33a8c8618b9c03232cad6b5c00d.patch";
      hash = "sha256-hQ4C8YH1Bz47jewFb7t9qifkYAJqSYYbSiq0ikode6M=";
      name = "GHSA-23fc-ggg4-5r2r.7.patch";
    })
    # client: Bound the messages read on ping-only websockets
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8e0b2b976560471f615c5b54dc9b5e643a58b849.patch";
      hash = "sha256-rrBnjzN6h1LCgDnKXgv2tP6if94lfM1CPpibfP6pPDA=";
      name = "GHSA-3jgx-fpg2-x499.3.patch";
    })
    # client: Bound the responses read from untrusted servers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/dd7481892fcabbb899dbe4dd8c2c5f58972ac9fa.patch";
      hash = "sha256-V0aLPsSEVTeBBs0XjgC7xo+Z70G4MECGUBd2p0eKMKg=";
      name = "GHSA-3jgx-fpg2-x499.4.patch";
    })
    # incusd/instancewriter: Bound the hard link map
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0ce6faa788526ef254aa1dc3e6c6b79c1f8ccded.patch";
      hash = "sha256-n+NbQzYk85pOAvmTPhQSuwgAEuOAnQHS4kOlFTrQuSs=";
      name = "GHSA-23fc-ggg4-5r2r.8.patch";
    })
    # incusd: Only cache metrics for existing projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2f52bb18a004b37aafce507838473c9456f81651.patch";
      hash = "sha256-PEEr2H7KvIOtV9aplsFri4fOAlog421bsm9hUvnF5ZE=";
      name = "GHSA-v855-hxm9-5pwg.21.patch";
    })
    # incusd/filter: Bound the size of filter regular expressions
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/40116a142277243c1db89e6aca17da70d3c8fe1d.patch";
      hash = "sha256-2OF4NFvUPREj9n3ops4F/nSLvqN8Q/sFCalNoIS5GpA=";
      name = "GHSA-v855-hxm9-5pwg.22.patch";
    })
    # incusd/util: Harden template rendering
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/66cc69c2b31705bb9acb7e15732ccef8276a8ae2.patch";
      hash = "sha256-ZWWlP/1QHog605TrYZbVo75uRuwXEoLxByT6U1lSTeE=";
      name = "GHSA-v855-hxm9-5pwg.23.patch";
    })
    # incusd/instance/qemu: Bound the QMP log
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/873c9cbde0bccfcf47a16c29c22982dc8b7c758a.patch";
      hash = "sha256-nB1yt5zIyXIHRg6RzFPtr1WJQLaHThbBK9dO8kzZnhc=";
      name = "GHSA-v855-hxm9-5pwg.24.patch";
    })
    # incusd: Only send the snapshots the source offered
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d2c899a46cc8a3dd77e1f9048426c7f3633d84ab.patch";
      hash = "sha256-awxqtQEx+pr9dQkMpSxo4iRzDyrZo5RFdCGC9MXBfdo=";
      name = "GHSA-42x8-664j-84w8.11.patch";
    })
    # incusd/project: Check restrictions on snapshots received through copy and migration
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/549fc9e0f303cfe03613f58709c442f926b5951a.patch";
      hash = "sha256-3wgubOTmz2KYM3ZJFJ92nmTsQXHzg5ghl33HO+KLCNQ=";
      name = "GHSA-5pf7-5wqc-rp52.6.patch";
    })
    # incusd: Bound reads of files supplied by images and backups
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/575229a1871115a06ff8be154ba24af8c1594dd5.patch";
      hash = "sha256-7ETTDceLRrgGXMeT7BxSvnsEBaJvf7pBTuvu3qm7Jio=";
      name = "GHSA-42x8-664j-84w8.12.patch";
    })
    # incusd/instance/lxc: Only stop the DHCP helper of the instance
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a7c0c01a3ed5d16a4ffe123f117cb1d796ec4f46.patch";
      hash = "sha256-a3fVhWMsEPQevVITZBKtBL44MUygmZBP7TlaP6evhlY=";
      name = "GHSA-28m6-7v43-rr8m.6.patch";
    })
    # incusd/events: Keep server-wide events to privileged viewers
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/aa51ca494daf92a361073ad849864436074c1d09.patch";
      hash = "sha256-oQxzoJZKUKwSEb9RIzyekvOIa2u45MbhD+kcj8p9Uig=";
      name = "GHSA-44g3-g988-46rg.11.patch";
    })
    # incusd: Keep balancing CPUs when one instance has an invalid CPU set
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f9389a6d9606740ad04813a12ab04d332450e79f.patch";
      hash = "sha256-7pdH2DI5NUeld9RXGdmSc/b6CXUB2Nyjo9P60KSwOtM=";
      name = "GHSA-v855-hxm9-5pwg.25.patch";
    })
    # incusd/endpoints: Let the kernel pick the vsock port
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/89c703269f75326ce85108388f4773251b022975.patch";
      hash = "sha256-7UPSMWa3oqhFh9/wSCM2G6X/1+fl41EnaOT6tJib82I=";
      name = "GHSA-23fc-ggg4-5r2r.9.patch";
    })
    # incusd: Don't make instance hooks wait for autostart to finish
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f3651af9fc1e5b0e4d2c4e47cba9576d40e99acc.patch";
      hash = "sha256-NyOjdtII9CS7lfqKVhjvPGdOsSLPdSloj5tZbrsHWKc=";
      name = "GHSA-v855-hxm9-5pwg.26.patch";
    })
    # incusd/endpoints: Keep accepting on the local socket after a failed accept
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/ab843acf8f502fcbf5a809b9fa21b86fded63a96.patch";
      hash = "sha256-7ju7l4IMT8ZdaH9nZWJA+bDAb84S0p6kp+2rhzCK3aw=";
      name = "GHSA-v855-hxm9-5pwg.27.patch";
    })
    # incusd: Read the network creation request before taking the lock
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/05f50501f3161ef99949e623e51c854d091ffc67.patch";
      hash = "sha256-Ca+WzPjU6sxllyv0w89Y+fBQJu5Z8HIxvPJASRxBHQ0=";
      name = "GHSA-v855-hxm9-5pwg.28.patch";
    })
    # shared/idmap: Bound the number of entries in a textual ID map
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f2a7c07e3ae5ccb9a0c6be100f60134ec48fdd9a.patch";
      hash = "sha256-WYHAoQmO/4SdUzKp4iZAANv+NeavqkqRshb3oiUxBvQ=";
      name = "GHSA-v855-hxm9-5pwg.29.patch";
    })
    # incusd/instance/qemu: Bound the TCP agent probe
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/9892c4d5ccaab6da5ffad1c12d7d72a86f5e2381.patch";
      hash = "sha256-qoj5bcFPNQFd4vfB4+lEXCnlRptAAZW8p8G0M6dS56s=";
      name = "GHSA-23fc-ggg4-5r2r.10.patch";
    })
    # incusd: Refuse dates the database can't read back
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7acaac1b08f98e9ef5277990b473f69494bb0738.patch";
      hash = "sha256-fujv6NDJiwjWnMIUmerc4di9e5yGKIsXtd4m2j7wu9w=";
      name = "GHSA-v855-hxm9-5pwg.30.patch";
    })
    # incusd: Start without a device monitor when none can be created
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8f43c43562558ca08563d93075db9a4d8998abda.patch";
      hash = "sha256-oQWY1qZ8d9gMuTdXBRRl0fmxHltfGRiHstHmHCBzKjg=";
      name = "GHSA-v855-hxm9-5pwg.31.patch";
    })
    # incusd/instance/lxc: Bound the wait for forkfile to stop
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/93ab406bb81f262bb4b674273745942c082812dd.patch";
      hash = "sha256-HzERUSL9Mgnf4GHM03gQJUbxDEoLGHcEB0i+9hpSW60=";
      name = "GHSA-23fc-ggg4-5r2r.11.patch";
    })
    # incusd: Match profile filters outside the database transaction
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/adcec079181fb4872bd56aa8f1b4550836cabb79.patch";
      hash = "sha256-A+ZXfdoMigrIy/OzOP5qHrLi/1LG23xInufKKx6y2Co=";
      name = "GHSA-v855-hxm9-5pwg.32.patch";
    })
    # incusd: Keep one tenant's snapshots from blocking everyone else's
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/8b7b709e28522cd677a11e634dd2d1ab13a782cb.patch";
      hash = "sha256-JKagWCG9ZALZ3rtMT5whDID4zK1eO0lPTIHvkA5UGQQ=";
      name = "GHSA-v855-hxm9-5pwg.33.patch";
    })
    # incusd: Don't hold the publish lock during the instance export
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/be831719c3410bc9a8d2de04c6483a70465e8669.patch";
      hash = "sha256-FR6Jd+bK5gRCoplxqMfUoNF4R+Psi0h5XHyakVfwgys=";
      name = "GHSA-v855-hxm9-5pwg.34.patch";
    })
    # incusd: Cancel an image download that stops receiving data
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/875988970023796aae6681e190204256026ba69e.patch";
      hash = "sha256-W/s7L7Uhqo1Zhvo7ywAxd+qwtLbnoWw5U6nOEzgnuE8=";
      name = "GHSA-3jgx-fpg2-x499.5.patch";
    })
    # incusd: Check trust token expiry for remote operations
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2650b2b652c48b06e2b9c3c063ba2059e98a5a19.patch";
      hash = "sha256-n4Kwl12v6cbwWRL3dWCn1QqZRTJB+YHEAFCk0WwNOBA=";
      name = "GHSA-9m5m-cr24-m367.9.patch";
    })
    # incusd/cluster: Give joined members the cluster CA symlink
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d2d27816b6463178b8700473ffca9f39f938c78a.patch";
      hash = "sha256-SBJ1/EEf4QVQkc8akExLAV/iQ8qV06rPaS2jt7GOioM=";
      name = "GHSA-9m5m-cr24-m367.10.patch";
    })
    # incusd: Keep the CA and CRL across server certificate updates
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/a61e705321bd1464c0677be516bd71e201b6dc03.patch";
      hash = "sha256-5jpvJK2gqrqXRHYzDm/Ga+VYRrpl/5EnEZTmAJhl+GQ=";
      name = "GHSA-9m5m-cr24-m367.11.patch";
    })
    # incusd: Require console access to read the console log
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5446de6c73fe267ba4e078a22bce18b29256f322.patch";
      hash = "sha256-khthIC4nsjzh/UkO8ZDbcKsgi7tpgOuU/KdSeT3D9vg=";
      name = "GHSA-8553-6xmq-7g3g.8.patch";
    })
    # incusd: Reload the trust cache when a project is deleted or renamed
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/84141421e2850e25a4da499a6db1ec900442ea3b.patch";
      hash = "sha256-y6eVJD2FrQ5+a+If3CXUPjC1+ht4uxzkUJfyQJkf3N0=";
      name = "GHSA-9m5m-cr24-m367.12.patch";
    })
    # incusd: Re-read the certificate record after the update body
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7d4f329192fb72e82f49d06184cbcd51bf672b94.patch";
      hash = "sha256-PZcG6NWWCDmpgogKE4vcVinTnC1acGW694J/ljEPDX0=";
      name = "GHSA-9m5m-cr24-m367.13.patch";
    })
    # incusd: Close the connections of a certificate that lost trust
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2f1f041b114136e33ab491e022a4b251fb974b45.patch";
      hash = "sha256-PB3EWsUdk1i3Rsr62y5UXng99XRS3KHtfM93ZFEBtzw=";
      name = "GHSA-9m5m-cr24-m367.14.patch";
    })
    # incusd/auth/oidc: Ignore an unverified email claim for the user name
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0cc7e510c3aa2a633ace2e700831a54d669862a6.patch";
      hash = "sha256-shOB0lECeU1QTzxvf0lNFdq6ys6MHI4BdG2h7+0dj18=";
      name = "GHSA-cp5w-98j2-x2hv.2.patch";
    })
    # incusd/auth/oidc: Don't accept an ID token in place of the access token
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2d5a323bce82b5c6ce7633ae8d04f570fac5899d.patch";
      hash = "sha256-MBANRptAaTY94gIKnpmSwtY05qj5nJlQo85J8WewE8E=";
      name = "GHSA-cp5w-98j2-x2hv.3.patch";
    })
    # incusd: Check the alias entitlement on image upload
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/3e8d1d0c0fff8f790178cdda115cbbd73fb366c9.patch";
      hash = "sha256-Ix/MM78EAKcJXv+IsitEjzVHaPSaNZbwq1CpjpJ/Ot8=";
      name = "GHSA-8553-6xmq-7g3g.9.patch";
    })
    # incusd: Limit port forwarding to the instance's own addresses
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2108673bed18a3d0615da297cf8dc23531d9f953.patch";
      hash = "sha256-zb1ikLvWNtcvCbPkWD7vBIcUaThcP74A4eym5I+J7GQ=";
      name = "GHSA-8553-6xmq-7g3g.10.patch";
    })
    # incusd/forkproxy: Bound what a proxy device holds on the host
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/44333bd2fc8c460509276f16300141d3c961989d.patch";
      hash = "sha256-4+GP5qSBVbrXBZuz3Ydb/2I7t3goG4nepVxeMfqq8yo=";
      name = "GHSA-23fc-ggg4-5r2r.12.patch";
    })
    # incusd: Bound the port forward helper
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/d7d2a112c4f501cf7568f5216d8030114868ca8b.patch";
      hash = "sha256-e5LilewTZUCAE+cEL9zs1P8o+36zmySRnMqaYY2JpyQ=";
      name = "GHSA-23fc-ggg4-5r2r.13.patch";
    })
    # incusd/forkfile: Don't spin on a closed listener
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f5e8b51aae863481ba83dfe35345ffc72034214b.patch";
      hash = "sha256-zPiM1dvDsJgOoVkRQ6/mi7okSMMebzg1pYRdmzBMeWc=";
      name = "GHSA-23fc-ggg4-5r2r.14.patch";
    })
    # incusd: Stop forkfile when its PID file can't be written
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c919ad1ce5c3e766129b3a2deacc02509214f59a.patch";
      hash = "sha256-uB5gsYPirAu6t4dvESF8G7pbQ4G3f7KcHMVYdR1k3ms=";
      name = "GHSA-23fc-ggg4-5r2r.15.patch";
    })
    # incusd/forkzfs: Exit when the mount namespace can't be unshared
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/097bb5db513a4cbc73032aee5b5a07ad90742cd2.patch";
      hash = "sha256-sGWKcI0vhsfPATQJLeCCSJm/5coGZZuqvjocUaPNGms=";
      name = "GHSA-28m6-7v43-rr8m.7.patch";
    })
    # incusd/linux: Decode escaped mount points from mountinfo
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2e9c98d955d12b38f589a6445c0ff19a3c4978fe.patch";
      hash = "sha256-B1im+bdbWpC7qtqo0wxVMasW+RNgkqXPfNqWRMjFUU8=";
      name = "GHSA-28m6-7v43-rr8m.8.patch";
    })
    # incusd/apparmor: Remove the profile file without AppArmor too
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/42d8c8aaf0f2e8e0620bfcad45baf78163c2e2b3.patch";
      hash = "sha256-R+O+Gb21mnba85JBANMMMgicqKjPCiSv7BpG6BvEuc0=";
      name = "GHSA-28m6-7v43-rr8m.9.patch";
    })
    # incus/image: Check the fingerprint before using it as a file name
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/b82135292f7a1920c4d76343cb6a400f8961bb62.patch";
      hash = "sha256-pz+mfUQ3e5MGxUTikVEex10E/pcH/TMo6K6FsgPD3l0=";
      name = "GHSA-5jh2-v77p-jr6q.patch";
    })
    # incusd/instance/lxc: Don't cache a failed idmapped mount probe
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/62a1992d7a952843dea78cf06c542e2293bae02e.patch";
      hash = "sha256-j7UZRI5AY93m4N79rWXw55lwaaqgHMmqSLy49W/9edM=";
      name = "GHSA-28m6-7v43-rr8m.10.patch";
    })
    # incusd/project: Cap limits.cpu.allowance percentages in restricted projects
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/eb687047b54d64338c92196bfb5fb6c26076fce7.patch";
      hash = "sha256-NylAXHCW4gvffWs6QCitorGjForFCcLpOvvkKDX5ld8=";
      name = "GHSA-5pf7-5wqc-rp52.7.patch";
    })
    # incusd/backup: Bound backup parsing to the project's disk budget
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2825fd75a6fde4852de66d0199da4824015562ec.patch";
      hash = "sha256-PV+PVK6Xg/rlxj+CSmfDyUASs4k7lBVHSAg2SBJwzB0=";
      name = "GHSA-9pvj-5r2h-r873.12.patch";
    })
    # incusd/project: Check pool disk limits on volume update
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/dd2d03e8cb9b481f16eeaef6527611639a48f4c7.patch";
      hash = "sha256-Bc9rOz69NAWPT0tWe0uXdfXT/IIUnsHi1Aw5HGFvArc=";
      name = "GHSA-9pvj-5r2h-r873.13.patch";
    })
    # incus/file: Track symlinks created during a recursive pull by identity
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0072cca50366fca5a155d6ffa97b06833e42c984.patch";
      hash = "sha256-4eQvmtV/3BGZ2oCiv7ldWT6B006EIENMswi0YmENF5g=";
      name = "GHSA-whqq-3g5w-5p5w.patch";
    })
    # incus: Default the NBD listeners to a private unix socket
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7c4c3b969db5263a0ca9601dac77b0c3353f5f7b.patch";
      hash = "sha256-W1ns6mN6AdcjNZJraEPCXTn54//dX1X0nbQ/HcU82us=";
      name = "GHSA-wm96-rxh7-f5w2.patch";
    })
    # incus/webui: Keep the access token off the browser command line
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/90274c2e13b90f572d00a5240ae6dfd22f64f0e5.patch";
      hash = "sha256-Uc2Jh8sc/S29f3h8/h34sc8WPGKp/07L0mqCG64QXhM=";
      name = "GHSA-37v2-35hc-m379.patch";
    })
    # incusd/instance: Reject empty and relative snapshot names
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f9c946c8bb113a7871300b2058da2b1705de944f.patch";
      hash = "sha256-eEpRfFsmYuXIG+3Fwjj9iRAaxFf7gVDkC7B5MVrdOQc=";
      name = "GHSA-gg58-ppxh-6h48.patch";
    })
    # incusd/storage/btrfs: Confine received subvolumes to the volume
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/e3f7f9549d98fb94d22b0314b40f3de2ec3879c5.patch";
      hash = "sha256-/1FvCSW4T2UtKwPQciATP0vvuIF+37o23PoQxI+8iaE=";
      name = "GHSA-6g98-m9m8-cggj.patch";
    })
    # incusd/images: Hold received image data to the project budget
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5ea5f83e957bfb3908029c6cedd088bca7ac51ad.patch";
      hash = "sha256-Y0qXhTAD3yQEbFfTbwnwsnVgti+tOMLZ58ovY+amdOM=";
      name = "GHSA-9pvj-5r2h-r873.14.patch";
    })
    # incusd/images: Don't hold the image lock during downloads
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/095818563c21e3654762ad1606c96d5007c4f916.patch";
      hash = "sha256-xirDBEQX3OEnzEl8UERY2w8L2qDJgX45Vx85Eqg3gpw=";
      name = "GHSA-3jgx-fpg2-x499.6.patch";
    })
    # incusd/project: Keep projects, ACLs and network peers in filtered used_by lists
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/4f3ea7ec8aeceef2b17cf699acbdf45ce57b55ce.patch";
      hash = "sha256-FCDz8p9Gk3cBJuindGKp3BfnNkPsHHngcyU+bgZdgd4=";
      name = "GHSA-44g3-g988-46rg.12.patch";
    })
    # incusd/events: Close listeners outside of the server lock
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/7c5a59434f4f5ced07ca61af56f559c42db06079.patch";
      hash = "sha256-OUYbgRWeRC6nXXaNjMoDeESno36Ca6+PpTnZU25TWEE=";
      name = "GHSA-9m5m-cr24-m367.15.patch";
    })
    # incusd/util: Stop the rendering of a template past the output limit
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/52a48d5f2d5fbd51f97949dd4b71546fe6763eff.patch";
      hash = "sha256-lXdlHeZa90AmQY2fcHQm6vyiT693YZeYSjuEskfTmkk=";
      name = "GHSA-v855-hxm9-5pwg.35.patch";
    })
    # incusd/rsync: Apply the output bound to copied streams
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/ec22d6d97752f8370b82e88286d578cf1e701295.patch";
      hash = "sha256-2sCyAZOxawgezm5614wgX5ksuZHfcy83ESKQbBJLupU=";
      name = "GHSA-23fc-ggg4-5r2r.16.patch";
    })
    # incusd/forkfile: Only open regular files and directories
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/0953d79974e9032ee8bf22b95c1a0fef22d6e60a.patch";
      hash = "sha256-wfwSB+tB7DT7XtAdeOSs/fqPEv6KrU5q1fuDVYoH++8=";
      name = "GHSA-xw8w-vwh3-9w5v.patch";
    })
    # incusd/instance/qemu: Take the VM disk format from config at startup
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f0ada3f90143ef80d30b0c55ea3852f08695e69e.patch";
      hash = "sha256-AbU+4qQ6U5GSo/PpwYWTJm2tznWSrM0RYEsXjUVvOak=";
      name = "GHSA-4375-qwr5-8vjj.8.patch";
    })
    # incusd/storage/zfs: Don't take the dataset type or mount point from a stream
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/faf31da75e195ea2c14da23649c2b9ebb1884235.patch";
      hash = "sha256-a3KqN5SmC95pcHMKoqRFY2vsUyXw2p4pUFshdB4ZEp0=";
      name = "GHSA-992p-fqxp-43w6.patch";
    })
    # incusd/firewall: Filter spoofed source MACs at the device ingress
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/c26756801a6f7095ba7395e69b8a97f4f68dc751.patch";
      hash = "sha256-SNsA3S4x2Hb37jw6KVUGiw7syViDc/6zfusjkRjXfO8=";
      name = "GHSA-48vp-j46r-q79m.patch";
    })
    # i18n: Update translation templates
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/2162adce828762413e083e62e0c738e079112e8f.patch";
      hash = "sha256-qyA8nys9OZM1qeP5pwSkkBSmZaXY3sBV+e+KDTYV8+0=";
    })
    # incusd/storage: Check bucket access against the project holding the bucket
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/42060171b8e5c5a558e77d365f20e6bebd2148dd.patch";
      hash = "sha256-BnRir1taQGRa6lfTBzcTNV5v0+8+UnKj7v/1Uo8IRSE=";
      name = "GHSA-92jx-73cc-wf5v.patch";
    })
    # incusd/instance: Only render regular files as templates
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f65d711a2fa869638013924d2ca1da7ede31fb2f.patch";
      hash = "sha256-9L2JpCmsIC64lSSW0/mE/P1AJRU/uUfiEKz6wh9myt4=";
      name = "GHSA-42x8-664j-84w8.13.patch";
    })
    # incusd/instance/lxc: Keep instance and image environment out of the start helper
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/f7fb719242a609a863fd56e53185c4bddcdbebe3.patch";
      hash = "sha256-t7FPftocAwq5kTQXY1oYfA8hPByig+fveScDrgmGnN0=";
      name = "GHSA-hw96-p258-g4jg.patch";
    })
    # incusd: Bind guest API connections to the peer's pidfd
    (fetchpatch {
      url = "https://github.com/lxc/incus/commit/5f2771bd1db10992b0ad492ff22a06dbf01ecc07.patch";
      hash = "sha256-uoJI+WSS8/EPhsf6ZcB8H8NIjIuroT5bK5/isOn1XL0=";
      name = "GHSA-63p9-v6jg-fvvp.patch";
    })
  ];
  lts = true;
  nixUpdateExtraArgs = [
    "--version-regex=^v(7\\.0\\.[0-9]+)$"
    "--override-filename=pkgs/by-name/in/incus/lts.nix"
  ];
}
