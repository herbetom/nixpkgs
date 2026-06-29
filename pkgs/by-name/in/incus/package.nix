import ./generic.nix {
  hash = "sha256-GVCC0nV5Ghd9BroVC4ysqiTIQ3AtXIJ+EG6VbJVQBB4=";
  version = "7.2.0";
  vendorHash = "sha256-0lBMQXQEf+oYlvyoFV2VTpJbY+reavCJZQkzt9UbnaI=";
  patches = fetchpatch2: [
    (fetchpatch2 {
      name = "incus-move_Apply-storage-pool-to-dependent-disks.patch";
      url = "https://github.com/lxc/incus/commit/30c603507e631eb90ed189a9803709a95ed61c71.patch?full_index=1";
      hash = "sha256-KuNM6IeeL0ImiAviK2zU9gyNcScGxm9VndwOC4r4h+c=";
    })
    (fetchpatch2 {
      name = "incusd-firewall_Fix-double-Wait-in-nftParseRuleset.patch";
      url = "https://github.com/lxc/incus/commit/c97d867faabce3bb56176709396b0506afc0d95e.patch?full_index=1";
      hash = "sha256-vgkzFIEymM8CAAiFPmZKgIweXB2yrBoSoyIpFZ8crcY=";
    })
    (fetchpatch2 {
      name = "incusd-device_Allow-static-CIDR-address-on-unmanaged-bridge.patch";
      url = "https://github.com/lxc/incus/commit/713a400c979c2473e40f813a92246b7788aebe17.patch?full_index=1";
      hash = "sha256-NbUEnHMwPT0s/Obj2BPoedBcoKZlFSsLrDGdCkK6HqY=";
    })
    (fetchpatch2 {
      name = "shared-logger_Add-WarnOnErrorExcept-helper.patch";
      url = "https://github.com/lxc/incus/commit/31de4be43c17eafa6c9aa516f9f5a99cea1569c6.patch?full_index=1";
      hash = "sha256-h3WHUq7yYitBwgN47knLh2CriM0e8iR2yC44OXIUlqc=";
    })
    (fetchpatch2 {
      name = "incus_Avoid-double-close-warning-on-volume-bucket-instance-import.patch";
      url = "https://github.com/lxc/incus/commit/7a6df891b5c60087333458479fc6757b4055a586.patch?full_index=1";
      hash = "sha256-rXUa6f5k8QiUDDod3ea+SaMP7aei9j1j4uUszUuuLtc=";
    })
    (fetchpatch2 {
      name = "incusd-device_Reset-VM-disk-I-O-limits-on-unset.patch";
      url = "https://github.com/lxc/incus/commit/bfece20827965836d27c90579be4a766e6ac4748.patch?full_index=1";
      hash = "sha256-MdFJjfKoxW/iL/bHQ8vWY0yKV+vXlNpbW9hRbJRh+Os=";
    })
    (fetchpatch2 {
      name = "incusd-devices_Allow--32-and--128-for-OCI-addresses.patch";
      url = "https://github.com/lxc/incus/commit/6eb95b4dae48ac81be7e4ca4b13e4c637f343234.patch?full_index=1";
      hash = "sha256-gUms9+PsAEgAfLPcR6TxosY9nJB/yxKAKnUY4ZqG7NY=";
    })
    (fetchpatch2 {
      name = "incusd-operations_Fix-nil-deref-race-in-Cancel.patch";
      url = "https://github.com/lxc/incus/commit/661d3c36df2467e36f5b80208aa11d4ef7833526.patch?full_index=1";
      hash = "sha256-qIP9669V3IehLxN7Z5oKRa4Fwa36pqs5UudwewCNXXw=";
    })
  ];
  nixUpdateExtraArgs = [
    "--override-filename=pkgs/by-name/in/incus/package.nix"
  ];
}
