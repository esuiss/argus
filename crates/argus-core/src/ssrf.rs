use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddressVerdict {
    #[error("the address is a loopback address")]
    Loopback,

    #[error("the address is in a private range")]
    Private,

    #[error("the address is link-local")]
    LinkLocal,

    #[error("the address is a cloud metadata address")]
    CloudMetadata,

    #[error("the address is otherwise special-use (RFC 6890)")]
    SpecialUse,
}

#[must_use]
pub fn classify(address: IpAddr) -> Option<AddressVerdict> {
    match address {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<AddressVerdict> {
    if ip == Ipv4Addr::new(169, 254, 169, 254) {
        return Some(AddressVerdict::CloudMetadata);
    }
    if ip.is_loopback() {
        return Some(AddressVerdict::Loopback);
    }
    if ip.is_private() {
        return Some(AddressVerdict::Private);
    }
    if ip.is_link_local() {
        return Some(AddressVerdict::LinkLocal);
    }
    if ip.octets()[0] == 0
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || matches!(ip.octets(), [100, b, _, _] if (64..128).contains(&b))
        || matches!(ip.octets(), [192, 0, 0, _])
        || matches!(ip.octets(), [198, 18 | 19, _, _])
        || ip.octets()[0] >= 240
    {
        return Some(AddressVerdict::SpecialUse);
    }
    None
}

fn classify_v6(ip: Ipv6Addr) -> Option<AddressVerdict> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return classify_v4(mapped);
    }

    if ip.is_loopback() {
        return Some(AddressVerdict::Loopback);
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return Some(AddressVerdict::SpecialUse);
    }

    let segments = ip.segments();
    if segments[0] & 0xfe00 == 0xfc00 {
        return Some(AddressVerdict::Private);
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some(AddressVerdict::LinkLocal);
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some(AddressVerdict::SpecialUse);
    }

    if let Some(compat) = ip.to_ipv4() {
        return classify_v4(compat).or(Some(AddressVerdict::SpecialUse));
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{AddressVerdict, classify};
    use core::net::IpAddr;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("address")
    }

    #[test]
    fn loopback_is_refused_in_both_families() {
        assert_eq!(classify(ip("127.0.0.1")), Some(AddressVerdict::Loopback));
        assert_eq!(classify(ip("127.1.2.3")), Some(AddressVerdict::Loopback));
        assert_eq!(classify(ip("::1")), Some(AddressVerdict::Loopback));
    }

    #[test]
    fn the_ranges_mcp_names_are_all_refused() {
        for raw in [
            "10.0.0.1",
            "172.16.5.4",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
        ] {
            assert!(classify(ip(raw)).is_some(), "allowed {raw}");
        }
    }

    #[test]
    fn cloud_metadata_is_named_specifically() {
        assert_eq!(
            classify(ip("169.254.169.254")),
            Some(AddressVerdict::CloudMetadata)
        );
    }

    #[test]
    fn ipv4_mapped_and_compatible_ipv6_do_not_smuggle_private_addresses() {
        assert_eq!(
            classify(ip("::ffff:127.0.0.1")),
            Some(AddressVerdict::Loopback)
        );
        assert_eq!(
            classify(ip("::ffff:10.0.0.1")),
            Some(AddressVerdict::Private)
        );
        assert_eq!(
            classify(ip("::ffff:169.254.169.254")),
            Some(AddressVerdict::CloudMetadata)
        );
    }

    #[test]
    fn carrier_grade_nat_and_benchmarking_ranges_are_refused() {
        assert_eq!(classify(ip("100.64.0.1")), Some(AddressVerdict::SpecialUse));
        assert_eq!(classify(ip("198.18.0.1")), Some(AddressVerdict::SpecialUse));
        assert_eq!(classify(ip("192.0.0.1")), Some(AddressVerdict::SpecialUse));
    }

    #[test]
    fn documentation_ranges_are_refused() {
        assert_eq!(classify(ip("192.0.2.1")), Some(AddressVerdict::SpecialUse));
        assert_eq!(
            classify(ip("198.51.100.1")),
            Some(AddressVerdict::SpecialUse)
        );
        assert_eq!(
            classify(ip("203.0.113.1")),
            Some(AddressVerdict::SpecialUse)
        );
        assert_eq!(
            classify(ip("2001:db8::1")),
            Some(AddressVerdict::SpecialUse)
        );
    }

    #[test]
    fn ordinary_public_addresses_are_allowed() {
        for raw in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert_eq!(classify(ip(raw)), None, "refused {raw}");
        }
    }

    #[test]
    fn the_boundaries_of_the_private_ranges_are_exact() {
        assert!(classify(ip("172.15.255.255")).is_none());
        assert!(classify(ip("172.16.0.0")).is_some());
        assert!(classify(ip("172.31.255.255")).is_some());
        assert!(classify(ip("172.32.0.0")).is_none());
        assert!(classify(ip("100.63.255.255")).is_none());
        assert!(classify(ip("100.64.0.0")).is_some());
        assert!(classify(ip("100.127.255.255")).is_some());
        assert!(classify(ip("100.128.0.0")).is_none());
    }
}
