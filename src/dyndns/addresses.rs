use ipnet::Ipv6Net;
use std::net::Ipv6Addr;

#[must_use]
pub fn merge(address: Ipv6Addr, prefix: Ipv6Net) -> Ipv6Addr {
    // "remove"/zero-out the prefix by applying the hostmask
    let host_only = u128::from(address) & u128::from(prefix.hostmask());
    // now set the network-bits
    let merged = u128::from(prefix.network()) | host_only;

    Ipv6Addr::from(merged)
}

#[cfg(test)]
mod test {
    use crate::dyndns::addresses::merge;
    use std::net::Ipv6Addr;

    #[test]
    fn test_merge() {
        // an existing AAAA record, e.g. from the dyn.example.com fixture zone
        let sample_address = "2001:db8:1::96c6:91ff:fea5:2dff".parse().unwrap();
        // the new prefix reported by a pdns performing a dyndns update
        let sample_prefix = "2001:db8:2::/64".parse().unwrap();

        assert_eq!(
            merge(sample_address, sample_prefix),
            "2001:db8:2::96c6:91ff:fea5:2dff"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
    }
}
