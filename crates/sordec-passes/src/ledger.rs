//! Soroban ledger-time constants.
//!
//! TTL thresholds and extension amounts are expressed in *ledgers*, not
//! seconds. The SDK's `DAY_IN_LEDGERS` (17280, at the protocol's nominal
//! ~5s close time) is the unit contracts build their TTL magic numbers
//! from — `INSTANCE_BUMP_AMOUNT`, `BALANCE_BUMP_AMOUNT`, and friends are
//! all `N * DAY_IN_LEDGERS`. The concrete SDK constant *names* are
//! contract-private and unrecoverable, but the duration a ledger count
//! represents is a witnessed fact once the count resolves.

/// Ledgers per day at the protocol's nominal ~5-second close time — the
/// SDK's `DAY_IN_LEDGERS`.
pub const DAY_IN_LEDGERS: u32 = 17280;

/// Human duration a TTL ledger count represents, when it is a whole
/// number of days (`N * DAY_IN_LEDGERS`) — `"1 day"` or `"N days"`.
///
/// Returns `None` for zero or any count that is not an exact multiple:
/// the naming is a witnessed decode of the `DAY_IN_LEDGERS` unit, never a
/// rounded approximation.
#[must_use]
pub fn ledger_duration_name(ledgers: u32) -> Option<String> {
    if ledgers == 0 || !ledgers.is_multiple_of(DAY_IN_LEDGERS) {
        return None;
    }
    let days = ledgers / DAY_IN_LEDGERS;
    Some(if days == 1 {
        "1 day".to_string()
    } else {
        format!("{days} days")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_day_multiples_name_their_duration() {
        assert_eq!(ledger_duration_name(17280).as_deref(), Some("1 day"));
        assert_eq!(ledger_duration_name(103680).as_deref(), Some("6 days"));
        assert_eq!(ledger_duration_name(120960).as_deref(), Some("7 days"));
        assert_eq!(ledger_duration_name(501120).as_deref(), Some("29 days"));
        assert_eq!(ledger_duration_name(518400).as_deref(), Some("30 days"));
    }

    #[test]
    fn zero_and_non_multiples_are_unnamed() {
        assert_eq!(ledger_duration_name(0), None);
        assert_eq!(ledger_duration_name(1), None);
        assert_eq!(ledger_duration_name(17281), None);
        // A computed allowance TTL (ledger_seq + amount) is not a day multiple.
        assert_eq!(ledger_duration_name(100_003), None);
    }
}
