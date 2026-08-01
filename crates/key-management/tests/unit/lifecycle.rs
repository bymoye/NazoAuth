use super::*;

#[test]
fn refresh_interval_is_bounded_by_prepublish_window() {
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(86_400)),
        Duration::from_secs(3_600)
    );
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(30)),
        Duration::from_secs(15)
    );
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(1)),
        Duration::from_secs(1)
    );
}
