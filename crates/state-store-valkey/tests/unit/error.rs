use super::{Error, ErrorKind};
use fred::error::{Error as FredError, ErrorKind as FredErrorKind};

#[test]
fn fred_protocol_errors_remain_distinct_from_corrupt_stored_data() {
    let protocol = Error::from_fred(FredError::new(
        FredErrorKind::Protocol,
        "malformed wire response",
    ));
    let parse = Error::from_fred(FredError::new(FredErrorKind::Parse, "invalid RESP"));
    let unavailable = Error::from_fred(FredError::new(FredErrorKind::IO, "connection lost"));
    let corrupt = Error::corrupt_data("malformed stored JSON");

    assert_eq!(protocol.kind(), ErrorKind::Protocol);
    assert_eq!(parse.kind(), ErrorKind::Protocol);
    assert_eq!(unavailable.kind(), ErrorKind::Unavailable);
    assert_eq!(corrupt.kind(), ErrorKind::CorruptData);
}
