//! Verification of the `Content-Type` header of a request.
use http::{HeaderMap, header};

/// the `Content-Type` is missing, ambiguous, malformed or not `application/json`
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Content-Type is not application/json")]
pub struct Error;

#[cfg_attr(not(test), expect(unused))]
/// Verifies that the headers contain exactly one `Content-Type` of `application/json`.
/// Parameters like `charset` are ignored.
pub fn verify_json(headers: &HeaderMap) -> Result<(), Error> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(Error);
    };

    let content_type: mime::Mime = value
        .to_str()
        .map_err(|_| Error)?
        .parse()
        .map_err(|_| Error)?;

    if content_type.essence_str() == mime::APPLICATION_JSON.essence_str() {
        Ok(())
    } else {
        Err(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(values: &[&[u8]]) -> HeaderMap {
        let mut sample = HeaderMap::new();
        for v in values {
            sample.append(header::CONTENT_TYPE, HeaderValue::from_bytes(v).unwrap());
        }
        sample
    }

    #[test]
    fn accepts_json() {
        for value in [
            "application/json",
            "Application/JSON",
            "application/json; charset=utf-8",
            "application/json;charset=utf-8",
        ] {
            let sample = headers(&[value.as_bytes()]);

            let actual = verify_json(&sample);

            assert_eq!(actual, Ok(()), "{value}");
        }
    }

    #[test]
    fn rejects_missing_content_type() {
        let sample = headers(&[]);

        let actual = verify_json(&sample);

        assert_eq!(actual, Err(Error));
    }

    #[test]
    fn rejects_other_media_types() {
        for value in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "application/jsonx",
            "application/json-patch+json",
            "text/json",
        ] {
            let sample = headers(&[value.as_bytes()]);

            let actual = verify_json(&sample);

            assert_eq!(actual, Err(Error), "{value}");
        }
    }

    #[test]
    fn rejects_malformed_content_type() {
        for value in [
            &b"application"[..],
            b"",
            b"application/json, text/plain",
            b"application/\xff",
        ] {
            let sample = headers(&[value]);

            let actual = verify_json(&sample);

            assert_eq!(actual, Err(Error), "{value:?}");
        }
    }

    #[test]
    fn rejects_multiple_content_type_headers() {
        let sample = headers(&[b"application/json", b"application/json"]);

        let actual = verify_json(&sample);

        assert_eq!(actual, Err(Error));
    }
}
