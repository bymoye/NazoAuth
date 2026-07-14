use super::ScimError;

pub const SCIM_DEFAULT_PAGE_SIZE: i64 = 100;
pub const SCIM_MAX_PAGE_SIZE: i64 = 200;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScimListRequest {
    pub start_index: Option<i64>,
    pub count: Option<i64>,
    pub filter: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScimPagination {
    Index { start_index: i64, count: i64 },
    Cursor { encoded: Option<String>, count: i64 },
}

impl ScimPagination {
    #[must_use]
    pub fn repository_window(&self) -> (i64, i64) {
        match self {
            Self::Index { start_index, count } => (*count, start_index.saturating_sub(1)),
            Self::Cursor { count: 0, .. } => (0, 0),
            Self::Cursor { count, .. } => (count.saturating_add(1), 0),
        }
    }
}

pub fn parse_scim_list_query(raw_query: &str) -> Result<ScimListRequest, ScimError> {
    let mut query = ScimListRequest::default();
    for (name, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "startIndex" => {
                if query.start_index.is_some() {
                    return Err(ScimError::new(
                        "invalidValue",
                        "startIndex must not be repeated",
                    ));
                }
                query.start_index = Some(value.parse().map_err(|_| {
                    ScimError::new("invalidValue", "startIndex must be an integer")
                })?);
            }
            "count" => {
                if query.count.is_some() {
                    return Err(ScimError::new("invalidCount", "count must not be repeated"));
                }
                query.count = Some(
                    value
                        .parse()
                        .map_err(|_| ScimError::new("invalidCount", "count must be an integer"))?,
                );
            }
            "filter" => {
                if query.filter.is_some() {
                    return Err(ScimError::new(
                        "invalidValue",
                        "filter must not be repeated",
                    ));
                }
                query.filter = Some(value.into_owned());
            }
            "cursor" => {
                if query.cursor.is_some() {
                    return Err(ScimError::new(
                        "invalidCursor",
                        "cursor must not be repeated",
                    ));
                }
                query.cursor = Some(value.into_owned());
            }
            _ => {}
        }
    }
    Ok(query)
}

pub fn select_scim_pagination(query: &ScimListRequest) -> Result<ScimPagination, ScimError> {
    if let Some(cursor) = &query.cursor {
        if query.start_index.is_some() {
            return Err(ScimError::new(
                "invalidValue",
                "startIndex and cursor cannot be combined",
            ));
        }
        let count = query.count.unwrap_or(SCIM_DEFAULT_PAGE_SIZE).max(0);
        if count > SCIM_MAX_PAGE_SIZE {
            return Err(ScimError::new(
                "invalidCount",
                "count exceeds the maximum cursor page size",
            ));
        }
        return Ok(ScimPagination::Cursor {
            encoded: (!cursor.is_empty()).then(|| cursor.clone()),
            count,
        });
    }
    Ok(ScimPagination::Index {
        start_index: query.start_index.unwrap_or(1).max(1),
        count: query
            .count
            .unwrap_or(SCIM_DEFAULT_PAGE_SIZE)
            .clamp(0, SCIM_MAX_PAGE_SIZE),
    })
}
