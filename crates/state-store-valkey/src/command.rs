use fred::prelude::{Expiration, KeysInterface, SetOptions};

use crate::{Error, ValkeyConnection};

const COMPARE_DELETE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  return 'missing'
end
if current ~= ARGV[1] then
  return 'changed'
end
redis.call('DEL', KEYS[1])
return 'deleted'
"#;

const COMPARE_DELETE_JSON_SCRIPT: &str = r#"
local function parse_json(raw)
  local position = 1
  local length = #raw

  local function skip_whitespace()
    while position <= length and string.find(' \t\r\n', string.sub(raw, position, position), 1, true) do
      position = position + 1
    end
  end

  local function parse_string()
    if string.sub(raw, position, position) ~= '"' then
      error('expected string')
    end
    local start = position
    position = position + 1
    local escaped = false
    while position <= length do
      local character = string.sub(raw, position, position)
      if escaped then
        escaped = false
      elseif character == '\\' then
        escaped = true
      elseif character == '"' then
        position = position + 1
        return cjson.decode(string.sub(raw, start, position - 1))
      end
      position = position + 1
    end
    error('unterminated string')
  end

  local parse_value
  parse_value = function()
    skip_whitespace()
    local character = string.sub(raw, position, position)
    if character == '[' then
      position = position + 1
      local values = {}
      skip_whitespace()
      if string.sub(raw, position, position) == ']' then
        position = position + 1
        return { kind = 'array', values = values }
      end
      while true do
        table.insert(values, parse_value())
        skip_whitespace()
        character = string.sub(raw, position, position)
        if character == ']' then
          position = position + 1
          return { kind = 'array', values = values }
        end
        if character ~= ',' then
          error('expected array separator')
        end
        position = position + 1
      end
    end
    if character == '{' then
      position = position + 1
      local values = {}
      skip_whitespace()
      if string.sub(raw, position, position) == '}' then
        position = position + 1
        return { kind = 'object', values = values }
      end
      while true do
        skip_whitespace()
        local key = parse_string()
        if values[key] ~= nil then
          error('duplicate object key')
        end
        skip_whitespace()
        if string.sub(raw, position, position) ~= ':' then
          error('expected object colon')
        end
        position = position + 1
        values[key] = parse_value()
        skip_whitespace()
        character = string.sub(raw, position, position)
        if character == '}' then
          position = position + 1
          return { kind = 'object', values = values }
        end
        if character ~= ',' then
          error('expected object separator')
        end
        position = position + 1
      end
    end
    if character == '"' then
      return { kind = 'string', value = parse_string() }
    end
    local start = position
    while position <= length do
      character = string.sub(raw, position, position)
      if string.find(',]} \t\r\n', character, 1, true) then
        break
      end
      position = position + 1
    end
    if start == position then
      error('expected primitive')
    end
    local token = string.sub(raw, start, position - 1)
    local value = cjson.decode(token)
    if token == 'null' then
      return { kind = 'null' }
    end
    return { kind = type(value), value = value }
  end

  local result = parse_value()
  skip_whitespace()
  if position <= length then
    error('trailing JSON data')
  end
  return result
end

local function json_equal(left, right)
  if left.kind ~= right.kind then
    return false
  end
  if left.kind == 'array' then
    if #left.values ~= #right.values then
      return false
    end
    for index = 1, #left.values do
      if not json_equal(left.values[index], right.values[index]) then
        return false
      end
    end
    return true
  end
  if left.kind == 'object' then
    local left_keys = {}
    local right_count = 0
    for key, _ in pairs(left.values) do
      table.insert(left_keys, key)
    end
    for _, _ in pairs(right.values) do
      right_count = right_count + 1
    end
    if #left_keys ~= right_count then
      return false
    end
    table.sort(left_keys)
    for _, key in ipairs(left_keys) do
      if right.values[key] == nil or not json_equal(left.values[key], right.values[key]) then
        return false
      end
    end
    return true
  end
  if left.kind == 'null' then
    return true
  end
  return left.value == right.value
end

local current_raw = redis.call('GET', KEYS[1])
if not current_raw then
  return 'missing'
end
local current_ok, current = pcall(parse_json, current_raw)
local expected_ok, expected = pcall(parse_json, ARGV[1])
if not current_ok or not expected_ok then
  return 'malformed'
end
if not json_equal(current, expected) then
  return 'changed'
end
redis.call('DEL', KEYS[1])
return 'deleted'
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompareDelete {
    Deleted,
    MissingOrChanged,
}

pub(crate) async fn set_ex_nx(
    connection: &ValkeyConnection,
    key: String,
    value: &'static str,
    ttl_seconds: u64,
) -> Result<bool, Error> {
    let reply = connection
        .client
        .set::<Option<String>, _, _>(
            key,
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await
        .map_err(Error::from_fred)?;
    match reply.as_deref() {
        Some("OK") => Ok(true),
        None => Ok(false),
        Some(other) => Err(Error::unexpected(format!(
            "unexpected SET NX reply {other:?}"
        ))),
    }
}

pub(crate) async fn set_ex_nx_string(
    connection: &ValkeyConnection,
    key: String,
    value: String,
    ttl_seconds: u64,
) -> Result<bool, Error> {
    let reply = connection
        .client
        .set::<Option<String>, _, _>(
            key,
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await
        .map_err(Error::from_fred)?;
    match reply.as_deref() {
        Some("OK") => Ok(true),
        None => Ok(false),
        Some(other) => Err(Error::unexpected(format!(
            "unexpected SET NX reply {other:?}"
        ))),
    }
}

pub(crate) async fn set_ex(
    connection: &ValkeyConnection,
    key: String,
    value: &'static str,
    ttl_seconds: u64,
) -> Result<(), Error> {
    connection
        .client
        .set::<(), _, _>(
            key,
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            None,
            false,
        )
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn take(
    connection: &ValkeyConnection,
    key: String,
) -> Result<Option<String>, Error> {
    connection
        .client
        .getdel(key)
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn set_ex_string(
    connection: &ValkeyConnection,
    key: String,
    value: String,
    ttl_seconds: u64,
) -> Result<(), Error> {
    connection
        .client
        .set::<(), _, _>(
            key,
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            None,
            false,
        )
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn get(
    connection: &ValkeyConnection,
    key: String,
) -> Result<Option<String>, Error> {
    connection.client.get(key).await.map_err(Error::from_fred)
}

pub(crate) async fn get_many(
    connection: &ValkeyConnection,
    keys: Vec<String>,
) -> Result<Vec<Option<String>>, Error> {
    connection.client.mget(keys).await.map_err(Error::from_fred)
}

pub(crate) async fn delete(connection: &ValkeyConnection, key: String) -> Result<i64, Error> {
    connection.client.del(key).await.map_err(Error::from_fred)
}

pub(crate) async fn compare_delete(
    connection: &ValkeyConnection,
    key: String,
    expected: &str,
) -> Result<CompareDelete, Error> {
    match eval_string(
        connection,
        COMPARE_DELETE_SCRIPT,
        vec![key],
        vec![expected.to_owned()],
    )
    .await?
    .as_str()
    {
        "deleted" => Ok(CompareDelete::Deleted),
        "missing" | "changed" => Ok(CompareDelete::MissingOrChanged),
        reply => Err(Error::unexpected(format!(
            "unexpected compare-delete reply {reply:?}"
        ))),
    }
}

pub(crate) async fn compare_delete_json(
    connection: &ValkeyConnection,
    key: String,
    expected: &str,
) -> Result<CompareDelete, Error> {
    match eval_string(
        connection,
        COMPARE_DELETE_JSON_SCRIPT,
        vec![key],
        vec![expected.to_owned()],
    )
    .await?
    .as_str()
    {
        "deleted" => Ok(CompareDelete::Deleted),
        "missing" | "changed" => Ok(CompareDelete::MissingOrChanged),
        "malformed" => Err(Error::corrupt_data(
            "malformed stored or expected JSON during compare-delete",
        )),
        reply => Err(Error::unexpected(format!(
            "unexpected JSON compare-delete reply {reply:?}"
        ))),
    }
}

pub(crate) async fn eval_string(
    connection: &ValkeyConnection,
    script: &'static str,
    keys: Vec<String>,
    args: Vec<String>,
) -> Result<String, Error> {
    use fred::prelude::LuaInterface;

    connection
        .client
        .eval(script, keys, args)
        .await
        .map_err(Error::from_fred)
}

#[cfg(test)]
mod tests {
    use super::{COMPARE_DELETE_JSON_SCRIPT, COMPARE_DELETE_SCRIPT};

    #[test]
    fn compare_delete_checks_the_opaque_value_before_deleting() {
        let get = COMPARE_DELETE_SCRIPT.find("redis.call('GET'").unwrap();
        let compare = COMPARE_DELETE_SCRIPT.find("current ~= ARGV[1]").unwrap();
        let delete = COMPARE_DELETE_SCRIPT.find("redis.call('DEL'").unwrap();

        assert!(get < compare && compare < delete);
        assert!(COMPARE_DELETE_SCRIPT.contains("return 'changed'"));
        assert!(COMPARE_DELETE_SCRIPT.contains("return 'deleted'"));
    }

    #[test]
    fn json_compare_delete_decodes_before_a_type_preserving_deep_compare() {
        let decode = COMPARE_DELETE_JSON_SCRIPT.find("pcall(parse_json").unwrap();
        let compare = COMPARE_DELETE_JSON_SCRIPT
            .find("json_equal(current, expected)")
            .unwrap();
        let delete = COMPARE_DELETE_JSON_SCRIPT.find("redis.call('DEL'").unwrap();

        assert!(decode < compare && compare < delete);
        assert!(COMPARE_DELETE_JSON_SCRIPT.contains("kind = 'array'"));
        assert!(COMPARE_DELETE_JSON_SCRIPT.contains("kind = 'object'"));
        assert!(COMPARE_DELETE_JSON_SCRIPT.contains("left.kind ~= right.kind"));
        assert!(COMPARE_DELETE_JSON_SCRIPT.contains("table.sort(left_keys)"));
        assert!(COMPARE_DELETE_JSON_SCRIPT.contains("return 'malformed'"));
    }
}
