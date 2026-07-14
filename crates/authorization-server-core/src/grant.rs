#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
    DeviceCode,
    TokenExchange,
    JwtBearer,
    Ciba,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedGrantType;

impl GrantType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            Self::JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
            Self::Ciba => "urn:openid:params:grant-type:ciba",
        }
    }
}

impl TryFrom<&str> for GrantType {
    type Error = UnsupportedGrantType;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "refresh_token" => Ok(Self::RefreshToken),
            "client_credentials" => Ok(Self::ClientCredentials),
            "urn:ietf:params:oauth:grant-type:device_code" => Ok(Self::DeviceCode),
            "urn:ietf:params:oauth:grant-type:token-exchange" => Ok(Self::TokenExchange),
            "urn:ietf:params:oauth:grant-type:jwt-bearer" => Ok(Self::JwtBearer),
            "urn:openid:params:grant-type:ciba" => Ok(Self::Ciba),
            _ => Err(UnsupportedGrantType),
        }
    }
}
