#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    ConsumeCode,

    RevokeTokensIssuedForCode,

    RotateRefreshToken,

    RevokeRefreshFamily,

    RecordAudit(&'static str),
}
