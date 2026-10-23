use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "callerRefreshSeconds")]
    pub caller_refresh_seconds: Option<i64>,
    #[serde(alias = "catalogRefreshSeconds")]
    pub catalog_refresh_seconds: Option<i64>,
    #[serde(alias = "cdgcApiUrl", deserialize_with = "pdk::serde::deserialize_service")]
    pub cdgc_api_url: pdk::hl::Service,
    #[serde(
        alias = "cdgcLoginUrl",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub cdgc_login_url: pdk::hl::Service,
    #[serde(alias = "cdgcOrgPassword")]
    pub cdgc_org_password: String,
    #[serde(alias = "cdgcOrgUsername")]
    pub cdgc_org_username: String,
    #[serde(alias = "consumerClaim")]
    pub consumer_claim: Option<String>,
    #[serde(alias = "consumerHeader")]
    pub consumer_header: Option<String>,
    #[serde(alias = "dataCollectionIds")]
    pub data_collection_ids: Option<Vec<String>>,
    #[serde(alias = "distributed")]
    pub distributed: Option<bool>,
    #[serde(alias = "failOpenOnIdmcError")]
    pub fail_open_on_idmc_error: Option<bool>,
    #[serde(alias = "fieldClassTypes")]
    pub field_class_types: Option<Vec<String>>,
    #[serde(alias = "idmcPodUrl", deserialize_with = "pdk::serde::deserialize_service")]
    pub idmc_pod_url: pdk::hl::Service,
    #[serde(alias = "mcpServerAssetId")]
    pub mcp_server_asset_id: String,
    #[serde(alias = "policyRefreshSeconds")]
    pub policy_refresh_seconds: Option<i64>,
    #[serde(alias = "requireConsumerAccess")]
    pub require_consumer_access: Option<bool>,
    #[serde(alias = "timeout")]
    pub timeout: Option<i64>,
    #[serde(alias = "usageContextClaim")]
    pub usage_context_claim: Option<String>,
    #[serde(alias = "usageContextHeader")]
    pub usage_context_header: Option<String>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.cdgc_api_url)?;
    abi.service_create(config.cdgc_login_url)?;
    abi.service_create(config.idmc_pod_url)?;
    abi.setup()?;
    Ok(())
}
