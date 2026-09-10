use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use argus_core::scim::{GROUP_SCHEMA, USER_SCHEMA};
pub const ENTERPRISE_USER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

pub const CONTENT_TYPE: &str = "application/scim+json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ScimError {
    #[must_use]
    pub fn new(status: u16, scim_type: Option<&str>, detail: &str) -> Self {
        Self {
            schemas: vec![ERROR_SCHEMA.to_owned()],
            status: status.to_string(),
            scim_type: scim_type.map(str::to_owned),
            detail: Some(detail.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<Value>,
}

impl ListResponse {
    #[must_use]
    pub fn new(resources: Vec<Value>, total: usize, start_index: usize) -> Self {
        Self {
            schemas: vec![LIST_RESPONSE_SCHEMA.to_owned()],
            total_results: total,
            items_per_page: resources.len(),
            start_index,
            resources,
        }
    }
}

#[must_use]
pub fn service_provider_config(base: &str) -> Value {
    serde_json::json!({
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": format!("{base}/scim/docs"),
        "patch":         { "supported": true },
        "bulk":          { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter":        { "supported": true, "maxResults": 200 },
        "changePassword":{ "supported": false },
        "sort":          { "supported": true },
        "securityEvents": {
            "asyncRequest": "none",
            "eventUris": argus_core::scim_event::all_event_uris()
        },
        "pagination": {
            "cursor": true,
            "index": true,
            "defaultPaginationMethod": "index",
            "cursorTimeout": 3600
        },
        "etag":          { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication scheme using the OAuth Bearer Token Standard",
            "specUri": "http://www.rfc-editor.org/info/rfc6750",
            "primary": true
        }],
        "meta": {
            "location": format!("{base}/scim/v2/ServiceProviderConfig"),
            "resourceType": "ServiceProviderConfig"
        }
    })
}

#[must_use]
pub fn resource_types(base: &str) -> Vec<Value> {
    vec![
        serde_json::json!({
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": USER_SCHEMA,
            "schemaExtensions": [{
                "schema": ENTERPRISE_USER_SCHEMA,
                "required": false
            }],
            "meta": {
                "location": format!("{base}/scim/v2/ResourceTypes/User"),
                "resourceType": "ResourceType"
            }
        }),
        serde_json::json!({
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Group",
            "schema": GROUP_SCHEMA,
            "meta": {
                "location": format!("{base}/scim/v2/ResourceTypes/Group"),
                "resourceType": "ResourceType"
            }
        }),
    ]
}

fn attribute(
    name: &str,
    kind: &str,
    multi: bool,
    required: bool,
    mutability: &str,
    uniqueness: &str,
    case_exact: bool,
) -> Value {
    serde_json::json!({
        "name": name,
        "type": kind,
        "multiValued": multi,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": uniqueness
    })
}

#[must_use]
pub fn schemas(base: &str) -> Vec<Value> {
    vec![
        serde_json::json!({
            "schemas": [SCHEMA_SCHEMA],
            "id": USER_SCHEMA,
            "name": "User",
            "description": "User Account",
            "attributes": [
                attribute("userName", "string", false, true, "readWrite", "server", false),
                attribute("displayName", "string", false, false, "readWrite", "none", false),
                attribute("active", "boolean", false, false, "readWrite", "none", false),
                attribute("externalId", "string", false, false, "readWrite", "none", true),
                {
                    "name": "name",
                    "type": "complex",
                    "multiValued": false,
                    "required": false,
                    "mutability": "readWrite",
                    "returned": "default",
                    "subAttributes": [
                        attribute("givenName", "string", false, false, "readWrite", "none", false),
                        attribute("familyName", "string", false, false, "readWrite", "none", false),
                        attribute("formatted", "string", false, false, "readWrite", "none", false)
                    ]
                },
                {
                    "name": "emails",
                    "type": "complex",
                    "multiValued": true,
                    "required": false,
                    "mutability": "readWrite",
                    "returned": "default",
                    "subAttributes": [
                        attribute("value", "string", false, false, "readWrite", "none", false),
                        attribute("type", "string", false, false, "readWrite", "none", false),
                        attribute("primary", "boolean", false, false, "readWrite", "none", false)
                    ]
                }
            ],
            "meta": {
                "location": format!("{base}/scim/v2/Schemas/{USER_SCHEMA}"),
                "resourceType": "Schema"
            }
        }),
        serde_json::json!({
            "schemas": [SCHEMA_SCHEMA],
            "id": GROUP_SCHEMA,
            "name": "Group",
            "description": "Group",
            "attributes": [
                attribute("displayName", "string", false, true, "readWrite", "none", false),
                {
                    "name": "members",
                    "type": "complex",
                    "multiValued": true,
                    "required": false,
                    "mutability": "readWrite",
                    "returned": "default",
                    "subAttributes": [
                        attribute("value", "string", false, false, "immutable", "none", true),
                        attribute("display", "string", false, false, "immutable", "none", false),
                        attribute("$ref", "reference", false, false, "immutable", "none", true)
                    ]
                }
            ],
            "meta": {
                "location": format!("{base}/scim/v2/Schemas/{GROUP_SCHEMA}"),
                "resourceType": "Schema"
            }
        }),
        serde_json::json!({
            "schemas": [SCHEMA_SCHEMA],
            "id": ENTERPRISE_USER_SCHEMA,
            "name": "EnterpriseUser",
            "description": "Enterprise User",
            "attributes": [
                attribute("employeeNumber", "string", false, false, "readWrite", "none", false),
                attribute("department", "string", false, false, "readWrite", "none", false),
                attribute("costCenter", "string", false, false, "readWrite", "none", false)
            ],
            "meta": {
                "location": format!("{base}/scim/v2/Schemas/{ENTERPRISE_USER_SCHEMA}"),
                "resourceType": "Schema"
            }
        }),
    ]
}

#[must_use]
pub fn with_meta(
    mut resource: Value,
    resource_type: &str,
    base: &str,
    created: &str,
    modified: &str,
) -> Value {
    let id = resource
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let plural = match resource_type {
        "User" => "Users",
        _ => "Groups",
    };

    if let Some(object) = resource.as_object_mut() {
        object.insert(
            "meta".to_owned(),
            serde_json::json!({
                "resourceType": resource_type,
                "created": created,
                "lastModified": modified,
                "location": format!("{base}/scim/v2/{plural}/{id}")
            }),
        );
    }
    resource
}

#[must_use]
pub fn project(resource: &Value, attributes: Option<&str>, excluded: Option<&str>) -> Value {
    let Some(object) = resource.as_object() else {
        return resource.clone();
    };

    let always: [&str; 3] = ["schemas", "id", "meta"];

    if let Some(list) = attributes {
        let wanted: Vec<String> = list
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let mut out = Map::new();
        for (key, value) in object {
            let keep = always.contains(&key.as_str())
                || wanted.iter().any(|w| {
                    let key = key.to_lowercase();
                    *w == key || w.starts_with(&format!("{key}."))
                });
            if keep {
                out.insert(key.clone(), value.clone());
            }
        }
        return Value::Object(out);
    }

    if let Some(list) = excluded {
        let unwanted: Vec<String> = list
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let mut out = Map::new();
        for (key, value) in object {
            let drop = !always.contains(&key.as_str())
                && unwanted.iter().any(|w| *w == key.to_lowercase());
            if !drop {
                out.insert(key.clone(), value.clone());
            }
        }
        return Value::Object(out);
    }

    resource.clone()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::{
        ERROR_SCHEMA, ListResponse, ScimError, project, resource_types, schemas,
        service_provider_config, with_meta,
    };
    use serde_json::json;

    #[test]
    fn the_error_status_is_a_json_string_not_a_number() {
        let json =
            serde_json::to_string(&ScimError::new(409, Some("uniqueness"), "taken")).expect("json");
        assert!(json.contains(r#""status":"409""#), "{json}");
        assert!(json.contains(r#""scimType":"uniqueness""#));
        assert!(json.contains(ERROR_SCHEMA));
    }

    #[test]
    fn a_list_response_reports_its_own_page_size() {
        let list = ListResponse::new(vec![json!({"id": "1"}), json!({"id": "2"})], 57, 11);
        assert_eq!(list.items_per_page, 2);
        assert_eq!(list.total_results, 57);
        assert_eq!(list.start_index, 11);
    }

    #[test]
    fn the_config_declares_the_event_dictionary_but_no_asynchronous_requests() {
        let config = service_provider_config("https://idp.test");
        assert_eq!(
            config["securityEvents"]["asyncRequest"], "none",
            "Prefer: respond-async is the most invasive change to the request pipeline and is not implemented"
        );
        let uris = config["securityEvents"]["eventUris"]
            .as_array()
            .expect("array");
        assert!(
            uris.iter()
                .any(|u| u == "urn:ietf:params:scim:event:prov:create:notice")
        );
        assert!(
            !uris
                .iter()
                .any(|u| u == "urn:ietf:params:scim:event:prov:create:full"),
            "advertising an event the server never emits would mislead a receiver"
        );
    }

    #[test]
    fn the_config_declares_both_pagination_methods_rfc_9865_defines() {
        let config = service_provider_config("https://idp.test");
        assert_eq!(config["pagination"]["cursor"], true);
        assert_eq!(config["pagination"]["index"], true);
    }

    #[test]
    fn the_service_provider_config_declares_patch_and_denies_bulk() {
        let config = service_provider_config("https://idp.test");
        assert_eq!(config["patch"]["supported"], true);
        assert_eq!(
            config["bulk"]["supported"], false,
            "Entra does not use /Bulk and we do not claim it"
        );
        assert_eq!(config["filter"]["supported"], true);
    }

    #[test]
    fn the_user_resource_type_declares_the_enterprise_extension() {
        let types = resource_types("https://idp.test");
        let user = types.first().expect("user");
        assert_eq!(user["endpoint"], "/Users");
        assert_eq!(
            user["schemaExtensions"][0]["schema"],
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        );
    }

    #[test]
    fn user_name_is_unique_and_case_insensitive_while_external_id_is_case_exact() {
        let all = schemas("https://idp.test");
        let user = all.first().expect("user schema");
        let attributes = user["attributes"].as_array().expect("array");

        let by_name = |name: &str| {
            attributes
                .iter()
                .find(|a| a["name"] == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };

        assert_eq!(by_name("userName")["uniqueness"], "server");
        assert_eq!(by_name("userName")["caseExact"], false);
        assert_eq!(by_name("externalId")["caseExact"], true);
    }

    #[test]
    fn group_membership_values_are_immutable() {
        let all = schemas("https://idp.test");
        let group = all.get(1).expect("group schema");
        let members = group["attributes"]
            .as_array()
            .expect("array")
            .iter()
            .find(|a| a["name"] == "members")
            .expect("members");

        assert_eq!(members["subAttributes"][0]["mutability"], "immutable");
    }

    #[test]
    fn meta_carries_the_location_the_client_will_follow() {
        let resource = with_meta(
            json!({ "id": "abc", "userName": "bjensen" }),
            "User",
            "https://idp.test",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(
            resource["meta"]["location"],
            "https://idp.test/scim/v2/Users/abc"
        );
        assert_eq!(resource["meta"]["resourceType"], "User");
    }

    #[test]
    fn projection_keeps_the_attributes_that_are_always_returned() {
        let resource = json!({
            "schemas": ["a"], "id": "1", "meta": {"x": 1},
            "userName": "bjensen", "displayName": "Barbara", "active": true
        });

        let projected = project(&resource, Some("userName"), None);
        assert!(projected.get("schemas").is_some());
        assert!(projected.get("id").is_some());
        assert!(projected.get("meta").is_some());
        assert!(projected.get("userName").is_some());
        assert!(
            projected.get("displayName").is_none(),
            "attributes not asked for must be dropped"
        );
    }

    #[test]
    fn exclusion_cannot_drop_the_attributes_that_are_always_returned() {
        let resource = json!({
            "schemas": ["a"], "id": "1", "meta": {"x": 1}, "userName": "bjensen"
        });

        let projected = project(&resource, None, Some("id,meta,schemas,userName"));
        assert!(projected.get("id").is_some());
        assert!(projected.get("schemas").is_some());
        assert!(projected.get("meta").is_some());
        assert!(projected.get("userName").is_none());
    }

    #[test]
    fn projection_is_case_insensitive_on_attribute_names() {
        let resource = json!({ "id": "1", "userName": "bjensen" });
        let projected = project(&resource, Some("USERNAME"), None);
        assert!(projected.get("userName").is_some());
    }
}
