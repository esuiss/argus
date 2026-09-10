use argus_core::ldap::{
    Dn, Entry, Membership, OID_PAGED_RESULTS, OID_PASSWORD_MODIFY, OID_START_TLS, OID_WHO_AM_I,
    Scope, escape_rdn_value, evaluate, posix_id, project,
};
use argus_parse::ldap_filter::Filter;

pub const VENDOR_NAME: &str = "Argus";
pub const SUBSCHEMA_DN: &str = "cn=Subschema";

pub const DEFAULT_SIZE_LIMIT: i64 = 500;
pub const MAX_SIZE_LIMIT: i64 = 5_000;
pub const DEFAULT_TIME_LIMIT: i64 = 30;
pub const MAX_TIME_LIMIT: i64 = 120;

pub use argus_core::ldap::{Group, Person};

pub struct Directory {
    pub base: Dn,
    pub base_text: String,
    pub people: Vec<Person>,
    pub groups: Vec<Group>,
    pub vendor_version: String,
    pub start_tls_offered: bool,
}

impl Directory {
    #[must_use]
    pub fn people_base(&self) -> String {
        format!("ou=people,{}", self.base_text)
    }

    #[must_use]
    pub fn groups_base(&self) -> String {
        format!("ou=groups,{}", self.base_text)
    }

    #[must_use]
    pub fn person_dn(&self, uid: &str) -> String {
        format!("uid={},{}", escape_rdn_value(uid), self.people_base())
    }

    #[must_use]
    pub fn group_dn(&self, name: &str) -> String {
        format!("cn={},{}", escape_rdn_value(name), self.groups_base())
    }

    #[must_use]
    pub fn root_dse(&self) -> Entry {
        let mut extensions = vec![OID_WHO_AM_I.to_owned(), OID_PASSWORD_MODIFY.to_owned()];
        if self.start_tls_offered {
            extensions.insert(0, OID_START_TLS.to_owned());
        }

        Entry {
            dn: String::new(),
            attributes: vec![
                (
                    "objectClass".to_owned(),
                    vec!["top".to_owned(), "OpenLDAProotDSE".to_owned()],
                ),
                ("namingContexts".to_owned(), vec![self.base_text.clone()]),
                ("supportedLDAPVersion".to_owned(), vec!["3".to_owned()]),
                (
                    "subschemaSubentry".to_owned(),
                    vec![SUBSCHEMA_DN.to_owned()],
                ),
                ("supportedExtension".to_owned(), extensions),
                (
                    "supportedControl".to_owned(),
                    vec![OID_PAGED_RESULTS.to_owned()],
                ),
                ("supportedSASLMechanisms".to_owned(), Vec::new()),
                ("vendorName".to_owned(), vec![VENDOR_NAME.to_owned()]),
                (
                    "vendorVersion".to_owned(),
                    vec![self.vendor_version.clone()],
                ),
            ],
        }
    }

    #[must_use]
    pub fn subschema(&self) -> Entry {
        Entry {
            dn: SUBSCHEMA_DN.to_owned(),
            attributes: vec![
                (
                    "objectClass".to_owned(),
                    vec!["top".to_owned(), "subschema".to_owned()],
                ),
                ("cn".to_owned(), vec!["Subschema".to_owned()]),
                (
                    "objectClasses".to_owned(),
                    OBJECT_CLASSES.iter().map(|s| (*s).to_owned()).collect(),
                ),
                (
                    "attributeTypes".to_owned(),
                    ATTRIBUTE_TYPES.iter().map(|s| (*s).to_owned()).collect(),
                ),
            ],
        }
    }

    #[must_use]
    pub fn container(&self, dn: &str, name: &str) -> Entry {
        Entry {
            dn: dn.to_owned(),
            attributes: vec![
                (
                    "objectClass".to_owned(),
                    vec!["top".to_owned(), "organizationalUnit".to_owned()],
                ),
                ("ou".to_owned(), vec![name.to_owned()]),
            ],
        }
    }

    #[must_use]
    pub fn suffix(&self) -> Entry {
        Entry {
            dn: self.base_text.clone(),
            attributes: vec![
                (
                    "objectClass".to_owned(),
                    vec!["top".to_owned(), "domain".to_owned()],
                ),
                (
                    "dc".to_owned(),
                    self.base
                        .first_value("dc")
                        .map(str::to_owned)
                        .into_iter()
                        .collect(),
                ),
            ],
        }
    }

    #[must_use]
    pub fn person_entry(&self, person: &Person) -> Entry {
        let dn = self.person_dn(&person.uid);
        let uid_number = posix_id(&person.uuid).to_string();

        let mut attributes = vec![
            (
                "objectClass".to_owned(),
                vec![
                    "top".to_owned(),
                    "person".to_owned(),
                    "organizationalPerson".to_owned(),
                    "inetOrgPerson".to_owned(),
                    "posixAccount".to_owned(),
                ],
            ),
            ("uid".to_owned(), vec![person.uid.clone()]),
            ("cn".to_owned(), vec![person.display_name.clone()]),
            ("sn".to_owned(), vec![person.surname.clone()]),
            ("givenName".to_owned(), vec![person.given_name.clone()]),
            ("displayName".to_owned(), vec![person.display_name.clone()]),
            ("uidNumber".to_owned(), vec![uid_number.clone()]),
            ("gidNumber".to_owned(), vec![uid_number]),
            (
                "homeDirectory".to_owned(),
                vec![format!("/home/{}", person.uid)],
            ),
            ("loginShell".to_owned(), vec!["/bin/bash".to_owned()]),
            ("sAMAccountName".to_owned(), vec![person.uid.clone()]),
            (
                "userAccountControl".to_owned(),
                vec![if person.active { "512" } else { "514" }.to_owned()],
            ),
        ];

        if let Some(mail) = person.mail.as_ref() {
            attributes.push(("mail".to_owned(), vec![mail.clone()]));
            attributes.push(("userPrincipalName".to_owned(), vec![mail.clone()]));
        }

        attributes.push((
            "memberOf".to_owned(),
            person
                .groups
                .iter()
                .map(|name| self.group_dn(name))
                .collect(),
        ));

        Entry { dn, attributes }
    }

    #[must_use]
    pub fn group_entry(&self, group: &Group) -> Entry {
        let dn = self.group_dn(&group.name);
        let gid_number = posix_id(&group.uuid).to_string();

        let mut members: Vec<String> = group
            .member_uids
            .iter()
            .map(|uid| self.person_dn(uid))
            .collect();
        members.extend(group.member_groups.iter().map(|name| self.group_dn(name)));

        let mut attributes = vec![
            (
                "objectClass".to_owned(),
                vec![
                    "top".to_owned(),
                    "groupOfNames".to_owned(),
                    "posixGroup".to_owned(),
                ],
            ),
            ("cn".to_owned(), vec![group.name.clone()]),
            ("gidNumber".to_owned(), vec![gid_number]),
            ("member".to_owned(), members),
            ("memberUid".to_owned(), group.member_uids.clone()),
        ];

        if let Some(description) = group.description.as_ref() {
            attributes.push(("description".to_owned(), vec![description.clone()]));
        }

        Entry { dn, attributes }
    }

    #[must_use]
    pub fn entries(&self) -> Vec<Entry> {
        let mut out = vec![
            self.suffix(),
            self.container(&self.people_base(), "people"),
            self.container(&self.groups_base(), "groups"),
        ];

        out.extend(self.people.iter().map(|person| self.person_entry(person)));
        out.extend(self.groups.iter().map(|group| self.group_entry(group)));
        out
    }

    #[must_use]
    pub fn find_by_bind_name(&self, name: &str) -> Option<&Person> {
        if let Ok(dn) = Dn::parse(name)
            && !dn.components.is_empty()
            && let Some(uid) = dn.first_value("uid")
        {
            return self
                .people
                .iter()
                .find(|person| person.uid.eq_ignore_ascii_case(uid));
        }

        self.people.iter().find(|person| {
            person.uid.eq_ignore_ascii_case(name)
                || person
                    .mail
                    .as_deref()
                    .is_some_and(|mail| mail.eq_ignore_ascii_case(name))
        })
    }
}

impl Membership for Directory {
    fn transitively_contains(&self, group_dn: &str, member_dn: &str) -> bool {
        let Ok(target) = Dn::parse(group_dn) else {
            return false;
        };

        let Some(start) = self.groups.iter().find(|group| {
            Dn::parse(&self.group_dn(&group.name)).is_ok_and(|parsed| parsed.equals(&target))
        }) else {
            return false;
        };

        let Ok(member) = Dn::parse(member_dn) else {
            return false;
        };

        let mut seen: Vec<&str> = Vec::new();
        let mut pending: Vec<&Group> = vec![start];

        while let Some(group) = pending.pop() {
            if seen.contains(&group.name.as_str()) {
                continue;
            }
            seen.push(&group.name);

            for uid in &group.member_uids {
                if Dn::parse(&self.person_dn(uid)).is_ok_and(|parsed| parsed.equals(&member)) {
                    return true;
                }
            }

            for name in &group.member_groups {
                if Dn::parse(&self.group_dn(name)).is_ok_and(|parsed| parsed.equals(&member)) {
                    return true;
                }
                if let Some(nested) = self.groups.iter().find(|g| &g.name == name) {
                    pending.push(nested);
                }
            }
        }

        false
    }
}

#[must_use]
pub fn effective_size_limit(requested: i64) -> i64 {
    if requested <= 0 || requested > MAX_SIZE_LIMIT {
        DEFAULT_SIZE_LIMIT
    } else {
        requested
    }
}

#[must_use]
pub fn effective_time_limit(requested: i64) -> i64 {
    if requested <= 0 || requested > MAX_TIME_LIMIT {
        DEFAULT_TIME_LIMIT
    } else {
        requested
    }
}

pub struct SearchOutcome {
    pub entries: Vec<Entry>,
    pub truncated: bool,
}

#[must_use]
pub fn search(
    directory: &Directory,
    base: &str,
    scope: Scope,
    filter: &Filter,
    attributes: &[String],
    size_limit: i64,
) -> SearchOutcome {
    let limit = usize::try_from(effective_size_limit(size_limit)).unwrap_or(usize::MAX);

    if base.trim().is_empty() && scope == Scope::Base {
        return SearchOutcome {
            entries: vec![project(&directory.root_dse(), attributes)],
            truncated: false,
        };
    }

    let Ok(requested_base) = Dn::parse(base) else {
        return SearchOutcome {
            entries: Vec::new(),
            truncated: false,
        };
    };

    if Dn::parse(super::directory::SUBSCHEMA_DN).is_ok_and(|schema| schema.equals(&requested_base))
    {
        return SearchOutcome {
            entries: vec![project(&directory.subschema(), attributes)],
            truncated: false,
        };
    }

    let mut entries = Vec::new();
    let mut truncated = false;

    for entry in directory.entries() {
        let Ok(dn) = Dn::parse(&entry.dn) else {
            continue;
        };

        let in_scope = match scope {
            Scope::Base => dn.equals(&requested_base),
            Scope::OneLevel => dn.is_under(&requested_base) && dn.depth_below(&requested_base) == 1,
            Scope::Subtree => dn.is_under(&requested_base),
        };

        if !in_scope {
            continue;
        }

        if !evaluate(&entry, filter, directory) {
            continue;
        }

        if entries.len() >= limit {
            truncated = true;
            break;
        }

        entries.push(project(&entry, attributes));
    }

    SearchOutcome { entries, truncated }
}

const OBJECT_CLASSES: [&str; 11] = [
    "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
    "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ description ) )",
    "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL )",
    "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ mail $ givenName $ displayName ) )",
    "( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( loginShell $ userPassword ) )",
    "( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST cn MAY ( member $ description ) )",
    "( 1.3.6.1.1.1.2.2 NAME 'posixGroup' SUP top AUXILIARY MUST ( cn $ gidNumber ) MAY memberUid )",
    "( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou )",
    "( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc MAY description )",
    "( 2.5.20.1 NAME 'subschema' AUXILIARY MAY ( objectClasses $ attributeTypes ) )",
    "( 1.3.6.1.4.1.4203.1.4.1 NAME 'OpenLDAProotDSE' SUP top STRUCTURAL MAY cn )",
];

const ATTRIBUTE_TYPES: [&str; 31] = [
    "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.5.4.4 NAME 'sn' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.5.4.42 NAME 'givenName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
    "( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
    "( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
    "( 2.5.4.31 NAME 'member' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
    "( 1.3.6.1.1.1.1.12 NAME 'memberUid' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
    "( 1.2.840.113556.1.2.102 NAME 'memberOf' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION USAGE directoryOperation )",
    "( 1.3.6.1.1.1.1.4 NAME 'loginShell' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
    "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
    "( 1.2.840.113556.1.4.656 NAME 'userPrincipalName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
    "( 1.2.840.113556.1.4.8 NAME 'userAccountControl' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
    "( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 2.5.4.11 NAME 'ou' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 0.9.2342.19200300.100.1.25 NAME 'dc' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
    "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
    "( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
    "( 2.5.21.6 NAME 'objectClasses' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
    "( 2.5.21.5 NAME 'attributeTypes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
    "( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )",
    "( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )",
    "( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
    "( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
    "( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )",
    "( 1.3.6.1.1.4 NAME 'vendorName' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
    "( 1.3.6.1.1.5 NAME 'vendorVersion' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
    "( 1.3.6.1.4.1.1466.101.120.10 NAME 'subschemaSubentry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
];
