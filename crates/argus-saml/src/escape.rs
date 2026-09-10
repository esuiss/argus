#[must_use]
pub fn text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

#[must_use]
pub fn attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{attribute, text};

    #[test]
    fn a_display_name_cannot_close_the_element_it_sits_in() {
        assert_eq!(
            text("</saml:Assertion><script>"),
            "&lt;/saml:Assertion&gt;&lt;script&gt;"
        );
    }

    #[test]
    fn an_attribute_value_cannot_escape_its_quotes() {
        assert_eq!(
            attribute(r#"" onload="alert(1)"#),
            "&quot; onload=&quot;alert(1)"
        );
        assert_eq!(attribute("it's"), "it&apos;s");
    }

    #[test]
    fn a_carriage_return_survives_canonicalization_as_a_reference() {
        assert_eq!(text("a\rb"), "a&#xD;b");
        assert_eq!(attribute("a\r\nb"), "a&#xD;&#xA;b");
    }

    #[test]
    fn ordinary_text_passes_through_unchanged() {
        assert_eq!(text("Barbara Jensen"), "Barbara Jensen");
        assert_eq!(
            attribute("urn:oasis:names:tc:SAML:2.0:protocol"),
            "urn:oasis:names:tc:SAML:2.0:protocol"
        );
    }
}
