/// Returns a partially-masked version of a secret string suitable for log
/// output.
///
/// Rules:
/// - **≤ 3 chars** → `***` (fully masked)
/// - **4 – 8 chars** → first char + `***`
/// - **9 – 12 chars** → first 2 chars + `***` + last char
/// - **≥ 13 chars** → first 3 chars + `***` + last 3 chars
///
/// # Example
/// ```
/// use secret_store::common::obfuscate_secret;
/// assert_eq!(obfuscate_secret("ab"),           "***");
/// assert_eq!(obfuscate_secret("abcd"),         "a***");
/// assert_eq!(obfuscate_secret("abcdefghi"),    "ab***i");
/// assert_eq!(obfuscate_secret("abcdefghijklm"),"abc***klm");
/// ```
pub fn obfuscate_secret(s: &str) -> String {
    let len = s.chars().count();
    match len {
        0..=3 => "***".to_owned(),
        4..=8 => {
            let first: String = s.chars().take(1).collect();
            format!("{first}***")
        }
        9..=12 => {
            let first: String = s.chars().take(2).collect();
            let last: String = s.chars().rev().take(1).collect::<String>().chars().rev().collect();
            format!("{first}***{last}")
        }
        _ => {
            let first: String = s.chars().take(3).collect();
            let last: String = s.chars().rev().take(3).collect::<String>().chars().rev().collect();
            format!("{first}***{last}")
        }
    }
}

/// Returns `true` if the string is a plausible secret name (non-empty,
/// contains only alphanumeric characters, hyphens, underscores, or dots).
pub fn is_valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── obfuscate_secret ──────────────────────────────────────────────────────

    #[test]
    fn empty_string_is_fully_masked() {
        assert_eq!(obfuscate_secret(""), "***");
    }

    #[test]
    fn one_char_is_fully_masked() {
        assert_eq!(obfuscate_secret("a"), "***");
    }

    #[test]
    fn three_chars_are_fully_masked() {
        assert_eq!(obfuscate_secret("abc"), "***");
    }

    #[test]
    fn four_chars_show_first_char() {
        assert_eq!(obfuscate_secret("abcd"), "a***");
    }

    #[test]
    fn eight_chars_show_first_char() {
        assert_eq!(obfuscate_secret("abcdefgh"), "a***");
    }

    #[test]
    fn nine_chars_show_first_two_and_last_one() {
        assert_eq!(obfuscate_secret("abcdefghi"), "ab***i");
    }

    #[test]
    fn twelve_chars_show_first_two_and_last_one() {
        assert_eq!(obfuscate_secret("abcdefghijkl"), "ab***l");
    }

    #[test]
    fn thirteen_chars_show_first_three_and_last_three() {
        assert_eq!(obfuscate_secret("abcdefghijklm"), "abc***klm");
    }

    #[test]
    fn long_string_shows_first_three_and_last_three() {
        assert_eq!(obfuscate_secret("supersecretpassword"), "sup***ord");
    }

    #[test]
    fn obfuscated_never_equals_original_for_non_trivial_secrets() {
        let secret = "my-super-secret-password";
        let obfuscated = obfuscate_secret(secret);
        assert_ne!(obfuscated, secret);
        assert!(!obfuscated.contains("super-secret"));
    }

    #[test]
    fn obfuscated_output_contains_mask_marker() {
        for secret in &["x", "abcd", "abcdefghi", "averylongsecret"] {
            assert!(
                obfuscate_secret(secret).contains("***"),
                "obfuscated({secret:?}) did not contain '***'"
            );
        }
    }

    // ── is_valid_secret_name ──────────────────────────────────────────────────

    #[test]
    fn valid_secret_names() {
        assert!(is_valid_secret_name("my-secret"));
        assert!(is_valid_secret_name("MY_SECRET_123"));
        assert!(is_valid_secret_name("prod.db.password"));
        assert!(is_valid_secret_name("a"));
    }

    #[test]
    fn empty_name_is_invalid() {
        assert!(!is_valid_secret_name(""));
    }

    #[test]
    fn name_with_spaces_is_invalid() {
        assert!(!is_valid_secret_name("my secret"));
    }

    #[test]
    fn name_with_slash_is_invalid() {
        assert!(!is_valid_secret_name("my/secret"));
    }

    #[test]
    fn name_with_at_is_invalid() {
        assert!(!is_valid_secret_name("my@secret"));
    }
}
