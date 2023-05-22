use syn::{Attribute, LitInt, LitStr};

pub fn parse_version_args(attr: &Attribute) -> (String, u8, u8, String) {
    let mut prot = String::default();
    let mut major = 0;
    let mut minor = 0;
    let mut format = String::default();
    if attr.path().is_ident("version") {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("protocol") {
                let value = meta.value()?;
                let s: LitStr = value.parse()?;
                prot = s.value();
                Ok(())
            } else if meta.path.is_ident("minor") {
                let value = meta.value()?;
                let s: LitInt = value.parse()?;
                minor = s.base10_parse::<u8>().unwrap();
                Ok(())
            } else if meta.path.is_ident("major") {
                let value = meta.value()?;
                let s: LitInt = value.parse()?;
                major = s.base10_parse::<u8>().unwrap();
                Ok(())
            } else if meta.path.is_ident("format") {
                let value = meta.value()?;
                let s: LitStr = value.parse()?;
                format = s.value();
                Ok(())
            } else {
                Err(meta.error("unsupported attribute"))
            }
        })
        .unwrap();
    };
    (prot, major, minor, format)
}
