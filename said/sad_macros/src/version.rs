use syn::{Attribute, LitInt, LitStr};

pub fn parse_version_args(attr: &Attribute) -> (String, u8, u8, String) {
    let mut prot = String::default();
    let mut major = 0;
    let mut minor = 0;
    let mut format: String = "".into();
    if attr.path().is_ident("version") {
        // this parses the `tea`
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("protocol") {
                // this parses the `kind`
                let value = meta.value()?; // this parses the `=`
                let s: LitStr = value.parse()?; // this parses `"EarlGrey"`
                prot = s.value();
                Ok(())
            } else if meta.path.is_ident("minor") {
                let value = meta.value()?; // this parses the `=`
                let s: LitInt = value.parse()?; // this parses `"EarlGrey"`
                minor = s.base10_parse::<u8>().unwrap();
                Ok(())
            } else if meta.path.is_ident("major") {
                let value = meta.value()?; // this parses the `=`
                let s: LitInt = value.parse()?; // this parses `"EarlGrey"`
                major = s.base10_parse::<u8>().unwrap();
                Ok(())
            } else if meta.path.is_ident("format") {
                let value = meta.value()?; // this parses the `=`
                let s: LitStr = value.parse()?; // this parses `"EarlGrey"`
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
