use syn::{Attribute, LitStr};

pub fn parse_said_args(attr: &Attribute) -> (Option<String>, Option<String>) {
    let mut code = None;
    let mut format = None;
    if attr.path().is_ident("said") {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("code") {
                let value = meta.value()?;
                let s: LitStr = value.parse()?;
                code = Some(s.value());
                Ok(())
            } else if meta.path.is_ident("format") {
                let value = meta.value()?;
                let s: LitStr = value.parse()?;
                format = Some(s.value());
                Ok(())
            } else {
                Err(meta.error("unsupported attribute"))
            }
        })
        .expect("Problem while parsing version arguments");;
    };
    (code, format)
}
