use syn::{Attribute, Ident};

#[derive(Debug)]
pub struct TransField {
    pub name: Option<Ident>,
    pub attributes: Vec<Attribute>,
    pub said: bool,
    pub original: syn::Field,
}

impl TransField {
    pub fn from_ast(field: syn::Field) -> Self {
        let name = field.ident.clone();
        let attributes = field.attrs.clone();

        let said = attributes
            .iter()
            .any(|attr| attr.path().segments.iter().any(|seg| seg.ident.eq("said")));

        let attrs = attributes
            .into_iter()
            .filter(|attr| attr.path().segments.iter().any(|att| !att.ident.eq("said")));

        Self {
            name,
            attributes: attrs.collect(),
            said,
            original: field,
        }
    }
}
