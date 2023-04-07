use proc_macro::TokenStream;
use quote::quote;
use syn::{self};

#[proc_macro_derive(SAD, attributes(said))]
pub fn compute_digest_derive(input: TokenStream) -> TokenStream {
    // Construct a representation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    impl_compute_digest(&ast)
}

fn impl_compute_digest(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let fname = format!("{}TMP", name);
    let varname = syn::Ident::new(&fname, name.span());

    // Iterate over struct field, and replace type of those with `said` attribute with String type.
    let fields = match &ast.data {
        syn::Data::Struct(s) => s.fields.clone(),
        _ => panic!("Not a struct"),
    };
    // Generate body of newly created struct fields.
    // Replace field type with String if it is tagged as said.
    let body = fields.iter().map(|field| {
        let name = &field.ident;
        let said_attribute = field
            .attrs
            .iter()
            .find(|attr| attr.path.segments.iter().any(|att| att.ident.eq("said")));
        match said_attribute {
            Some(_) => quote! {#name: String},
            None => {
                let ty = &field.ty;
                quote! {#name: #ty}
            }
        }
    });

    // Set fields tagged as said to computed digest string, depending on
    // digest set in `dig_length` variable. Needed for generation of From
    // implementation.
    let concrete = fields.iter().map(|field| {
        let name = &field.ident;
        let said_attribute = field
            .attrs
            .iter()
            .find(|attr| attr.path.segments.iter().any(|att| att.ident.eq("said")));
        match said_attribute {
            Some(_) => quote! {#name: "#".repeat(dig_length).to_string()},
            None => {
                quote! {#name: value.#name.clone()}
            }
        }
    });

    // Set fields tagged as said to hash string with proper length, depending on
    // length set in `digest` variable.
    let out = fields.iter().map(|field| {
        let name = &field.ident;
        let said_attribute = field
            .attrs
            .iter()
            .find(|attr| attr.path.segments.iter().any(|att| att.ident.eq("said")));
        match said_attribute {
            Some(_) => quote! {#name: digest.clone()},
            None => {
                quote! {#name: self.#name.clone()}
            }
        }
    });

    let gen = quote! {
        // Create temporary, serializable struct
        #[derive(Serialize)]
        struct #varname {
                #(#body,)*
        }

        impl From<(&#name, usize)> for #varname {
            fn from(value: (&#name, usize)) -> Self {
                let dig_length = value.1;
                let value = value.0;;
                Self {
                    #(#concrete,)*
                }
            }
        }

        impl SAD for #name {
            fn compute_digest(&self, code: HashFunctionCode, serialization: SerializationFormats) -> Self {
                use said::derivation::HashFunction;
                use cesrox::derivation_code::DerivationCode;
                let tmp: #varname = (self, code.full_size()).into();
                let serialized = serialization.encode(&tmp).unwrap();
                let digest = Some(HashFunction::from(code).derive(&serialized));

                Self {#(#out,)*}
            }
        }
    };
    gen.into()
}
