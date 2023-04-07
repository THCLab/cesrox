use proc_macro::TokenStream;
use quote::quote;
use syn::{self, parse_macro_input, DeriveInput};

#[proc_macro_derive(SAD, attributes(said))]
pub fn compute_digest_derive(input: TokenStream) -> TokenStream {
    // let ast = parse_macro_input!(input as DeriveInput);
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
        syn::Data::Enum(_) => todo!(),
        syn::Data::Union(_) => todo!(),
    };
    let body = fields.iter().map(|field| {
        let name = &field.ident;
        let ty = &field.ty;
        let attributes = &field.attrs;

        let digested = attributes.get(0);
        if let Some(a) = digested {
            let s = a.path.segments.iter().next().unwrap();
            if s.ident == "said" {
                quote! {#name: String}
            } else {
                quote! {#name: #ty}
            }
        } else {
            quote! {#name: #ty}
        }
    });
    let concrete = fields.iter().map(|field| {
        let name = &field.ident;
        let attributes = &field.attrs;

        let digested = attributes.get(0);
        if let Some(a) = digested {
            let s = a.path.segments.iter().next().unwrap();
            if s.ident == "said" {
                quote! {#name: "#".repeat(dig_length).to_string()}
            } else {
                quote! {#name: value.#name.clone()}
            }
        } else {
            quote! {#name: value.#name.clone()}
        }
    });

    let out = fields.iter().map(|field| {
        let name = &field.ident;
        let attributes = &field.attrs;

        let digested = attributes.get(0);
        if let Some(a) = digested {
            let s = a.path.segments.iter().next().unwrap();
            if s.ident == "said" {
                quote! {#name: digest.clone()}
            } else {
                quote! {#name: self.#name.clone()}
            }
        } else {
            quote! {#name: self.#name.clone()}
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
            fn compute_digest(&self, code: HashFunctionCode) -> Self {
                use said::derivation::HashFunction;
                use cesrox::derivation_code::DerivationCode;
                let tmp: #varname = (self, code.full_size()).into();
                let serialized = serde_json::to_string(&tmp).unwrap();
                let digest = Some(HashFunction::from(code).derive(serialized.as_bytes()));
                println!("digest is computed from: {}", serialized);

                Self {#(#out,)*}
            }
        }
    };
    gen.into()
}
