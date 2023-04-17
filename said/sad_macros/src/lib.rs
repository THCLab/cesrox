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

    let generics = &ast.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Iterate over struct field, and replace type of those with `said` attribute with String type.
    let fields = match &ast.data {
        syn::Data::Struct(s) => s.fields.clone(),
        _ => panic!("Not a struct"),
    };
    // Generate body of newly created struct fields.
    // Replace field type with String if it is tagged as said.
    let body = fields.iter().map(|field| {
        let name = &field.ident;
        let (said_attribute, not_said): (Vec<_>, Vec<_>) = field
            .attrs
            .clone()
            .into_iter()
            .partition(|attr| attr.path.segments.iter().any(|att| att.ident.eq("said")));
        if said_attribute.is_empty() {
            quote! {#field}
        } else {
            quote! {
                #(#not_said)* 
                #name: String
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
            None => quote! {#name: self.#name.clone()},
        }
    });

    let gen = quote! {
        // Create temporary, serializable struct
        #[derive(Serialize)]
        struct #varname #ty_generics #where_clause {
                #(#body,)*
        }

        impl #impl_generics From<(&#name #ty_generics, usize)> for #varname #ty_generics #where_clause {
            fn from(value: (&#name #ty_generics, usize)) -> Self {
                let dig_length = value.1;
                let value = value.0;;
                Self {
                    #(#concrete,)*
                }
            }
        }

        impl #impl_generics SAD for #name #ty_generics #where_clause {
            fn compute_digest(&self, code: HashFunctionCode, serialization: SerializationFormats) -> Self {
                use said::derivation::HashFunction;
                let serialized = self.derivation_data(&code, &serialization);
                let digest = Some(HashFunction::from(code).derive(&serialized));

                Self {#(#out,)*}
            }

            fn derivation_data(&self, code: &HashFunctionCode, serialization: &SerializationFormats) -> Vec<u8> {
                use cesrox::derivation_code::DerivationCode;
                let tmp: #varname #ty_generics = (self, code.full_size()).into();
                serialization.encode(&tmp).unwrap()
            }
        }
    };
    gen.into()
}
