use derivation::parse_said_args;
use field::TransField;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self};

mod field;
mod version;
mod derivation;
use version::parse_version_args;

#[proc_macro_derive(SAD, attributes(said, version))]
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

    // Check if versioned attribute is added.
    let version = ast
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("version"))
        .map(|attr| parse_version_args(attr));
    
    let config = ast
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("said"))
        .map(|attr| parse_said_args(attr));
    let (code, form) = 
    match config {
        Some((Some(code), Some(format))) => (code, format),
        Some((None, Some(format))) => ("E".to_string(), format),
        Some((Some(code), None)) => (code, "JSON".to_string()),
        _ => ("E".to_string(), "JSON".to_string()),
    };

    let fields = match &ast.data {
        syn::Data::Struct(s) => s.fields.clone(),
        _ => panic!("Not a struct"),
    }
    .into_iter()
    .map(|field| TransField::from_ast(field));

    // Generate body of newly created struct fields.
    // Replace field type with String if it is tagged as said.
    let body = fields.clone().map(|field| {
        if !field.said {
            let original = field.original;
            quote! {#original}
        } else {
            let name = &field.name;
            let attrs = field.attributes;
            quote! {
                #(#attrs)*
                #name: String
            }
        }
    });

    // Set fields tagged as said to computed digest string, depending on
    // digest set in `dig_length` variable. Needed for generation of From
    // implementation.
    let concrete = fields.clone().map(|field| {
        let name = &field.name;
        if field.said {
            quote! {#name: "#".repeat(dig_length).to_string()}
        } else {
            quote! {#name: value.#name.clone()}
        }
    });

    // Set fields tagged as said to computed SAID set in `digest` variable.
    let out = fields.clone().map(|field| {
        let name = &field.name;
        if field.said {
            quote! {self.#name = digest.clone();}
        } else {
            quote! {}
        }
    });

    // Adding version field logic.
    let version_field = if let Some(_) = version {
        quote! {
        #[serde(rename = "v")]
        version: SerializationInfo,
        }
    } else {
        quote! {}
    };
    let tmp_struct = if let Some((prot, major, minor)) = version {
        quote! {
           let mut tmp_self = Self {
                version: SerializationInfo::new_empty(#prot.to_string(), #major, #minor, #form.parse().unwrap()),
                #(#concrete,)*
                };
            let enc = tmp_self.version.serialize(&tmp_self).unwrap();
            tmp_self.version.size = enc.len();
            tmp_self
        }
    } else {
        quote! {Self {
            #(#concrete,)*
        }}
    };

    let gen = quote! {
    // Create temporary, serializable struct
    #[derive(Serialize)]
    struct #varname #ty_generics #where_clause {
            #version_field
            #(#body,)*
    }

    impl #impl_generics From<(&#name #ty_generics, usize)> for #varname #ty_generics #where_clause {
        fn from(value: (&#name #ty_generics, usize)) -> Self {
            let dig_length = value.1;

            let value = value.0;
            #tmp_struct
        }
    }

    impl #impl_generics SAD for #name #ty_generics #where_clause {
        fn compute_digest(&mut self, code: HashFunctionCode) {
            use said::derivation::HashFunction;
            let serialized = self.derivation_data(&code);
            let digest = Some(HashFunction::from(code).derive(&serialized));
            #(#out;)*
        }

        fn derivation_data(&self, code: &HashFunctionCode) -> Vec<u8> {
            use said::sad::DerivationCode;
            let tmp: #varname #ty_generics = (self, code.full_size()).into();
            let serialization: SerializationFormats = #form.parse().unwrap();
            serialization.encode(&tmp).unwrap()
        }
    }};
    gen.into()
}
