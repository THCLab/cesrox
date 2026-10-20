use field::TransField;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self};

mod field;
mod version;
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
    // helper types are named after the type, so several derives can share a
    // module
    let tmp_name = syn::Ident::new(&format!("{}TMP", name), name.span());
    let enc_name = syn::Ident::new(&format!("{}ENC", name), name.span());

    let generics = &ast.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Check if versioned attribute is added.
    let version = ast
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("version"))
        .map(parse_version_args);

    let fields: Vec<TransField> = match &ast.data {
        syn::Data::Struct(s) => s.fields.clone(),
        _ => panic!("Not a struct"),
    }
    .into_iter()
    .map(TransField::from_ast)
    .collect();

    // Fields of the derivation struct: SAID fields become strings holding
    // the placeholder.
    let tmp_body = fields.iter().map(|field| {
        if !field.said {
            let original = &field.original;
            quote! {#original}
        } else {
            let name = &field.name;
            let attrs = &field.attributes;
            quote! {
                #(#attrs)*
                #name: String
            }
        }
    });

    // Values of the derivation struct: `#` placeholders of the SAID's length
    // in SAID fields, the type's own values elsewhere.
    let tmp_values = fields.iter().map(|field| {
        let name = &field.name;
        if field.said {
            quote! {#name: "#".repeat(dig_length)}
        } else {
            quote! {#name: value.#name.clone()}
        }
    });

    // Statements setting the SAID fields to the computed digest.
    let set_said = fields.iter().filter(|field| field.said).map(|field| {
        let name = &field.name;
        quote! {self.#name = digest.clone();}
    });

    let version_field = quote! {
        #[serde(rename = "v")]
        __said_version: ::said::version::SerializationInfo,
    };

    let (tmp_version_field, tmp_version_value, fix_size, encode) = match &version {
        Some((prot, major, minor)) => {
            let new_version = quote! {
                ::said::version::SerializationInfo::new_empty(
                    #prot.to_string(), #major, #minor, *format
                )
            };
            // the type's own fields without the `said` marker
            let originals = fields.iter().map(|field| {
                let name = &field.name;
                let ty = &field.original.ty;
                let attrs = &field.attributes;
                quote! {
                    #(#attrs)*
                    #name: #ty
                }
            });
            let enc_values = fields.iter().map(|field| {
                let name = &field.name;
                quote! {#name: self.#name.clone()}
            });
            let encode = quote! {
                // The message with its version string first; a struct rather
                // than a flattened map, so CBOR maps get a definite length.
                #[derive(::serde::Serialize)]
                struct #enc_name #ty_generics #where_clause {
                    #version_field
                    #(#originals,)*
                }

                impl #impl_generics ::said::version::Encode for #name #ty_generics #where_clause {
                    fn encode(
                        &self,
                        _code: &::said::derivation::HashFunctionCode,
                        format: &::said::sad::SerializationFormats,
                    ) -> Result<Vec<u8>, ::said::version::error::Error> {
                        let mut message = #enc_name {
                            __said_version: #new_version,
                            #(#enc_values,)*
                        };
                        // the size field has a fixed width
                        message.__said_version.size = format.encode(&message)?.len();
                        format.encode(&message)
                    }
                }
            };
            (
                version_field.clone(),
                quote! {__said_version: #new_version,},
                quote! { tmp.__said_version.size = format.encode(&tmp)?.len(); },
                encode,
            )
        }
        None => (quote! {}, quote! {}, quote! {}, quote! {}),
    };

    let gen = quote! {
        // The type with placeholders in its SAID fields, which the SAID is
        // computed over.
        #[derive(::serde::Serialize)]
        struct #tmp_name #ty_generics #where_clause {
            #tmp_version_field
            #(#tmp_body,)*
        }

        #encode

        impl #impl_generics From<(&#name #ty_generics, usize, &::said::sad::SerializationFormats)>
            for #tmp_name #ty_generics #where_clause
        {
            fn from(
                (value, dig_length, format): (&#name #ty_generics, usize, &::said::sad::SerializationFormats),
            ) -> Self {
                let _ = format;
                Self {
                    #tmp_version_value
                    #(#tmp_values,)*
                }
            }
        }

        impl #impl_generics ::said::sad::SAD for #name #ty_generics #where_clause {
            fn compute_digest(
                &mut self,
                code: &::said::derivation::HashFunctionCode,
                format: &::said::sad::SerializationFormats,
            ) -> Result<(), ::said::version::error::Error> {
                let serialized = self.derivation_data(code, format)?;
                let digest = Some(::said::derivation::HashFunction::from(code.clone()).derive(&serialized));
                #(#set_said)*
                Ok(())
            }

            fn derivation_data(
                &self,
                code: &::said::derivation::HashFunctionCode,
                format: &::said::sad::SerializationFormats,
            ) -> Result<Vec<u8>, ::said::version::error::Error> {
                use ::said::sad::DerivationCode;
                let mut tmp: #tmp_name #ty_generics = (self, code.full_size(), format).into();
                #fix_size
                format.encode(&tmp)
            }
        }
    };
    gen.into()
}
